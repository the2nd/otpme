# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" A pool of worker processes for a job that walks many objects.

Made for the walk that puts ACLs on the members of a unit and used by
the upgrade of the object configs of a site as well. Both have a long
list of objects that are independent of each other -- each is read,
changed and written on its own -- so the only thing a worker needs is
which one to do, and the time goes into the index and the caches, which
take more than one process at a time.

Built like the pool that merges a sync (sync1.py): a pool that stays
for the whole job, work and results over POSIX message queues, and a
parent that counts what it pushed against what came back, so a worker
that dies does not make it wait for ever.
"""
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import multiprocessing
from otpme.lib.job.callback import JobCallback

from otpme.lib.exceptions import *

logger = config.logger

# From how many items on it is worth starting workers at all. Below
# that the forking and the queues cost more than they save.
WORKER_MIN_ITEMS = 500

# How many lines go over the connection in one message. One message per
# line is more than the connection takes where the walk is quick: five
# ACLs on fourteen thousand objects are seventy thousand of them, and
# the walk outruns the client.
MESSAGE_BLOCK = 100

# How many seconds may pass without anything going to the client.
# Whatever has piled up goes then, and if there is nothing -- with
# verbose off a walk may make no lines at all -- a keepalive goes
# instead, or the connection of the job times out. Same cadence the
# mass add uses (see mgmt1.py).
KEEPALIVE_INTERVAL = 1

# Set in a worker, so it does not start a pool of its own: a member
# that is a unit is walked where it was handed to, and a sub unit with
# enough members below it would otherwise fork four more workers per
# worker. A module level name, which is per process, which is what a
# worker is.
in_worker = False


def get_worker_count(procs=None):
    """ How many workers a pool starts.

    A quarter of the cores, and not more, because the node goes on
    answering logins while this runs: authd and ldapd want cores too,
    and a bulk change is not more urgent than somebody signing in.
    A quarter is also where the measurements sit -- four workers on
    sixteen cores took a walk over 28095 users from 19:36 to 7:26,
    which is a factor of 2.6 and so 65% of what four could give. The
    curve is flat enough by then that taking half would not buy half
    again. Whoever knows the node has nothing else to do says --procs.

    The cores this process may actually use, which on a machine that
    was given a subset is not what os.cpu_count() answers.
    """
    if procs:
        return max(1, int(procs))
    try:
        cores = len(os.sched_getaffinity(0))
    except AttributeError:
        cores = os.cpu_count() or 1
    return max(1, int(cores / 4))


class WorkerCallback(JobCallback):
    """ A callback that keeps the messages instead of sending them.

    A worker has no business writing to the connection of the job: the
    workers of one pool would be writing to the same socket, and what
    the client reads would be their output cut into each other. So a
    worker collects what it would have said and hands it back with its
    result, and the process that owns the connection sends it.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.messages = []

    def send(self, message='\0OTPME_NULL\0', error=False, **kwargs):
        if message == '\0OTPME_NULL\0':
            return True
        self.messages.append((bool(error), str(message)))
        return True

    def take_messages(self):
        """ What was said since the last time somebody asked. """
        messages = self.messages
        self.messages = []
        return messages


class WorkerPool(object):
    """ Workers that take one item at a time and hand back a result.

    <handler> is called in a worker as handler(item, callback) for
    every item given to run(), and what it returns travels back as the
    status of the item. False means the item failed. An item is a
    dict, and it is small: it travels a queue. Everything a worker
    needs besides, it inherits when it is forked.

    What the handler says through its callback comes back with the
    result and is sent from the process that owns the connection.

    <ordered> holds the lines of an item back until those of the items
    before it have been said. An item says its place in 'pos' then. A
    worker answers when it is done, so the answers do not come back in
    the order the items went out, and lines that count ("3/100") would
    count up and down again. What is held back is what the workers have
    in their hands, so a handful of items.

    run() can be called more than once; the workers stay until stop().
    """
    def __init__(self, name, handler, callback, procs=None, ordered=False):
        self.name = name
        self.handler = handler
        self.callback = callback
        self.ordered = ordered
        self.worker_count = get_worker_count(procs)
        self.workers = []
        self.work_queue = None
        self.result_queue = None
        # The lines on their way to the client, and when something last
        # went. They go in blocks, and where nothing goes for a while a
        # keepalive goes instead.
        self.message_block = []
        self.last_sent = time.time()
        # The lines of an item that is done, by its place.
        self.waiting_messages = {}
        self.next_pos = 1

    def start(self):
        """ Fork the workers. """
        from otpme.lib.multiprocessing import MessageQueue
        queue_id = stuff.gen_uuid()
        self.work_queue = MessageQueue(name=f"{self.name}_work",
                                    identifier=queue_id)
        self.result_queue = MessageQueue(name=f"{self.name}_result",
                                        identifier=queue_id)
        for x in range(self.worker_count):
            worker = multiprocessing.start_process(
                                name=f"{self.name}_worker_{x}",
                                target=self._worker_loop,
                                hard_exit=True,
                                daemon=True,
                                start=True)
            self.workers.append(worker)

    def flush_messages(self):
        if not self.message_block:
            return
        self.callback.send("\n".join(self.message_block))
        self.message_block.clear()
        self.last_sent = time.time()

    def say(self, messages):
        for is_error, text in messages:
            if not is_error:
                self.message_block.append(text)
                continue
            # An error goes on its own and at once, but in its place:
            # what was said before it goes first.
            self.flush_messages()
            self.callback.send(text, error=True)
            self.last_sent = time.time()
        if len(self.message_block) >= MESSAGE_BLOCK:
            self.flush_messages()

    def keep_the_line_open(self):
        """ Let the client hear something now and then.

        Whatever has piled up, or a keepalive where nothing has. Where
        a walk makes no lines at all this is the only thing that
        travels -- without it the job's connection times out.
        """
        if time.time() - self.last_sent < KEEPALIVE_INTERVAL:
            return
        if self.message_block:
            self.flush_messages()
            return
        self.callback.keepalive()
        self.last_sent = time.time()

    def say_in_order(self, pos, messages):
        """ Say this one once everything before it has been said. """
        if not self.ordered or pos is None:
            self.say(messages)
            return
        self.waiting_messages[pos] = messages
        while self.next_pos in self.waiting_messages:
            self.say(self.waiting_messages.pop(self.next_pos))
            self.next_pos += 1

    def say_the_rest(self):
        """ Say what is left, whatever is missing before it. """
        for pos in sorted(self.waiting_messages):
            self.say(self.waiting_messages.pop(pos))
            self.next_pos = pos + 1

    def run(self, items, on_result=None):
        """ Hand the items out and wait until all of them came back.

        <on_result> is called in this process with the status of each
        item as its result arrives.

        Returns False if an item failed or was lost with a worker that
        died, True otherwise.
        """
        failed = False
        pushed = 0
        seen = 0
        self.waiting_messages = {}
        self.next_pos = 1

        def drain(timeout=0):
            """ Take what came back and say it. """
            nonlocal seen, failed
            drained = 0
            while True:
                x_timeout = timeout if drained == 0 else 0
                try:
                    msg = self.result_queue.recv(timeout=x_timeout)
                except TimeoutReached:
                    break
                except (QueueClosed, ExitOnSignal):
                    break
                if msg is None:
                    break
                drained += 1
                seen += 1
                self.say_in_order(msg.get("pos"), msg.get("messages") or [])
                status = msg.get("status")
                if status is False:
                    failed = True
                if on_result is not None:
                    on_result(status)
            return drained

        try:
            for item in items:
                pushed += 1
                self.work_queue.send(item)
                drain()
                self.keep_the_line_open()

            # Ten seconds without a single result, at half a second a
            # look. A worker takes one item at a time, so one that
            # dies takes that one with it and no result for it is ever
            # sent -- waiting for all of them to die first would mean
            # waiting while the others sit idle.
            quiet_rounds = 0
            while seen < pushed:
                if drain(timeout=0.5) > 0:
                    quiet_rounds = 0
                    self.keep_the_line_open()
                    continue
                self.keep_the_line_open()
                quiet_rounds += 1
                alive = sum(1 for w in self.workers if w.is_alive())
                dead = len(self.workers) - alive
                outstanding = pushed - seen
                if alive > 0:
                    if dead < outstanding:
                        continue
                    if quiet_rounds < 20:
                        continue
                drain()
                lost = pushed - seen
                if lost > 0:
                    failed = True
                    # Whatever was being held back for the items that
                    # never came back has to be said now, out of order
                    # or not, or it would be dropped. And before the
                    # line below it, which does not go through say().
                    self.say_the_rest()
                    self.flush_messages()
                    msg = _("Lost {count} object(s): {dead} worker(s) gone.")
                    msg = msg.format(count=lost, dead=dead)
                    self.callback.send(msg, error=True)
                break
        finally:
            # Whatever is still held back goes now, whichever way this
            # was left -- the lines are of no use to anybody in here.
            self.say_the_rest()
            self.flush_messages()

        return not failed

    def stop(self):
        """ End the workers and take the queues out of the kernel. """
        # One sentinel per worker, and a timeout on it: a worker that
        # is already gone takes none, and the queue would fill up and
        # hold us here.
        for _worker in self.workers:
            try:
                self.work_queue.send({'stop': True}, timeout=5)
            except Exception:
                pass
        for worker in self.workers:
            try:
                worker.join(timeout=10)
                if worker.is_alive():
                    worker.terminate()
                    worker.join(timeout=5)
            except Exception:
                pass
        self.workers = []
        # Closed and unlinked: a posix message queue outlives the
        # process that made it until somebody takes it out of the
        # kernel.
        for queue in [self.work_queue, self.result_queue]:
            if queue is None:
                continue
            for method in ["close", "unlink"]:
                try:
                    getattr(queue, method)()
                except Exception:
                    pass
        self.work_queue = None
        self.result_queue = None

    def _worker_loop(self):
        """ Take one item at a time and hand it to the handler.

        Every turn ends in exactly one result, whatever happened, or the
        parent waits for one that is never coming.
        """
        import signal
        import setproctitle

        global in_worker
        in_worker = True

        # A worker has nobody to ask. The policies that want an answer
        # from whoever gave the command -- an auth_on_action wanting
        # them to authenticate again -- ran once before the pool
        # started, in the process that has the connection. Asking again
        # from here would be asking the void.
        if "interactive" not in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        parent_pid = os.getppid()

        proctitle = setproctitle.getproctitle()
        setproctitle.setproctitle(f"{proctitle}: {self.name} worker")

        # Our own database and cache connections, once per worker.
        multiprocessing.atfork()

        # Remembered and acted on between two items, so a write that
        # was running when the signal came is finished first.
        stop_flag = [False]
        def signal_handler(_signal, _frame):
            stop_flag[0] = True
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        while True:
            if stop_flag[0] and not config.active_transactions:
                return
            if os.getppid() != parent_pid:
                # A note and not a warning. Nobody is waiting for this
                # worker any more, so there is nothing wrong with it
                # going; whether anything was lost is counted by the
                # process that handed the items out, and that one says
                # so ("Lost N object(s)"). As a warning it made the end
                # of every walk look like a fault, once per worker.
                log_msg = _("Worker ending: the process that started it is gone.", log=True)[1]
                logger.debug(log_msg)
                return
            try:
                item = self.work_queue.recv(timeout=1)
            except TimeoutReached:
                continue
            except (QueueClosed, ExitOnSignal):
                return
            if item is None:
                continue
            if item.get("stop"):
                return
            worker_callback = WorkerCallback(name=f"{self.name}_worker")
            status = False
            try:
                status = self.handler(item, worker_callback)
            except Exception as e:
                log_msg = _("Worker failed to handle {item}: {error}", log=True)[1]
                log_msg = log_msg.format(item=item, error=e)
                logger.critical(log_msg)
                worker_callback.send(str(e), error=True)
            result = {
                    'pos'       : item.get("pos"),
                    'status'    : status,
                    'messages'  : worker_callback.take_messages(),
                    }
            if not self._send_result(result, parent_pid):
                return

    def _send_result(self, result, parent_pid):
        """ Hand a result back, as long as somebody is there to take it.

        A second at a time, and between two tries a look whether the
        process that started us is still there. A queue nobody reads
        fills up, and a send without a timeout would then wait for
        ever: the workers of a job whose parent was gone sat in here
        until they were killed.

        Returns False if the result cannot be handed back.
        """
        while True:
            try:
                self.result_queue.send(result, timeout=1, raise_timeout=True)
                return True
            except TimeoutReached:
                pass
            except (QueueClosed, ExitOnSignal):
                return False
            if os.getppid() != parent_pid:
                log_msg = _("Worker ending: the process that started it is gone.", log=True)[1]
                logger.debug(log_msg)
                return False
