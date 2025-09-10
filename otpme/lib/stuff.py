# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#import re
import sys
import signal
from contextlib import contextmanager

try:
    import simdjson as json
except:
    try:
        import ujson as json
    except:
        import json

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

# FIXME: any problems with re2?
from otpme.lib import re
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode
from otpme.lib.compression.base import compress
from otpme.lib.compression.base import decompress
from otpme.lib.compression.base import get_compression_type

from otpme.lib.exceptions import *

@contextmanager
def _timeout(timeout):
    # https://stackoverflow.com/questions/5255220/fcntl-flock-how-to-implement-a-timeout
    def timeout_handler(signum, frame):
        msg = "Timeout reached."
        raise TimeoutReached(msg)
    original_handler = signal.signal(signal.SIGALRM, timeout_handler)
    try:
        #signal.alarm(timeout)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, original_handler)

def start_with_timeout(function, timeout=3):
    # https://stackoverflow.com/questions/5255220/fcntl-flock-how-to-implement-a-timeout
    with _timeout(timeout):
        return function()

def get_dict_size(obj, seen=None):
    """ Get recursive dict size. """
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)
    size = sys.getsizeof(obj)
    if isinstance(obj, dict):
        size += sum(get_dict_size(v, seen) for v in obj.values())
        size += sum(get_dict_size(k, seen) for k in obj.keys())
    elif isinstance(obj, (list, tuple, set)):
        size += sum(get_dict_size(i, seen) for i in obj)
    return size

def read_pass_from_stdin(timeout=1):
    import select
    rlist = select.select([sys.stdin], [], [], timeout)[0]
    if not rlist:
        msg = (_("Timeout reading password from stdin."))
        raise OTPmeException(msg)
    password = sys.stdin.readline().replace("\n", "")
    if not password:
        msg = (_("Got empty password."))
        raise OTPmeException(msg)
    return  password

def get_newest_object():
    from otpme.lib import config
    from otpme.lib import backend
    object_types = config.tree_object_types
    return_attributes = ['full_oid', 'last_modified']
    newest_date = 0
    newest_object_data = {}
    for object_type in object_types:
        result = backend.search(object_type=object_type,
                                attribute="uuid",
                                value="*",
                                order_by="last_modified",
                                return_attributes=return_attributes,
                                reverse_order=True,
                                max_results=1,
                                realm=config.realm,
                                site=config.site)
        for x in result:
            x_last_modified = result[x]['last_modified'][0]
            x_full_oid = result[x]['full_oid']
            if x_last_modified < newest_date:
                continue
            newest_date = x_last_modified
            newest_object_data = {
                                'full_oid'      : x_full_oid,
                                'last_modified' : x_last_modified,
                                }
    return newest_object_data

def update_reload_file():
    """ Update reload file. """
    from otpme.lib import config
    try:
        os.utime(config.reload_file_path, None)
    except IOError as e:
        if e.errno == e.errno.EACCES:
            raise Exception("Permission denied.")
    except Exception as e:
        msg = (_("Error accessing reload file: ") % e)
        raise Exception(msg)
    msg = (_("You must wait up to %s seconds for config reload to "
            "happen.") % config.reload_config_interval)
    raise OTPmeException(msg)

def split_list(_list, _len):
    """ Split list. """
    list_list = []
    for x in range(0, len(_list), _len):
        x_list = _list[x:x + _len]
        list_list.append(x_list)
    return list_list

def get_progressbar(maxval, title="Progress: "):
    """ Return progressbar instance. """
    from progressbar import Bar, \
                            ETA, \
                            FileTransferSpeed, \
                            Percentage, \
                            ProgressBar, \
                            RotatingMarker
    widgets = [ title,
                Percentage(),
                ' ',
                Bar(marker=RotatingMarker()),
                ' ',
                ETA(),
                ' ',
                FileTransferSpeed()
            ]
    pbar = ProgressBar(widgets=widgets, maxval=maxval).start()

    return pbar

def get_val(argv_val):
    """ Get value from argv or environment variable. """
    # Check if argv value is meant to be a environment
    # variable name (e.g. enclosed in [])
    if argv_val.startswith('['):
        try:
            # Set var name
            var_name = argv_val
            # Remove surrounding '[]' from variable name
            var_name = re.sub('^\[', '', var_name)
            var_name = re.sub('\]$', '', var_name)
            # Get variable from environment
            var_value = os.environ[var_name]
            # Remove surrounding '"' from variable value
            var_value = re.sub('^"', '', var_value)
            var_value = re.sub('"$', '', var_value)
            return var_value
        except:
            return False
    else:
        return argv_val

def gen_nt_hash(password):
    """
    Generate NT password hash. This is needed to make MSCHAP
    challenge/response verification possible.
    """
    from otpme.lib import mschap
    nt_hash = mschap.nt_password_hash(password)
    nt_hash = encode(nt_hash, "hex")
    return nt_hash

def gen_md5(string):
    """ Generate MD5 hash from string. """
    import hashlib
    if isinstance(string, str):
        string = string.encode("utf-8")
    md5sum = hashlib.md5(string).hexdigest()
    return md5sum

def gen_xxhash(string):
    """ Generate xxhash hash from string. """
    import xxhash
    if isinstance(string, str):
        string = string.encode("utf-8")
    # FIXME: use xx64() on 64bit hosts??
    x = xxhash.xxh32()
    x.update(string)
    xx_hash = x.hexdigest()
    return xx_hash

def gen_sha512(string):
    """ Generate SHA512 hash from string. """
    import hashlib
    if isinstance(string, str):
        string = string.encode("utf-8")
    sha512sum = hashlib.sha512(string).hexdigest()
    return sha512sum

def gen_pin(pin_len=4):
    """ Generate PIN from length given as arg. """
    import random
    pin = ""
    for i in range(0, pin_len):
        number = random.randint(0,9)
        pin = "%s%s" % (pin, number)
    return pin

def gen_secret(len=32, encoding="hex"):
    """ Generate secret. """
    import base64
    import codecs
    random_bytes = get_random_bytes(len)
    if encoding:
        if encoding == "hex":
            secret = codecs.encode(random_bytes, "hex")
            secret = secret.decode()
        elif encoding == "base32":
            secret = base64.b32encode(random_bytes)
            secret = secret.decode()
        elif encoding == "base64":
            secret = base64.b64encode(random_bytes)
            secret = secret.decode()
        else:
            msg = "Unknown encoding: %s" % encoding
            raise OTPmeException(msg)
    return secret

def gen_password(len=16, capital=True, numbers=True,
    symbols=False, secure=False, ambiguous=False, count=1):
    """ Generate password via pwgen. """
    from subprocess import Popen
    from subprocess import PIPE
    from otpme.lib import config

    pwgen_bin = config.pwgen_bin
    pwgen_cmd = [ pwgen_bin ]
    if capital:
        pwgen_cmd.append("-c")
    else:
        pwgen_cmd.append("-A")
    if numbers:
        pwgen_cmd.append("-n")
    else:
        pwgen_cmd.append("-0")
    if symbols:
        pwgen_cmd.append("-y")
    if secure:
        pwgen_cmd.append("-s")
    if ambiguous:
        pwgen_cmd.append("-B")
    pwgen_cmd.append(str(len))
    pwgen_cmd.append(str(count))
    pipe = Popen(pwgen_cmd, stdout=PIPE, shell=False)
    password = pipe.communicate()[0]
    password = password.decode()
    if count > 1:
        password = password.replace('\n', ' ')
        password = password.split(' ')[0:count]
    else:
        password = password.replace('\n', '')
    return password

def get_random_bits(xbits):
    """ Get random bits. """
    import random
    random_bits = str(random.getrandbits(xbits))
    return random_bits

def get_random_bytes(xbytes):
    """ Get random bytes. """
    random_bytes = os.urandom(xbytes)
    return random_bytes

def gen_uuid():
    """ Generate UUID. """
    import uuid
    new_uuid = str(uuid.uuid4())
    return new_uuid

def is_uuid(uuid):
    """ Check if given string is UUID. """
    from uuid import UUID
    try:
        UUID(uuid, version=4)
    except ValueError:
        return False
    return True

def is_base64(s):
    import base64
    import binascii
    try:
        base64.b64decode(s, validate=True)
        return True
    except binascii.Error:
        return False

def copy_object(d):
    """ Deepcopy alternative (faster). """
    #import pickle
    #o = pickle.dumps(d)
    #o = pickle.loads(o)
    o = json.dumps(d)
    o = json.loads(o)
    return o

def get_daemon_socket(daemon, node_name):
    from otpme.lib import config
    from otpme.lib import backend
    result = backend.search(object_type="node",
                            attribute="name",
                            value=node_name,
                            return_type="instance")
    if not result:
        msg = "Unknown node: %s" % node_name
        raise UnknownObject(msg)
    node = result[0]
    daemon_port = config.default_ports[daemon]
    daemon_socket = "tcp://%s:%s" % (node.fqdn, daemon_port)
    return daemon_socket

def order_data_by_deps(order_data):
    deps = {}
    for module in order_data:
        try:
            before = order_data[module]['before']
        except KeyError:
            before = []
        try:
            after = order_data[module]['after']
        except KeyError:
            after = []
        # We can use 'after' as deps for the module.
        if module not in deps:
            deps[module] = []
        deps[module] += after
        # Add emtpy 'after' deps to deps.
        for x in after:
            if x in deps:
                continue
            deps[x] = []
        # Walk through 'before' deps to build deps from it.
        for x in before:
            if x not in deps:
                deps[x] = []
            deps[x].append(module)
    # Function to order modules.
    def order_deps(module, deps, module_order, seen):
        if module in seen:
            msg = ("Circular dependency detected: %s: %s"
                    % (module, seen))
            raise OTPmeException(msg)
        seen.append(module)
        x_deps = deps[module]
        for x_module in x_deps:
            order_deps(x_module, deps, module_order, seen)
        seen.remove(module)
        # Skip already added modules.
        if module in module_order:
            return
        # Add module to order list.
        module_order.append(module)
    # Actually order the modules.
    seen = []
    module_order = []
    for module in deps:
        order_deps(module, deps, module_order, seen)
    return module_order

## This function was created by ChatGPT.
#def order_data_by_deps(modules: dict):
#    """
#    Resolves dependencies between modules based on `before` and `after` keys.
#
#    :param modules: A dictionary where keys are module names, and values are sub-dictionaries
#                    containing 'before' and 'after' dependencies.
#    :return: A list of modules in the order they should be loaded.
#    :raises ValueError: If a circular dependency is detected.
#    """
#    from collections import deque
#    from collections import defaultdict
#    # Build the graph
#    graph = defaultdict(list)
#    in_degree = defaultdict(int)
#
#    for module, dependencies in modules.items():
#        # Handle 'after' dependencies (current module depends on others)
#        for dep in dependencies.get("after", []):
#            graph[dep].append(module)
#            in_degree[module] += 1
#
#        # Handle 'before' dependencies (others depend on the current module)
#        for dep in dependencies.get("before", []):
#            graph[module].append(dep)
#            in_degree[dep] += 1
#
#        # Ensure the module itself is in the graph
#        if module not in in_degree:
#            in_degree[module] = 0
#
#    # Topological sorting using Kahn's algorithm
#    queue = deque([node for node in in_degree if in_degree[node] == 0])
#    sorted_modules = []
#
#    while queue:
#        current = queue.popleft()
#        sorted_modules.append(current)
#
#        for neighbor in graph[current]:
#            in_degree[neighbor] -= 1
#            if in_degree[neighbor] == 0:
#                queue.append(neighbor)
#
#    # Check for circular dependencies
#    if len(sorted_modules) != len(in_degree):
#        raise ValueError("Circular dependency detected!")
#
#    return sorted_modules

def get_logged_in_users():
    """ Get all logged in users. """
    import psutil
    user_list = []
    # WORKAROUND: psutil.get_users() changed to users() between psutil
    # versions.
    try:
        psutil_method = psutil.users
    except:
        psutil_method = psutil.get_users
    for i in psutil_method():
        if i.name in user_list:
            continue
        user_list.append(i.name)
    return user_list

def get_signal_name(sig_number):
    """ Get signal name by number. """
    import signal
    signal_name = signal.Signals(sig_number).name
    return signal_name

def check_pid(pid):
    """ Check if PID is running. """
    import psutil
    try:
        psutil.Process(int(pid))
        return True
    except:
        return False

def get_pid_by_name(name):
    """ Get PID by process name. """
    import psutil
    pids = []
    for proc in psutil.process_iter():
        # WORKAROUND: proc.name changed from var to method between psutil
        # versions.
        try:
            proc_name = proc.name()
        except:
            proc_name = proc.name
        if proc_name == name:
            pids.append(proc.pid)
    return pids

def get_pid(name=None, user=None):
    """ Get PID by name and/or user. """
    import psutil
    pids = []
    for proc in psutil.process_iter():
        # FIXME: Use try/except to prevent "process no longer exists (pid=...)"
        try:
            if name:
                # WORKAROUND: proc.name changed from var to method between psutil
                # versions.
                try:
                    proc_name = proc.name()
                except:
                    proc_name = proc.name
                if proc_name != name:
                    continue
            if user:
                # WORKAROUND: proc.name changed from var to method between psutil
                # versions.
                try:
                    username = proc.username()
                except:
                    username = proc.username
                if username != user:
                    continue
            pids.append(proc.pid)
        except:
            pass
    return pids

def wait_pid(pid, timeout=10, recursive=False, message_method=None):
    """ Wait for process by PID. """
    import time
    import psutil

    pid_status = False
    try:
        proc = psutil.Process(int(pid))
    except:
        return False

    # WORKAROUND: name method changed between psutil versions.
    try:
        proc_name = proc.name()
    except:
        proc_name = proc.name

    if recursive:
        try:
            children = proc.get_children(recursive=True)
        except:
            children = proc.children(recursive=True)
        children.reverse()
        for child in children:
            child_status = wait_pid(pid=child.pid,
                                recursive=False,
                                timeout=timeout,
                                message_method=message_method)
            if child_status:
                pid_status = True
    count = 0
    wait_msg_sent = 0
    _timeout = timeout * 10
    while True:
        count += 1
        # WORKAROUND: status method changed between psutil versions.
        try:
            status_method = proc.is_alive
        except:
            status_method = proc.is_running
        wait_time = int(count / 100)
        if not status_method():
            if message_method:
                if wait_time > 3:
                    msg = ("PID %s (%s) terminated after %s seconds.\n"
                            % (proc.pid, proc_name, wait_time))
                    message_method(msg)
            break
        if count >= _timeout:
            pid_status = True
            break
        if message_method and wait_time > 0:
            msg = "."
            if wait_msg_sent == 0:
                msg = ("Waiting for PID %s [%s] to finish.."
                        % (proc.pid, proc_name))
                wait_msg_sent = time.time()
            else:
                wait_msg_sent = time.time()
            message_age = time.time() - wait_msg_sent
            if message_age >= 1:
                message_method(msg)
                wait_msg_sent = time.time()
        time.sleep(0.01)
    return pid_status

def kill_pid(pid, signal=15, timeout=None, kill_timeout=None,
    recursive=False, dont_kill_start_pid=False,
    message_method=None, print_messages=False):
    """ Kill process by PID. """
    import time
    import psutil
    try:
        proc = psutil.Process(int(pid))
    except:
        return False

    if proc.status() == "zombie":
        return

    if print_messages:
        if message_method is None:
            def send_msg(msg):
                sys.stdout.write(msg)
                sys.stdout.flush()
            message_method = send_msg

    # WORKAROUND: name method changed between psutil versions.
    try:
        proc_name = proc.name()
    except:
        proc_name = proc.name

    if recursive:
        try:
            children = proc.get_children(recursive=True)
        except:
            children = proc.children(recursive=True)
        children.reverse()
        for child in children:
            # WORKAROUND: name method changed between psutil versions.
            try:
                child_name = child.name()
            except:
                child_name = child.name
            try:
                kill_pid(pid=child.pid,
                        signal=signal,
                        recursive=False,
                        timeout=timeout,
                        kill_timeout=kill_timeout,
                        print_messages=print_messages,
                        message_method=message_method)
            except Exception as e:
                if print_messages:
                    msg = ("Failed to kill child PID %s (%s): %s\n"
                            % (child.pid, child_name, e))
                    message_method(msg)

    if not dont_kill_start_pid:
        if signal == 15:
            proc.terminate()
        elif signal == 9:
            proc.kill()
        else:
            proc.send_signal(signal)

    # Set kill timeout if given.
    if kill_timeout is not None:
        timeout = kill_timeout

    if timeout is None:
        return True

    if timeout == 0:
        return True

    count = 0
    kill_count = 0
    wait_msg_sent = 0
    _timeout = timeout * 100
    while True:
        count += 1
        # WORKAROUND: status method changed between psutil versions.
        try:
            status_method = proc.is_alive
        except:
            status_method = proc.is_running
        if not status_method():
            if kill_count > 0 and print_messages:
                if wait_msg_sent > 0:
                    message_method("\n")
                msg = ("PID %s (%s) killed by SIGKILL after %s seconds."
                        % (proc.pid, proc_name, timeout))
                message_method(msg)
            break
        if count >= _timeout:
            if kill_timeout is None:
                if print_messages:
                    if wait_msg_sent > 0:
                        message_method("\n")
                    msg = ("PID %s (%s) NOT terminated by signal %s "
                            "after %s seconds."
                            % (proc.pid, proc_name, signal, timeout))
                    message_method(msg)
                break
            if kill_count >= 30:
                if print_messages:
                    if wait_msg_sent > 0:
                        message_method("\n")
                    msg = ("Unable to kill PID %s (%s) by SIGKILL"
                            % (proc.pid, proc_name))
                    message_method(msg)
                break
            try:
                proc.kill()
            except:
                pass
            kill_count += 1
        if print_messages:
            msg = "."
            if wait_msg_sent == 0:
                msg = ("Waiting for PID %s (%s) to finish.."
                        % (proc.pid, proc_name))
                wait_msg_sent = time.time() - 1
            message_age = time.time() - wait_msg_sent
            if message_age >= 1:
                message_method(msg)
                wait_msg_sent = time.time()
        time.sleep(0.01)
    if wait_msg_sent > 0:
        message_method("\n")
    return True

def kill_proc(name=None, user=None, signal=15, timeout=None):
    """ Kill process that matches the given values. """
    status = False
    for pid in get_pid(name=name, user=user):
        if not kill_pid(pid, signal=signal, timeout=timeout):
            return False
        status = True
    return status

def get_pid_user(pid):
    """ Get user PID is running as. """
    import psutil
    try:
        proc = psutil.Process(int(pid))
        # WORKAROUND: proc.name changed from var to method between psutil
        # versions.
        try:
            proc_username = proc.username()
        except:
            proc_username = proc.username
    except Exception as e:
        proc_username = None
    return proc_username

def get_pid_tty(pid):
    """ Get tty PID is running on. """
    import psutil
    try:
        proc = psutil.Process(int(pid))
        if isinstance(proc.terminal, str):
            proc_tty = proc.terminal
        else:
            proc_tty = proc.terminal()
    except:
        proc_tty = None

    return proc_tty

def get_pid_group(pid):
    """ Get group PID is running as. """
    import psutil
    import grp
    try:
        proc = psutil.Process(int(pid))
    except:
        return None

    # WORKAROUND: proc.name changed from var to method between psutil
    # versions.
    try:
        proc_group = proc.gids()[0]
    except:
        proc_group = proc.gids.real

    proc_group = grp.getgrgid(proc_group)[0]

    return proc_group

def get_pid_name(pid):
    """ Get process name of PID. """
    import psutil
    try:
        proc = psutil.Process(int(pid))
    except:
        return None

    # WORKAROUND: proc.name changed from var to method between psutil
    # versions.
    try:
        proc_name = proc.name()
    except:
        proc_name = proc.name

    return proc_name

def get_pid_parent(pid):
    """ Get parent PID of PID. """
    import psutil
    try:
        proc = psutil.Process(int(pid))
        # WORKAROUND: proc.ppid changed from var to method between psutil
        # versions.
        try:
            return proc.ppid()
        except:
            return proc.ppid
    except:
        return None

def which(filename):
    """ Search environment PATH for given file. """
    try:
        locations = os.environ.get("PATH").split(os.pathsep)
    except:
        locations = []
    for location in locations:
        x = os.path.join(location, filename)
        if os.path.isfile(x):
            return x

def get_free_memory():
    """ Get free system memory. """
    import psutil
    # WORKAROUND: psutil methods changed between versions.
    if hasattr(psutil, "virtual_memory"):
        x = psutil.virtual_memory()
    else:
        x = psutil.phymem_usage()
    free_mem = x[4]
    return free_mem

def deumlaut(s):
    """
    Replaces umlauts with fake-umlauts.
    """
    s = s.replace('\xdf', 'ss')
    s = s.replace('\xfc', 'ue')
    s = s.replace('\xdc', 'Ue')
    s = s.replace('\xf6', 'oe')
    s = s.replace('\xd6', 'Oe')
    s = s.replace('\xe4', 'ae')
    s = s.replace('\xc4', 'Ae')
    return s

def args_to_hash(arguments, ignore_args=[],
    ignore_classes=[], class_key_attributes={}):
    """ Create key from args. """
    fargs = arguments['args']
    fkwargs = arguments['kwargs']
    key = []
    for x_val in fargs:
        if isinstance(x_val, int):
            x_str = str(x_val)
        elif isinstance(x_val, float):
            x_str = str(x_val)
        elif isinstance(x_val, str):
            x_str = x_val
        elif isinstance(x_val, list):
            x_str = json.dumps(sorted(x_val))
        elif isinstance(x_val, dict):
            x_str = json.dumps(x_val, sort_keys=True)
        elif isinstance(x_val, bool):
            x_str = str(x_val)
        elif x_val is None:
            x_str = str(x_val)
        else:
            valid_class = False
            for x in x_val.__class__.__mro__:
                if x.__name__ in ignore_classes:
                    valid_class = True
                    break
                if x.__name__ in class_key_attributes:
                    valid_class = True
                    key_attr = class_key_attributes[x.__name__]
                    x_str = getattr(x_val, key_attr)
                    break
            if not valid_class:
                msg = ("Cannot convert argument to string: %s (%s)"
                        % (x_val, x_val.__class__.__name__))
                raise OTPmeException(msg)
            x_str = str(x_val)
        key.append(x_str)

    for x_key in fkwargs:
        if x_key in ignore_args:
            continue
        x_val = fkwargs[x_key]
        if isinstance(x_val, int):
            x_str = x_val
        elif isinstance(x_val, float):
            x_str = x_val
        elif isinstance(x_val, str):
            x_str = x_val
        elif isinstance(x_val, list):
            x_str = json.dumps(x_val)
        elif isinstance(x_val, dict):
            x_str = json.dumps(x_val, sort_keys=True)
        elif isinstance(x_val, bool):
            x_str = x_val
        elif x_val is None:
            x_str = x_val
        else:
            valid_class = False
            for x in x_val.__class__.__mro__:
                if x.__name__ in ignore_classes:
                    valid_class = True
                    break
                if x.__name__ in class_key_attributes:
                    valid_class = True
                    key_attr = class_key_attributes[x.__name__]
                    x_str = getattr(x_val, key_attr)
                    break
            if not valid_class:
                msg = ("Cannot convert argument %s to string: %s (%s)"
                        % (x_key, x_val, x_val.__class__.__name__))
                raise OTPmeException(msg)
            x_str = str(x_val)
        # FIXME: Do we need this with python3?
        # Make sure key is of type string.
        if isinstance(x_key, str):
            x_key = str(x_key)

        key_str = "%s:%s" % (x_key, x_str)
        key.append(key_str)

    key = sorted(key)
    key = ",".join(key)
    key = gen_md5(key)
    return key

def string_to_type(value, ignore_int=False, ignore_float=False):
    """ Try to find value type and return value as the correct type. """
    # Non-string values need no conversion.
    if not isinstance(value, str):
        return value

    # Check if value is int() before float() because float can match int but
    # not vice versa.
    if not ignore_int:
        try:
            # FIXME: Workaround to prevent a string (e.g. an OTP)
            #        from beeing treated as int (e.g. 085624).
            #        str(val) should always be equal to str(int(val))
            int_val = int(value)
            if str(int_val) == str(value):
                return int_val
        except:
            pass
    # Check if value is float().
    if not ignore_float:
        try:
            # FIXME: Workaround to prevent a string (e.g. an OTP)
            #        from beeing treated as float (e.g. 461e49).
            #        str(val) should always be equal to str(float(val))
            float_val = float(value)
            if str(float_val) == str(value):
                return float_val
        except:
            pass

    ## Check if value is boolean
    #bool_re = re.compile("True|False", re.IGNORECASE)
    ## Check if value is None
    #none_re = re.compile("None", re.IGNORECASE)

    ## Check for bool(), None and str()
    #if bool_re.match(value):
    #    if value.lower() == "true":
    #        return True
    #    elif value.lower() == "false":
    #        return False
    #elif none_re.match(value):
    #    if value.lower() == "none":
    #        return None
    #else:
    #    return value

    # Check for "True".
    if value.lower() == "true":
        return True
    # Check for "False".
    if value.lower() == "false":
        return False
    # Check for "None".
    if value.lower() == "none":
        return None

    return value

def conf_to_dict(file_content, parameters=None):
    """ Convert config file content (key=val) to dict. """
    # FIXME: Make this function work with re2.
    import re
    remove_start_quotation = False
    value_start_found = False
    value_end_found = False
    multiline_value = False
    value_quotation = None
    object_config = {}
    para_values = []
    for line in file_content.split("\n"):
        # Remove new line from line..
        if line.endswith('\n'):
            line = line.replace('\n', '')

        if line.strip().startswith("#"):
            continue

        # Skip empty lines.
        if len(line) == 0:
            continue

        # Skip comments.
        # If we already found the value start this is a multi line value.
        if value_start_found:
            para_val = line
        elif "=" in line:
            # Get parameter name and value from config file line.
            try:
                para_name, para_val = line.split('=', 1)
                para_name = para_name.strip()
                para_val = para_val.strip()
            except:
                raise Exception(_("Wrong config file format: %s") % line)
            if parameters and not para_name in parameters:
                continue

        # Remove quotation mark from value start.
        if not value_start_found:
            if para_val.startswith('"'):
                value_quotation = '"'
                remove_start_quotation = True
            elif para_val.startswith("'"):
                value_quotation = "'"
                remove_start_quotation = True

        if remove_start_quotation:
            value_start_found = True
            quotation_re = '^%s' % value_quotation
            para_val = re.sub(quotation_re, '', para_val)
            #print("START_FOUND", para_val)
            remove_start_quotation = False
            if not para_val.endswith(value_quotation):
                multiline_value = True

        # Remove quotation mark from value end.
        if not value_end_found:
            if para_val.endswith(value_quotation):
                #print("END_FOUND:", para_val)
                value_end_found = True
                quotation_re = '%s$' % value_quotation
                para_val = re.sub(quotation_re, '', para_val)

        if multiline_value:
            # Skip empty value lines (e.g. for multiline values).
            if len(para_val) != 0:
                para_val = string_to_type(para_val)
                para_values.append(para_val)

        if not value_end_found:
            continue

        # Try to get build new dict entry with the correct value type
        # (string_to_type()).
        if multiline_value:
            para_values = "".join(para_values)
            new_para = { para_name : para_values }
        else:
            para_val = string_to_type(para_val)
            new_para = { para_name : para_val }

        # Update object config value
        object_config.update(new_para)

        value_start_found = False
        value_end_found = False
        multiline_value = False
        para_values = []

    return object_config

#def dict_to_conf(object_config):
#    """ Convert object config (dict) to config file content. """
#    file_content = ""
#    object_sum = None
#    object_uuid = None
#    parameters = list(object_config)
#    parameters.sort()
#    for para in parameters:
#        val = object_config[para]
#        conf_line = "%s='%s'\n" % (para, val)
#        if para == "UUID":
#            object_uuid = conf_line
#        elif para == "CHECKSUM":
#            object_sum = conf_line
#        else:
#            file_content = "%s%s" % (file_content, conf_line)
#    if object_uuid:
#        # Put object UUID on top to improve performance on backend index
#        # rebuild (file backend).
#        file_content = "%s%s" % (object_uuid, file_content)
#    if object_sum:
#        # Put object CHECKSUM on top to improve performance when reading
#        # object checksums only (e.g. sync).
#        file_content = "%s%s" % (object_sum, file_content)
#    return file_content

def convert_listdict(o, keep_unicode_iterkeys=False, keep_unicode_values=False):
    """ Walk list/dict recursive and convert values. """
    if isinstance(o, list):
        new_list = []
        for v in o:
            x = convert_listdict(v)
            new_list.append(x)
        return new_list
    elif isinstance(o, dict):
        new_dict = {}
        for n in o:
            v = o[n]
            if keep_unicode_iterkeys:
                x = n
            else:
                x = convert_listdict(n)
            if keep_unicode_values:
                y = v
            else:
                y = convert_listdict(v)
            new_dict[x] = y
        return new_dict
    else:
        return string_to_type(o)

def get_users_groups(username):
    import pwd
    import grp
    user_info = pwd.getpwnam(username)
    user_gid = user_info.pw_gid
    groups = []
    for g in grp.getgrall():
        if g.gr_gid == user_gid:
            groups.append(g.gr_name)
        elif username in g.gr_mem:
            groups.append(g.gr_name)
    return groups

def get_users_default_group(username):
    import pwd
    import grp
    pw_record = pwd.getpwnam(username)
    gid = pw_record.pw_gid
    group_name = grp.getgrgid(gid).gr_name
    return group_name

def user_exists(username):
    """ Check if given system user exists. """
    import pwd
    try:
        pwd.getpwnam(username)
    except KeyError:
        raise Exception(_("System user does not exist: %s") % username)

def group_exists(groupname):
    """ Check if given system user exists. """
    import grp
    try:
        grp.getgrnam(groupname)
    except KeyError:
        raise Exception(_("System group does not exist: %s") % groupname)

def contains_non_ascii(string):
    """" Check if string contains non-ascii chars. """
    for i in string:
        if ord(i) > 127 or i in ('\0', '\n', '\r'):
            return True
    return False

def websafe_encode(data):
    """ Encode data websafe base64. """
    import base64
    # Encode data and remove leading padding.
    #encoded_data = base64.urlsafe_b64encode(data).replace('=', '')
    # FIXME: python 3???
    # Make sure data is UTF-8.
    #data = data.encode('utf-8', 'ignore')
    encoded_data = base64.urlsafe_b64encode(data).decode().replace('=', '')
    return encoded_data

def websafe_decode(data):
    """ Decode websafe base64 string. """
    import base64
    # Add required base64 padding.
    pad_len = len(data) % 4
    data = "%s%s" % (data, (pad_len * "="))
    # Make sure data is UTF-8.
    data = data.encode('utf-8')
    if isinstance(data, bytes):
        data = data.decode()
    # Decode data.
    decoded_data = base64.urlsafe_b64decode(data)
    # FIXME: python 3???
    #decoded_data = base64.urlsafe_b64decode(data).decode()
    #decoded_data = decoded_data.decode()
    return decoded_data

def seed_rng(fork=True, quiet=False):
    """ Reinitialize RNG. """
    import ssl
    try:
        from Cryptodome import Random
    except:
        from Crypto import Random
        msg = "Failed to load pycryptodome, using pycrypto."
        print(msg)
    from otpme.lib import config

    logger = config.logger
    status = True
    if config.debug_level() < 4:
        quiet = True
    # Fix "AssertionError: PID check failed. RNG must be re-initialized after fork(). Hint: Try Random.atfork()"
    # Caveat: For the random number generator to work correctly, you must
    # call Random.atfork() in both the parent and child processes after
    # using os.fork()
    # https://github.com/dlitz/pycrypto
    if not quiet:
        logger.debug("Reinitializing RNG.")

    if fork:
        try:
            Random.atfork()
            if not quiet:
                logger.debug("Reinitializing done.")
        except Exception as e:
            #config.raise_exception()
            msg = ("Reinitializing of RNG failed: %s" % e)
            logger.critical(msg)
            status = False

    # Seed random number generator after spawning a child process.
    # https://docs.python.org/2/library/ssl.html#multi-processing
    # https://wiki.openssl.org/index.php/Random_fork-safety
    rand_seed_bytes = 32
    if not quiet:
        msg = ("Seeding RNG with %s bytes." % rand_seed_bytes)
        logger.debug(msg)
    try:
        random_bits = get_random_bytes(rand_seed_bytes)
    except Exception as e:
        random_bits = None
        msg = ("Seeding RNG failed: Unable to get random bits: %s" % e)
        logger.critical(msg)
        status = False

    if random_bits is not None:
        try:
            ssl.RAND_add(random_bits, 0.0)
            if not quiet:
                logger.debug("Seeding finished.")
        except Exception as e:
            logger.critical("Seeding RNG failed: %s" % e)
            status = False
    return status

def resolve_uuid(object_uuid, object_type=None, object_types=None):
    """ Resolve UUID to OID. """
    from otpme.lib import oid
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import connections
    if config.use_backend:
        object_id = backend.get_oid(uuid=object_uuid,
                                    object_type=object_type,
                                    object_types=object_types,
                                    instance=True)
    else:
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            msg = (_("Error connecting to hostd: %s") % e)
            raise OTPmeException(msg)
        object_id = hostd_conn.get_oid(object_uuid=object_uuid,
                                    object_type=object_type,
                                    object_types=object_types)
        if object_id:
            object_id = oid.get(object_id)
    if not object_id:
        msg = "Unable to resolve UUID: %s" % object_uuid
        raise UnknownUUID(msg)
    return object_id

def resolve_oid(object_id):
    """ Resolve UUID to OID. """
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import connections
    if config.use_backend:
        object_uuid = backend.get_uuid(object_id)
    else:
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            msg = (_("Error connecting to hostd: %s") % e)
            raise OTPmeException(msg)
        object_uuid = hostd_conn.get_uuid(str(object_id))
    if not object_uuid:
        msg = "Unable to resolve OID: %s" % object_id
        raise UnknownOID(msg)
    return object_uuid

def object_exists(object_id):
    """ Check if object exists by OID. """
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import connections
    if config.use_backend:
        if backend.object_exists(object_id):
            return True
        return False
    try:
        hostd_conn = connections.get("hostd")
    except Exception as e:
        msg = (_("Error connecting to hostd: %s") % e)
        raise OTPmeException(msg)
    if hostd_conn.object_exists(str(object_id)):
        return True
    return False

def search(**kwargs):
    """ Do search. """
    from otpme.lib import config
    from otpme.lib import backend
    if config.use_backend:
        result = backend.search(**kwargs)
        return result
    from otpme.lib.classes.command_handler import CommandHandler
    command_handler = CommandHandler(interactive=False)
    # FIXME: how to make sure we connect to correct site???
    result = command_handler.search(**kwargs)
    return result

def get_agent_vars(string):
    """ Get gpg/ssh-agent variables from string. """
    ssh_agent_name = None
    ssh_agent_pid = None
    ssh_auth_sock = None
    gpg_agent_info = None
    for line in string.split("\n"):
        if line.startswith("SSH_AUTH_SOCK="):
            ssh_auth_sock = re.sub('^SSH_AUTH_SOCK=([^;]*);.*', r'\1', line)
        if line.startswith("SSH_AGENT_PID="):
            ssh_agent_pid = re.sub('^SSH_AGENT_PID=([^;]*);.*', r'\1', line)
        if line.startswith("GPG_AGENT_INFO="):
            gpg_agent_info = re.sub('^GPG_AGENT_INFO=([^;]*);.*', r'\1', line)
        if line.startswith("SSH_AGENT_NAME="):
            ssh_agent_name = re.sub('^SSH_AGENT_NAME=([^;]*);.*', r'\1', line)
    return ssh_agent_name, ssh_agent_pid, ssh_auth_sock, gpg_agent_info

def start_otpme_agent(user=None, group=True,
    wait_for_socket=True, quiet=True):
    """ Start OTPme agent. """
    # Create otpme-agent instance.
    from otpme.lib import config
    from otpme.lib import system_command
    from otpme.lib.messages import message
    from otpme.lib.classes.otpme_agent import OTPmeAgent
    # Get logger.
    logger = config.logger
    # Check if agent is already running.
    otpme_agent = OTPmeAgent(user=user)
    agent_status, pid = otpme_agent.status(quiet=True)
    if agent_status:
        return True
    if user:
        _user = user
    else:
        _user = config.system_user()
    msg = "Starting otpme-agent (%s)..." % _user
    logger.debug(msg)
    if not quiet:
        message(msg)
    agent_socket = config.get_agent_socket(user).split(":")[1]
    otpme_agent_bin = '%s/otpme-agent' % config.bin_dir
    command = [ otpme_agent_bin, "start"]
    agent_returncode, \
    agent_stdout, \
    agent_stderr, \
    agent_pid = system_command.run(command=command, user=user, group=group)
    if agent_returncode != 0:
        msg = (_("Starting otpme-agent failed: %s") % agent_stderr)
        raise OTPmeException(msg)
    if not wait_for_socket:
        return
    wait_for_agent_socket(agent_socket=agent_socket)

def stop_otpme_agent(user=None, wait=True, quiet=True):
    """ Start OTPme agent. """
    # Stop otpme-agent instance.
    from otpme.lib.classes.otpme_agent import OTPmeAgent
    # Check if agent is already running.
    otpme_agent = OTPmeAgent(user=user)
    agent_status, pid = otpme_agent.status(quiet=quiet)
    if not agent_status:
        return
    otpme_agent.stop(wait=wait)

def wait_for_agent_socket(user=None, agent_socket=None, quiet=True):
    """ Wait for otpme-agent socket to appear. """
    import time
    from otpme.lib import config
    from otpme.lib.messages import message
    count = 0
    socket_wait = 500
    if agent_socket is None:
        agent_socket = config.get_agent_socket(user=user).split(":")[1]
    if os.path.exists(agent_socket):
        return
    logger = config.logger
    msg = "Waiting for otpme-agent socket..."
    if not quiet:
        message(msg)
    logger.debug(msg)
    while True:
        if count >= socket_wait:
            msg =(_("Timeout waiting for agent socket to appear."))
            raise OTPmeException(msg)
        if os.path.exists(agent_socket):
            # Wait a moment for otpme-agent to listen on the created socket.
            time.sleep(0.01)
            break
        count += 1
        time.sleep(0.01)

def controld_status():
    """ Get controld status. """
    from otpme.lib import config
    from otpme.lib.register import register_module
    from otpme.lib.daemon.controld import ControlDaemon
    register_module("otpme.lib.daemon.controld")
    control_daemon = ControlDaemon(config.controld_pidfile)
    if control_daemon.status(quiet=True)[0]:
        return True
    return False

def start_otpme_daemon():
    """ Start OTPme daemons. """
    # Create otpme-controld instance
    from otpme.lib import config
    from otpme.lib import system_command
    from otpme.lib.register import register_module
    from otpme.lib.daemon.controld import ControlDaemon
    register_module("otpme.lib.daemon.controld")
    # Get logger
    logger = config.logger
    # Check if daemon is already running.
    control_daemon = ControlDaemon(config.controld_pidfile)
    daemon_status, pid = control_daemon.status(quiet=True)
    if daemon_status:
        return True
    logger.debug("Starting OTPme daemons...")
    otpme_daemon_bin = '%s/otpme-controld' % config.bin_dir
    command = [ otpme_daemon_bin, "start" ]
    daemon_returncode, \
    daemon_stdout, \
    daemon_stderr, \
    daemon_pid = system_command.run(command=command)
    if daemon_returncode != 0:
        raise Exception(_("Starting OTPme daemons failed: %s") % daemon_stderr)
    return daemon_stdout

def stop_otpme_daemon(kill=False, timeout=None):
    """ Stop OTPme daemons. """
    # Create otpme-controld instance
    from otpme.lib import config
    from otpme.lib import system_command
    from otpme.lib.register import register_module
    from otpme.lib.daemon.controld import ControlDaemon
    register_module("otpme.lib.daemon.controld")
    # Get logger
    logger = config.logger
    # Check if agent is already running
    control_daemon = ControlDaemon(config.controld_pidfile)
    daemon_status, pid = control_daemon.status(quiet=True)
    if not daemon_status:
        return True
    msg = "Stopping OTPme daemons..."
    print(msg)
    logger.debug(msg)
    otpme_daemon_bin = '%s/otpme-controld' % config.bin_dir
    command = [ otpme_daemon_bin, "stop" ]
    if kill:
        command.append("-k")
    if timeout:
        command.append("--timeout")
        command.append(str(timeout))
    daemon_returncode, \
    daemon_stdout, \
    daemon_stderr, \
    daemon_pid = system_command.run(command=command)
    if daemon_returncode != 0:
        msg = (_("Stopping OTPme daemons failed: %s") % daemon_stderr)
        raise OTPmeException(msg)
    return daemon_stdout

def get_key_script(username):
    """ Get users key script from mgmtd. """
    from otpme.lib import config
    from otpme.lib.offline_token import OfflineToken
    from otpme.lib.classes.command_handler import CommandHandler

    key_script = None
    key_script_path = None
    key_script_opts = None
    key_script_signs = None

    # Get logger
    logger = config.logger

    command_handler = CommandHandler(interactive=False)
    try:
        key_script_path, \
        key_script_opts, \
        key_script_uuid, \
        key_script_signs, \
        key_script = command_handler.get_user_key_script(username=username)
    except Exception as e:
        msg = (_("Error getting user key script from server: %s") % e)
        logger.debug(msg)
        #raise OTPmeException(msg)

    if not key_script:
        try:
            offline_token = OfflineToken()
            offline_token.set_user(user=username)
            key_script_path, \
            key_script_opts, \
            key_script_uuid, \
            key_script_signs, \
            key_script = offline_token.get_script(script_id="key")
        except Exception as e:
            msg = ("Unable to get key script from offline tokens: %s" % e)
            logger.debug(msg)
            raise OTPmeException(msg)

    if not key_script_path:
        msg = ("User does not have a key script configured.")
        raise OTPmeException(msg)

    if not key_script:
        msg = (_("Users key script does not exist or is empty: %s")
                % key_script_path)
        raise OTPmeException(msg)

    return (key_script_path, key_script_opts, key_script_uuid,
            key_script_signs, key_script)

def verify_key_script(username, key_script=None,
    key_script_path=None, signatures=None):
    """ Verify users key script signatures. """
    from otpme.lib import config
    from otpme.lib.classes import signing

    if key_script and not key_script_path:
        msg = (_("Need 'key_script_path' when 'key_script' is given."))
        raise OTPmeException(msg)

    # Get users key script if none was given.
    if not key_script:
        try:
            key_script_path, \
            key_script_opts, \
            key_script_uuid, \
            key_script_signs, \
            key_script = get_key_script(username)
        except Exception as e:
            msg = (_("Error getting user key script: %s") % e)
            raise OTPmeException(msg)
        # Do not override given signatures.
        if not signatures and key_script_signs:
            signatures = key_script_signs

    # Get key script singers.
    script_signers = signing.get_signers(signer_type="key_script",
                                            username=username)
    # If no key script signature check is configured we are done.
    if not script_signers:
        return

    # Without signatures verification must fail.
    if not signatures:
        msg = (_("Key script verification failed: "
            "No key script signatures found."))
        raise OTPmeException(msg)

    # Verify key script.
    try:
        signing.verify_signatures(signer_type="key_script",
                                signers=script_signers,
                                signatures=signatures,
                                sign_data=key_script,
                                stop_on_fist_match=True)
    except OTPmeException as e:
        config.raise_exception()
        msg = (_("No valid key script signatures found: %s") % e)
        raise OTPmeException(msg)
    except Exception as e:
        config.raise_exception()
        msg = (_("Error verifying signatures: %s") % e)
        raise OTPmeException(msg)

def run_key_script(username, script_command, script_options=None,
    key_pass=None, key_pass_new=None, private_key=None, aes_pass=None,
    call=True, return_proc=False, key_script=None, key_script_options=None,
    key_script_uuid=None, user=None, group=None, disable_ctrl_c=True):
    """
    Run users key script with the given options and optionally verify
    script signatures.
    """
    from otpme.lib import config
    # Get logger
    logger = config.logger

    # If no user is given we run the script as the current system user.
    if user is None:
        user = config.system_user()

    if key_script and not key_script_uuid:
        msg = (_("Need 'key_script_uuid' when 'key_script' is given."))
        raise OTPmeException(msg)

    # Get users key script if none was given.
    if not key_script:
        try:
            key_script_path, \
            key_script_opts, \
            key_script_uuid, \
            key_script_signs, \
            key_script = get_key_script(username)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error getting user key script: %s") % e)
            raise OTPmeException(msg)

    if not key_script_path:
        msg = (_("User does not have a key script configured."))
        raise OTPmeException(msg)

    if not key_script:
        msg = (_("Users key script does not exist or is empty: %s")
                % key_script_path)
        raise OTPmeException(msg)

    logger.debug("Using key script: %s" % key_script_path)

    # Get a copy of our shell environment.
    script_env = os.environ.copy()
    # Set username for key script.
    script_env['_OTPME_KEYSCRIPT_USER'] = username
    # Set private key for key script.
    if private_key:
        script_env['_OTPME_KEYSCRIPT_PRIVATE_KEY'] = private_key
    # Set key password.
    if key_pass:
        script_env['_OTPME_KEYSCRIPT_KEY_PASS'] = key_pass
    # Set new password.
    if key_pass_new:
        script_env['_OTPME_KEYSCRIPT_KEY_PASS_NEW'] = key_pass_new
    # Set AES password.
    if aes_pass:
        script_env['_OTPME_KEYSCRIPT_AES_PASS'] = aes_pass

    # Build key script options.
    if key_script_options is None:
        key_script_options = []
    key_script_options += script_command
    if key_script_opts is not None:
        key_script_options += key_script_opts

    # Make sure script_options is a list.
    if script_options is None:
        script_options = []

    # Make sure we pass API options to key script.
    if config.use_api:
        if config.api_auth_token:
            auth_token_opt = "--auth-token"
            if auth_token_opt not in script_options:
                script_options.insert(0, config.api_auth_token)
                script_options.insert(0, auth_token_opt)
        api_opt = "--api"
        if api_opt not in script_options:
            script_options.insert(0, api_opt)

    # Add script options.
    key_script_options += script_options

    from otpme.lib import script
    # Run key script.
    return_val = script.run(script_type="key_script",
                        script_uuid=key_script_uuid,
                        script=key_script,
                        script_path=key_script_path,
                        options=key_script_options,
                        return_proc=return_proc,
                        script_env=script_env,
                        verify_signatures=True,
                        signatures=key_script_signs,
                        disable_ctrl_c=disable_ctrl_c,
                        user=user,
                        group=group,
                        call=call)
    return return_val

def encrypt_share_key(username, share_user, share_key, key_mode, disable_ctrl_c=False):
    # Make sure share key is bytes.
    if isinstance(share_key, str):
        share_key = share_key.encode()
    # Command for key script.
    script_command = [ "rsa_encrypt" ]
    # Add key mode.
    if key_mode == "server":
        script_command.append("--server-key")
    # Add share user option.
    script_options = ['-u', share_user]
    # Run key script.
    proc = run_key_script(username=username,
                        call=False,
                        return_proc=True,
                        script_command=script_command,
                        script_options=script_options,
                        disable_ctrl_c=disable_ctrl_c)
    proc.stdin.write(share_key)
    proc.stdin.flush()
    proc.stdin.close()
    encrypted_share_key = proc.stdout.read()
    proc.wait()
    script_stderr = proc.stderr.read()
    returncode = proc.returncode
    if returncode != 0:
        msg = "Failed to run key script: %s" % script_stderr
        raise OTPmeException(msg)
    # Make sure share key is string.
    if isinstance(encrypted_share_key, bytes):
        encrypted_share_key = encrypted_share_key.decode()
    return encrypted_share_key

def decrypt_share_key(username, encrypted_share_key,
    key_mode, encode=True, disable_ctrl_c=False):
    import base64
    # Make sure share key is bytes.
    if isinstance(encrypted_share_key, str):
        encrypted_share_key = encrypted_share_key.encode()
    # Command for key script.
    script_command = [ "rsa_decrypt" ]
    # Add key mode.
    if key_mode == "server":
        script_command.append("--server-key")
    # Run key script.
    proc = run_key_script(username=username,
                        call=False,
                        return_proc=True,
                        script_command=script_command,
                        disable_ctrl_c=disable_ctrl_c)
    proc.stdin.write(encrypted_share_key)
    proc.stdin.flush()
    proc.stdin.close()
    proc.wait()
    decrypted_share_key = proc.stdout.read()
    script_stderr = proc.stderr.read()
    returncode = proc.returncode
    if returncode != 0:
        msg = "Failed to run key script: %s" % script_stderr
        raise OTPmeException(msg)
    if encode:
        decrypted_share_key = base64.b64encode(decrypted_share_key)
        # Make sure share key is string.
        if isinstance(decrypted_share_key, bytes):
            decrypted_share_key = decrypted_share_key.decode()
    return decrypted_share_key

#def get_share_key(username, share_name, disable_ctrl_c=False):
#    import base64
#    from otpme.lib.classes.command_handler import CommandHandler
#    command_args = {'share_name':share_name}
#    command_handler = CommandHandler()
#    encrypted_share_key = command_handler.send_command(daemon="mgmtd",
#                                                    command="user",
#                                                    subcommand="get_share_key",
#                                                    command_args=command_args,
#                                                    object_list=[username],
#                                                    parse_command_syntax=False,
#                                                    client_type="RAPI")
#    share_key = decrypt_share_key(username,
#                                encrypted_share_key,
#                                key_mode=None,
#                                disable_ctrl_c=disable_ctrl_c)
#    try:
#        share_key = base64.b64decode(share_key)
#    except Exception as e:
#        msg = "Failed to decode share key: %s" % e
#        raise OTPmeException(msg)
#    return share_key

def get_agent_user():
    """ Try to get logged in user from otpme-agent. """
    from otpme.lib import config
    from otpme.lib import connections
    if config.use_api:
        return None
    agent_user = None
    agent_conn = None
    # Try to get agent connection
    agent_conn = connections.get("agent")
    try:
        # Try to get logged in user from otpme-agent
        if agent_conn.get_status():
            agent_user = agent_conn.get_user()
    except Exception as e:
        raise Exception(_("Error getting agent connection: %s") % e)
    return agent_user

def get_user_uuid(username):
    """ Resolve username to UUID. """
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import connections
    if config.use_backend:
        result = backend.search(object_type="user",
                                    attribute="name",
                                    value=username,
                                    return_type="uuid")
        if not result:
            return
        user_uuid = result[0]
    else:
        hostd_conn = connections.get("hostd")
        command = "get_user_uuid"
        command_args = {'username':username}
        status, \
        status_code, \
        reply, \
        binary_data = hostd_conn.send(command, command_args)
        if not status:
            return
        user_uuid = reply
    return user_uuid

def get_username_by_uuid(uuid):
    """ Resovle UUID to username via hostd. """
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import connections
    if config.use_backend:
        user_oid = backend.get_oid(object_type="user", uuid=uuid, instance=True)
        if not user_oid:
            return None
        user_name = user_oid.name
    else:
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            raise Exception(_("Error connecting to hostd: %s") % e)
        command_args = {'user_uuid':uuid}
        command = "get_user_name"
        status, \
        status_code, \
        reply, \
        binary_data = hostd_conn.send(command, command_args)
        user_name = reply
        if not status:
            return None
    return user_name

def get_site_address(realm, site):
    """ Get site address/FQDN. """
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import connections
    if config.use_backend:
        _site = backend.get_object(object_type="site",
                                    name=site,
                                    realm=realm)
        if _site:
            site_address = _site.address
        else:
            msg = (_("Unknown site: %s") % site)
            raise OTPmeException(msg)
    else:
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            msg = (_("Error connecting to hostd: %s") % e)
            raise OTPmeException(msg)
        daemon_command = "get_site_address"
        command_args = {
                        'realm' : realm,
                        'site'  : site,
                    }
        status, \
        status_code, \
        reply, \
        binary_data = hostd_conn.send(daemon_command, command_args)
        if not status:
            msg = (_("Error getting site address from hostd: %s") % reply)
            raise ConnectionError(msg)
        site_address = reply
    return site_address

def get_site_fqdn(realm, site, mgmt=False):
    """ Get site address/FQDN. """
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import connections
    if config.use_backend:
        _site = backend.get_object(object_type="site",
                                    name=site,
                                    realm=realm)
        if _site:
            if mgmt:
                site_address = _site.mgmt_fqdn
            else:
                site_address = _site.auth_fqdn
        else:
            msg = (_("Unknown site: %s") % site)
            raise OTPmeException(msg)
    else:
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            msg = (_("Error connecting to hostd: %s") % e)
            raise OTPmeException(msg)
        if mgmt:
            daemon_command = "get_site_mgmt_fqdn"
        else:
            daemon_command = "get_site_auth_fqdn"
        command_args = {
                        'realm' : realm,
                        'site'  : site,
                    }
        status, \
        status_code, \
        reply, \
        binary_data = hostd_conn.send(daemon_command, command_args)
        if not status:
            msg = (_("Error getting site address from hostd: %s") % reply)
            raise ConnectionError(msg)
        site_address = reply
    return site_address

def get_site_cert(realm, site):
    """ Get site address/FQDN. """
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import connections
    if config.use_backend:
        _site = backend.get_object(object_type="site",
                                    name=site,
                                    realm=realm)
        if not _site:
            msg = (_("Unknown site: %s") % site)
            raise OTPmeException(msg)
        site_cert = _site.cert
        return site_cert
    # Get site cert from hostd.
    try:
        hostd_conn = connections.get("hostd")
    except Exception as e:
        msg = (_("Error connecting to hostd: %s") % e)
        raise OTPmeException(msg)
    site_cert = hostd_conn.get_site_cert(realm=realm, site=site)
    return site_cert

def get_site_trust_status(realm, site):
    """ Get site trust status. """
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import connections

    if config.use_backend:
        # We can always trust users site.
        if config.realm == realm and config.site == site:
            return True
        # Load our site.
        result = backend.search(object_type="site",
                                attribute="name",
                                value=config.site,
                                realm=config.realm,
                                return_type="instance")
        if not result:
            raise Exception(_("Unknown site: %s") % site)
        our_site = result[0]
        # Load site we want to connect to.
        result = backend.search(object_type="site",
                                attribute="name",
                                value=site,
                                realm=realm,
                                return_type="instance")
        if not result:
            raise Exception(_("Unknown site: %s") % site)
        check_site = result[0]
        if check_site.uuid in our_site.trusted_sites:
            return True
        msg = "Site not trusted: %s" % check_site
        raise SiteNotTrusted(msg)

    # Get daemon connection
    try:
        hostd_conn = connections.get("hostd")
    except Exception as e:
        raise Exception(_("Error connecting to hostd: %s") % e)
    # Get site trust status.
    hostd_command = "get_site_trust_status"
    command_args = {
                    'realm'     : realm,
                    'site'      : site,
                }
    status, \
    status_code, \
    reply, \
    binary_data = hostd_conn.send(command=hostd_command,
                        command_args=command_args)
    if not status:
        raise Exception(_("Unable to get site trust status: %s")
                        % reply)
    if reply == "trusted":
        return True
    raise SiteNotTrusted(reply)

def check_login_user(user_name, user_uuid):
    """ Check if the given user/uuid is allowed to login. """
    from otpme.lib import config
    if config.deny_login_users:
        user_allowed = True
        for x in config.deny_login_users:
            if ":" in x:
                name = x.split(":")[0]
                uuid = x.split(":")[1]
            else:
                name = x
                uuid = None
            if user_name == name:
                user_allowed = False
                break
            if user_uuid == uuid:
                user_allowed = False
                break
        if not user_allowed:
            msg = (_("User denied by DENY_LOGIN_USERS: %s") % user_name)
            raise Exception(msg)

    if config.valid_login_users:
        user_allowed = False
        for x in config.valid_login_users:
            if ":" in x:
                name = x.split(":")[0]
                uuid = x.split(":")[1]
            else:
                name = x
                uuid = None
            if user_name == name:
                user_allowed = True
                break
            if user_uuid == uuid:
                user_allowed = True
                break
        if not user_allowed:
            msg = (_("User denied: Not found in " "VALID_LOGIN_USERS: %s")
                    % user_name)
            raise Exception(msg)

def add_decorators(decorator, blacklist_functions=[],
    blacklist_methods=[], func_names_regex=None):
    """ Add decorators to functions and classes. """
    import importlib
    from otpme.lib import preload
    for x in preload.preload_modules:
        if x == __name__:
            continue
        module = importlib.import_module(x)
        add_decorator(decorator, module,
                    blacklist_functions,
                    blacklist_methods,
                    func_names_regex)

def add_decorator(decorator, module, blacklist_functions=[],
    blacklist_methods=[], func_names_regex=None):
    """
    Add decorator if the method/function module matches module name.
    """
    import types
    for x in dir(module):
        module_name = module.__name__
        f = getattr(module, x)
        if isinstance(f, type):
            if f.__module__ != module_name:
                continue
            for y in dir(f):
                try:
                    m = getattr(f, y)
                    m_module = m.__module__
                except:
                    continue
                if m_module != module_name:
                    continue
                class_method = False
                method_path = "%s.%s.%s" % (m.__module__, x, y)
                add_method = True
                for x_path in blacklist_methods:
                    if x_path in method_path:
                        add_method = False
                        break
                if func_names_regex:
                    add_method = False
                    for f_regex in func_names_regex:
                        f_re = re.compile(f_regex)
                        if f_re.match(method_path):
                            add_method = True
                            break
                if not add_method:
                    continue
                try:
                    if m.__self__ == f:
                        class_method = True
                except Exception as e:
                    msg = ("Unable to get method type: %s" % method_path)
                    raise OTPmeException(msg)
                # FIXME: How to add decorator to class method with @classmethod??
                #        "TypeError: unbound method xy() must be called with..."
                if class_method:
                    #msg = ("Skipping @classmethod: %s" % method_path)
                    #error_message(msg)
                    continue
                m_decorator = decorator(m, _otpme_is_class_method=True)
                setattr(f, y, m_decorator)

        elif isinstance(f, types.FunctionType):
            add_method = True
            method_path = "%s.%s" % (f.__module__, f.__name__)
            if func_names_regex:
                add_method = False
                for f_regex in func_names_regex:
                    f_re = re.compile(f_regex)
                    if f_re.match(method_path):
                        add_method = True
                        break
            for x_path in blacklist_functions:
                if x_path in method_path:
                    add_method = False
                    break
            if not add_method:
                continue
            f_decorator = decorator(f)
            setattr(module, x, f_decorator)
