# -*- coding: utf-8 -*-

# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""Best-effort notification publisher for idled subscribers.

Producers (e.g. share.add_token/add_role/remove_*) call notify() to inform
all connected otpme-agent instances of the given user via the idled daemon.

Delivery is fire-and-forget: if idled is not running, the local socket is
absent, or the call fails, the notification is silently dropped. Agents
must be able to recover authoritative state on (re)connect; notifications
are a wake-up signal, not a transactional message.
"""
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib import connections

from otpme.lib.exceptions import *

def notify_host(host_uuid, event_type, data=None):
    """ Tell a host that there is something for it.

    Returns how many of the host's connections heard it, so a caller
    can say whether the host was reached. Zero is an answer and not a
    failure: a host that is not waiting picks the news up on its next
    round, which is what it did before anybody was told anything.

    What a host is told is never more than "look now". Everything that
    decides whether it may do something is checked where it always was:
    the job is fetched from syncd and verified against the signers the
    host holds.
    """
    if config.use_api:
        return 0
    if data is None:
        data = {}
    idled_conn = None
    try:
        idled_conn = connections.get("idled",
                                    auto_auth=False,
                                    auto_preauth=False,
                                    handle_host_auth=False,
                                    handle_user_auth=False,
                                    encrypt_session=False)
        command_args = {
                    'host_uuid'     : host_uuid,
                    'event_type'    : event_type,
                    'data'          : data,
                    }
        status, \
        status_code, \
        response, \
        binary_data = idled_conn.send(command="host_notify",
                                    command_args=command_args)
        if not status:
            log_msg = _("Failed to notify host: {response}", log=True)[1]
            log_msg = log_msg.format(response=response)
            config.logger.warning(log_msg)
            return 0
        return response
    except Exception as e:
        log_msg = _("Failed to notify host: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        config.logger.warning(log_msg)
        return 0


def message(text, title=None, username=None, host=None, all_users=False):
    """ Put a message in front of users that are logged in.

    One of username, host or all_users says who gets it, and idled
    works out which of its subscribers that is -- it is the one that
    knows who is here. The answer says how many users were told.

    Unlike notify() this is not fire and forget: a message that nobody
    could be told is something the caller has to hear, because somebody
    typed it and is waiting to learn whether it went out.
    """
    if config.use_api:
        return 0
    idled_conn = connections.get("idled",
                                auto_auth=False,
                                auto_preauth=False,
                                handle_host_auth=False,
                                handle_user_auth=False,
                                encrypt_session=False)
    command_args = {
                'text'          : text,
                'title'         : title,
                'username'      : username,
                'host'          : host,
                'all_users'     : all_users,
                }
    status, \
    status_code, \
    response, \
    binary_data = idled_conn.send(command="message",
                                command_args=command_args)
    if not status:
        msg = _("Failed to send message: {response}")
        msg = msg.format(response=response)
        raise OTPmeException(msg)
    return response


def notify(username, event_type, data):
    """Send a notification to all idled subscribers of the given user."""
    if config.use_api:
        return
    idled_conn = None
    try:
        idled_conn = connections.get("idled",
                                     auto_auth=False,
                                     auto_preauth=False,
                                     handle_host_auth=False,
                                     handle_user_auth=False,
                                     encrypt_session=False)
        command_args = {
            'username'      : username,
            'event_type'    : event_type,
            'data'          : data,
        }
        idled_conn.send(command="notify", command_args=command_args)
    except Exception as e:
        try:
            log_msg = _("Failed to send idle notification: {error}",
                        log=True)[1]
            log_msg = log_msg.format(error=e)
            config.logger.warning(log_msg)
        except Exception:
            pass
    finally:
        pass
        #if idled_conn is not None:
        #    try:
        #        idled_conn.close()
        #    except Exception:
        #        pass
