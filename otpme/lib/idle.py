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
