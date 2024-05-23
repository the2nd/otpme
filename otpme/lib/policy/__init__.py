# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import functools

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from .get_class import get_class
from .get_class import get_module
from otpme.lib import multiprocessing

processed_objects = {}

REGISTER_BEFORE = []
REGISTER_AFTER = []

modules = [
        'otpme.lib.policy.authonaction.authonaction',
        'otpme.lib.policy.autodisable.autodisable',
        'otpme.lib.policy.defaultgroups.defaultgroups',
        'otpme.lib.policy.defaultroles.defaultroles',
        'otpme.lib.policy.defaultunits.defaultunits',
        'otpme.lib.policy.forcetoken.forcetoken',
        'otpme.lib.policy.idrange.idrange',
        'otpme.lib.policy.logintimes.logintimes',
        'otpme.lib.policy.password.password',
        'otpme.lib.policy.tokenacls.tokenacls',
        'otpme.lib.policy.defaultpolicies.defaultpolicies',
        'otpme.lib.policy.objecttemplates.objecttemplates',
        ]

def register():
    """ Register modules. """
    from ..register import _register_modules
    _register_modules(modules)

def one_time_policy_run(func):
    """ Decorator to make sure a policy is ran only once for each object. """
    def wrapper(*args, **kwargs):
        #if sys.version[0] == '2':
        #    fn = func.func_name
        #if sys.version[0] == '3':
        #    fn = func.__name__
        #func_name = "%s.%s()" % (func.__module__, fn)

        global processed_objects

        already_active = False
        proc_id = multiprocessing.get_id()
        if proc_id in processed_objects:
            already_active = True

        if not already_active:
            processed_objects[proc_id] = []

        # Run function.
        result = func(*args, **kwargs)

        if not already_active:
            processed_objects.pop(proc_id)

        return result

    # Update func/method.
    functools.update_wrapper(wrapper, func)
    if not hasattr(wrapper, '__wrapped__'):
        # Python 2.7
        wrapper.__wrapped__ = func

    return wrapper
