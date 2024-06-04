# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import glob
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib.exceptions import *

register_done = False
registered_modules = []

modules = [
	#'otpme.lib.classes.data_objects.failed_pass',
	#'otpme.lib.classes.data_objects.last_assigned_id',
	#'otpme.lib.classes.data_objects.revoked_signature',
	#'otpme.lib.classes.data_objects.token_counter',
	#'otpme.lib.classes.data_objects.used_hash',
	#'otpme.lib.classes.data_objects.used_otp',
	#'otpme.lib.classes.data_objects.used_sotp',
	#'otpme.lib.classes.data_objects.rsa_key',
	#'otpme.lib.classes.data_objects.cert',
	#'otpme.lib.classes.accessgroup',
	#'otpme.lib.classes.ca',
	#'otpme.lib.classes.client',
	#'otpme.lib.classes.dictionary',
	#'otpme.lib.classes.group',
	#'otpme.lib.classes.host',
	#'otpme.lib.classes.node',
	#'otpme.lib.classes.otpme_object',
	#'otpme.lib.classes.policy',
	#'otpme.lib.classes.realm',
	#'otpme.lib.classes.resolver',
	#'otpme.lib.classes.role',
	#'otpme.lib.classes.script',
	#'otpme.lib.classes.session',
	#'otpme.lib.classes.site',
	#'otpme.lib.classes.token',
	#'otpme.lib.classes.unit',
	#'otpme.lib.classes.user',
	#'otpme.lib.cli.accessgroup',
	#'otpme.lib.cli.ca',
	#'otpme.lib.cli.client',
	#'otpme.lib.cli.dictionary',
	#'otpme.lib.cli.group',
	#'otpme.lib.cli.host',
	#'otpme.lib.cli.policy',
	#'otpme.lib.cli.realm',
	#'otpme.lib.cli.resolver',
	#'otpme.lib.cli.role',
	#'otpme.lib.cli.script',
	#'otpme.lib.cli.site',
	#'otpme.lib.cli.token',
	#'otpme.lib.cli.unit',
	#'otpme.lib.cli.user',
	'otpme.lib.cli',
	'otpme.lib.classes',
    'otpme.lib.index',
	'otpme.lib.token',
	'otpme.lib.policy',
	'otpme.lib.resolver',
	'otpme.lib.encoding',
	'otpme.lib.encryption',
	'otpme.lib.compression',
	'otpme.lib.connections',
	'otpme.lib.extensions.ldif_handler',
	'otpme.lib.extensions',
	'otpme.lib.filetools',
	'otpme.lib.ldap.schema',
	'otpme.lib.ldap.server',
	'otpme.lib.multiprocessing',
	'otpme.lib.protocols',
	'otpme.lib.protocols.otpme_server',
	'otpme.lib.protocols.otpme_client',
	'otpme.lib.smartcard',
	'otpme.lib.daemon',
	'otpme.lib.cache',
	'otpme.lib.host',
	'otpme.lib.sotp',
	'otpme.lib.classes.data_objects',
    ]

def load_mod_files():
    """ Return modules in register order. """
    from otpme.lib import config
    register_dir = os.path.join(config.otpme_lib_dir, "register")
    mod_files = glob.glob("%s/*" % register_dir)
    module_list = []
    for x in mod_files:
        if x.endswith(".py"):
            continue
        if x.endswith(".pyc"):
            continue
        if os.path.isdir(x):
            continue
        try:
            fd = open(x, "r")
            mod_name = fd.read().replace("\n", "")
        except Exception as e:
            msg = "Failed to read register file: %s: %s" % (x, e)
            raise OTPmeException(msg)
        if mod_name in module_list:
            msg = "Orphan module registration file: %s (%s)" % (x, mod_name)
            raise OTPmeException(msg)
        module_list.append(mod_name)
    module_list = list(set(module_list))
    return module_list

def get_mod_deps(mod):
    x_module = importlib.import_module(mod)
    REGISTER_BEFORE = "REGISTER_BEFORE"
    REGISTER_AFTER = "REGISTER_AFTER"
    try:
        before = getattr(x_module, REGISTER_BEFORE)
    except:
        msg = "Missing %s in module: %s" % (REGISTER_BEFORE, mod)
        raise OTPmeException(msg)
    try:
        after = getattr(x_module, REGISTER_AFTER)
    except:
        msg = "Missing %s in module: %s" % (REGISTER_AFTER, mod)
        raise OTPmeException(msg)
    return before, after

def get_modules(_modules):
    """ Return all modules in register order. """
    module_list = list(modules)
    module_list += list(_modules)
    ordered_mods = sort_modules(module_list)
    return ordered_mods

def get_dep_tree(module_list):
    """ Get modules dependency tree. """
    order_data = {}
    module_list = set(module_list)
    for mod_name in module_list:
        before, after = get_mod_deps(mod_name)
        order_data[mod_name] = {}
        order_data[mod_name]['before'] = before
        order_data[mod_name]['after'] = after
        before_order_data = get_dep_tree(before)
        for x in before_order_data:
            order_data[x] = before_order_data[x]
        after_order_data = get_dep_tree(after)
        for x in after_order_data:
            order_data[x] = after_order_data[x]
    return order_data

def sort_modules(module_list):
    """ Return modules in register order. """
    from otpme.lib import stuff
    module_list = set(module_list)
    order_data = get_dep_tree(module_list)
    ordered_mods = stuff.order_data_by_deps(order_data)
    return ordered_mods

def list_token_types():
    """ Return list with all installed token types. """
    from otpme.lib import config
    tokens = []
    for i in os.listdir(config.token_dir):
        t_dir = os.path.join(config.token_dir, i)
        t_file = os.path.join(t_dir, "%s.py" % i)
        if os.path.isfile(t_file):
            tokens.append(i)
    return tokens

def list_policy_types():
    """ Return list with all supported policy types. """
    from otpme.lib import config
    policies = []
    for i in os.listdir(config.policy_dir):
        p_dir = os.path.join(config.policy_dir, i)
        p_file = os.path.join(p_dir, "%s.py" % i)
        if os.path.isfile(p_file):
            policies.append(i)
    return policies

def list_resolver_types():
    """ Return list with all supported resolver types. """
    from otpme.lib import config
    resolver = []
    for i in os.listdir(config.resolver_dir):
        p_dir = os.path.join(config.resolver_dir, i)
        p_file = os.path.join(p_dir, "%s.py" % i)
        if os.path.isfile(p_file):
            resolver.append(i)
    return resolver

def remember_module(module):
    """ Register module. """
    global registered_modules
    if module in registered_modules:
        return
    registered_modules.append(module)

def register_module(mod, ignore_deps=False):
    if not ignore_deps:
        after = get_mod_deps(mod)[1]
        for x in after:
            register_module(x)
    _register_module(mod)

def _register_module(mod):
    """ Register module. """
    from otpme.lib import config
    if mod in registered_modules:
        return
    if config.debug_level() > 1:
        msg = "Registering module: %s" % mod
        try:
            logger = config.logger
            logger.debug(msg)
        except:
            print(msg)
    #register_str = "from %s import register;register()" % mod
    #code = compile(register_str, '<string>', 'exec')
    #exec code
    x_module = importlib.import_module(mod)
    remember_module(x_module.__name__)
    try:
        x_method = getattr(x_module, "register")
    except Exception as e:
        msg = "Unable to register module: %s: %s" % (mod, e)
        raise ImportError(msg)
    x_method()

def _register_modules(mod_list, ignore_deps=False):
    """ Register given modules. """
    if not ignore_deps:
        mod_list = sort_modules(mod_list)
    for x in mod_list:
        _register_module(x)

def register_modules():
    """ Register modules. """
    from otpme.lib import cache
    from otpme.lib import config
    global register_done
    if register_done:
        return
    # Register modules from directory.
    mod_list = load_mod_files()
    mods = get_modules(mod_list)
    for x in mods:
        _register_module(x)
    ## Register child class modules.
    #register_token_modules()
    #register_policy_modules()
    #register_resolver_modules()
    # Handle post object registration stuff.
    config.handle_post_object_registration()
    # Handle post base object registration stuff.
    config.handle_post_base_object_registration()
    # Remember register status.
    register_done = True
    # Init cache.
    cache.init()

#def register_token_modules():
#    """ Register token modules. """
#    from otpme.lib import token as _token
#    token_types = list_token_types()
#    for x in sorted(token_types):
#        x_module = _token.get_module(x)
#        if x_module.__name__ in registered_modules:
#            return
#        remember_module(x_module.__name__)
#        try:
#            x_method = getattr(x_module, "register")
#        except:
#            continue
#        msg = "Registering token module: %s" % x
#        logger.debug(msg)
#        x_method()
#
#def register_policy_modules():
#    """ Register policy modules. """
#    from otpme.lib import policy as _policy
#    policy_types = list_policy_types()
#    for x in sorted(policy_types):
#        x_module = _policy.get_module(x)
#        if x_module.__name__ in registered_modules:
#            return
#        remember_module(x_module.__name__)
#        try:
#            x_method = getattr(x_module, "register")
#        except:
#            continue
#        msg = "Registering policy module: %s" % x
#        logger.debug(msg)
#        x_method()
#
#def register_resolver_modules():
#    """ Register resolver modules. """
#    from otpme.lib import resolver as _resolver
#    resolver_types = list_resolver_types()
#    for x in sorted(resolver_types):
#        x_module = _resolver.get_module(x)
#        if x_module.__name__ in registered_modules:
#            return
#        remember_module(x_module.__name__)
#        try:
#            x_method = getattr(x_module, "register")
#        except:
#            continue
#        msg = "Registering resolver module: %s" % x
#        logger.debug(msg)
#        x_method()
