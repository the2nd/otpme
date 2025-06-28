# Copyright (C) 2014 the2nd <the2nd@otpme.org>

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.cache']

modules = [
        'otpme.lib.index.mysql',
        'otpme.lib.index.sqlite3',
        'otpme.lib.index.postgres',
        ]

def register(**kwargs):
    """ Register modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules, **kwargs)

def do_index_backup():
    from otpme.lib import backend
    from otpme.lib.messages import error_message
    result = backend.search(attribute="uuid",
                            value="*",
                            return_type="oid")
    full_index_data = {}
    for x_oid in result:
        msg = "Processing %s" % x_oid
        error_message(msg, color=False)
        try:
            index_data = backend.index_dump(x_oid)
        except Exception as e:
            msg = "Failed to backup index object: %s: %s" % (x_oid, e)
            error_message(msg)
            continue
        full_index_data[x_oid.full_oid] = index_data
    return full_index_data

def do_index_restore(full_index_data):
    from otpme.lib import backend
    from otpme.lib.messages import error_message
    backend.begin_transaction("index_restore")
    for x_oid in full_index_data:
        msg = "Processing %s" % x_oid
        error_message(msg, color=False)
        x_index_data = full_index_data[x_oid]
        backend.index_restore(x_index_data)
    backend.end_transaction()
