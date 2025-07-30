# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
#import types
import decimal
import inspect
import threading
import functools
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib.messages import message
#from otpme.lib.messages import error_message

from otpme.lib.exceptions import *

stacks = {}
trace_methods = []
highest_counter = 0
longest_timings = {}
debug_timings = False
slowness_method = None
debug_this_call = False
adding_decorators = False
trace_method_calls = False
method_tracing_start = None

BLACKLIST_FUNCTIONS = [
                    'otpme.lib.multiprocessing.job_type',
                    'otpme.lib.log',
                    ]
BLACKLIST_METHODS = [
                    #'otpme.lib.otpme_config.OTPmeConfig.debug_level',
                    'otpme.lib.log.ContextFilter.filter',
                    ]

#import objgraph
#objgraph.show_growth()  # Erster Aufruf - Baseline setzen
# <your code here>
#objgraph.show_growth()  # Zweiter Aufruf - zeigt was gewachsen ist

#import tracemalloc
#tracemalloc.start()
# <your code here>
#current, peak = tracemalloc.get_traced_memory()
#print(f"Current memory usage: {current / 1024 / 1024:.1f} MB")
#print(f"Peak memory usage: {peak / 1024 / 1024:.1f} MB")

## Top 10 memory consumers anzeigen
#snapshot = tracemalloc.take_snapshot()
#top_stats = snapshot.statistics('lineno')
#for stat in top_stats[:10]:
#    print(stat)

start_times = {}
def start_timing():
    global start_times
    trace_start = 1
    caller = inspect.stack()[trace_start][3]
    if caller == "debug_wrapper":
        trace_start += 1
        caller = inspect.stack()[trace_start][3]
    #print("START TIMING: %s" % caller)
    start_times[caller] = time.time()

def end_timing(warn_seconds=0.1, quiet=False):
    global start_times
    # Get calling function name.
    trace_start = 1
    caller = inspect.stack()[trace_start][3]
    if caller == "debug_wrapper":
        trace_start += 1
        caller = inspect.stack()[trace_start][3]
    end_time = time.time()
    try:
        age = end_time- start_times[caller]
    except:
        return
    if age < warn_seconds:
        return
    if not quiet:
        msg = "TOOK: %s: %.2f" % (caller, age)
        print(msg)
    start_times.pop(caller)
    return age

def trace(ignore_callers=[], trace_len=10):
    """ Use inspect module to trace callers. """
    trace_start = 2
    caller = inspect.stack()[trace_start][3]
    if caller == "debug_wrapper":
        trace_start += 1
        caller = inspect.stack()[trace_start][3]
    if caller in ignore_callers:
        return
    stack_len = len(inspect.stack())
    if stack_len >= trace_len:
        stack_len = trace_len
    callers = []
    for i in range(trace_start, stack_len):
        caller_file = inspect.stack()[i][1]
        caller_line = inspect.stack()[i][2]
        caller_name = inspect.stack()[i][3]

        msg = ("Called from: %s -> %s:%s"
                % (caller_name,
                caller_file,
                caller_line))
        print(msg)
        callers.append(msg)
    return callers

def print_timing_result(sort_by="time", print_status=False):
    """ Print timing results. """
    from otpme.lib import config
    result = {}
    timings = get_timing_result(sort_by=sort_by, print_status=print_status)
    for thread_id in timings:
        for x in timings[thread_id]:
            method = x[0]
            counts = x[1]
            timer_sum = x[2]

            if thread_id not in result:
                result[thread_id] = {}
                result[thread_id]['lines'] = []

            if sort_by == "time":
                if float(timer_sum) < config.debug_timing_limit:
                    continue
            else:
                if counts < config.debug_counter_limit:
                    continue
            msg = ("DEBUG: %s calls of %s took %s seconds"
                    % (counts, method, "%.2f" % timer_sum))
            result[thread_id]['lines'].append(msg)

    if not result:
        return

    _result = ""
    for thread_id in sorted(result, reverse=True):
        lines = result[thread_id]['lines']
        if not lines:
            continue
        if _result:
            _result += "\n"
        _result += "Thread (%s):\n" % thread_id
        _result += "\n".join(lines)
        _result += "\n"

    message("")
    message("METHOD TIMINGS")
    message("--------------")
    message(_result)
    message("--------------")

def get_timing_result(sort_by="time", print_status=False):
    """ Calculate method/function timings and put them in a sorted list. """
    global stacks
    result = {}
    sort_dict = {}
    msg = (_("Calculating timing results"))
    decimal.getcontext().prec = 256
    decimal.getcontext().rounding = decimal.ROUND_DOWN

    traced_methods = {}
    for thread_id in stacks:
        progress_counter = 0
        counts = stacks[thread_id]['counts']
        timing = stacks[thread_id]['timing']
        traceback = list(set(stacks[thread_id]['traceback']))
        traceback_len = len(traceback)
        for method in reversed(traceback):
            try:
                method_counts = traced_methods[thread_id][method]['counts']
                method_time_sum = traced_methods[thread_id][method]['timer_sum']
            except:
                if thread_id not in traced_methods:
                    traced_methods[thread_id] = {}
                traced_methods[thread_id][method] = {}
                method_counts = 0
                method_time_sum = decimal.Decimal(0)
            progress_counter += 1
            timer_sum = decimal.Decimal(0)
            method_counts += counts[method]
            for x in timing[method]:
                start = x[0]
                end = x[1]
                start = decimal.Decimal(start)
                end = decimal.Decimal(end)
                timer_sum += end - start
            method_time_sum += timer_sum
            traced_methods[thread_id][method]['counts'] = method_counts
            traced_methods[thread_id][method]['timer_sum'] = method_time_sum
            if print_status:
                full_msg = "%s (%s/%s): %s" % (msg, progress_counter, traceback_len, method)
                message(full_msg, sameline=True, newline=False)

    for thread_id in traced_methods:
        for method in traced_methods[thread_id]:
            counts = traced_methods[thread_id][method]['counts']
            timer_sum = traced_methods[thread_id][method]['timer_sum']
            if sort_by == "counts":
                dict_key = (counts, thread_id, method)
            else:
                dict_key = (timer_sum, thread_id, method)
            if thread_id not in sort_dict:
                sort_dict[thread_id] = {}
            sort_dict[thread_id][dict_key] = (method, counts, timer_sum)

    for thread_id in sort_dict:
        for dict_key in sorted(sort_dict[thread_id], reverse=True):
            method = sort_dict[thread_id][dict_key][0]
            counts = sort_dict[thread_id][dict_key][1]
            timer_sum = sort_dict[thread_id][dict_key][2]
            if thread_id not in result:
                result[thread_id] = []
            result[thread_id].append((method, counts, timer_sum))
    message("", sameline=True, newline=False)
    # Clear global dicts.
    stacks.clear()
    return result

def decorator(func, _otpme_class_debug=False):
    """
    Class method and function decorator to measure
    method/function runtimes.
    """
    from otpme.lib import config
    global stacks
    global adding_decorators
    try:
        debug_func_start_regex
    except:
        debug_func_start_regex = []
        for f_regex in config.debug_func_start:
            f_re = re.compile(f_regex)
            debug_func_start_regex.append(f_re)

    def debug_wrapper(*args, **kwargs):
        global debug_timings
        global debug_this_call
        global trace_method_calls
        global method_tracing_start
        try:
            fn = func.__name__
        except:
            fn = func.func_name
        if _otpme_class_debug:
            func_type = "method"
            func_name = ("%s.%s()" % (func.__module__, func.__qualname__))
        else:
            func_type = "function"
            func_name = "%s.%s()" % (func.__module__, fn)

        if debug_timings:
            if method_tracing_start is not None:
                debug_this_call = True
            if not debug_this_call:
                if debug_func_start_regex:
                    if func_name in trace_methods:
                        debug_this_call = True
                    else:
                        for f_re in debug_func_start_regex:
                            if not f_re.match(func_name):
                                continue
                            debug_this_call = True
                            trace_methods.append(func_name)
                            if method_tracing_start is None:
                                method_tracing_start = func
                            break
                else:
                    debug_this_call = True

        def call_original_method(func, *args, **kwargs):
            if debug_this_call:
                if trace_method_calls:
                    sameline = True
                    if last_caller != func_name:
                        message("")
                    msg = (_("DEBUG: Calling %s: %s (%s)")
                        % (func_type, func_name, call_counter))
                    message(msg, sameline=sameline)
            # Run function/method.
            result = func(*args, **kwargs)
            if debug_this_call:
                if trace_method_calls:
                    msg = (_("DEBUG: Finished %s: %s (%s)")
                        % (func_type, func_name, call_counter))
                    message(msg, sameline=sameline)
            return result

        if config.debug_users:
            if config.debug_user:
                if config.debug_user not in config.debug_users:
                    debug_this_call = False
            else:
                debug_this_call = False
        if config.debug_daemons:
            if config.daemon_name:
                if config.daemon_name not in config.debug_daemons:
                    debug_this_call = False
            else:
                debug_this_call = False

        if config.debug_func_names:
            debug_this_call = True

        if trace_method_calls:
            debug_this_call = True

        # No debugging while adding decorators.
        if adding_decorators:
            debug_this_call = False

        if not debug_this_call:
            result = call_original_method(func, *args, **kwargs)
            return result

        debug_wrapper.last_caller = None
        debug_wrapper.call_counter = 0
        try:
            last_caller = debug_wrapper.last_caller
        except:
            last_caller = None
        try:
            call_counter = debug_wrapper.call_counter
        except:
            call_counter = 0

        if last_caller == func_name:
            call_counter += 1
        else:
            call_counter = 1
        debug_wrapper.last_caller = func_name
        debug_wrapper.call_counter = call_counter

        if debug_timings:
            _id = threading.currentThread().ident
            _name = threading.currentThread().getName()
            thread_id = "%s (%s)" % (_name, _id)
            method = func_name
            if thread_id not in stacks:
                stacks[thread_id] = {}
            try:
                counts = stacks[thread_id]['counts']
            except:
                counts = {}
                stacks[thread_id]['counts'] = counts
            try:
                timing = stacks[thread_id]['timing']
            except:
                timing = {}
                stacks[thread_id]['timing'] = timing
            try:
                traceback = stacks[thread_id]['traceback']
            except:
                traceback = []
                stacks[thread_id]['traceback'] = traceback
            traceback.append(method)
            if method not in counts:
                counts[method] = 1
            else:
                counts[method] += 1

            time_id_counter = float("%.20f" % time.time())
            start_time = time_id_counter
            if func_name not in timing:
                timing[func_name] = []

        # Run function/method.
        result = call_original_method(func, *args, **kwargs)

        if debug_timings:
            end_time = float("%.20f" % time.time())
            timer = (start_time, end_time)
            timing[method].append(timer)

            if config.print_method_slowness:
                global longest_timings
                global slowness_method
                global highest_counter
                try:
                    counter = longest_timings[method]['counter']
                    slowest = longest_timings[method]['slowest']
                    fastest = longest_timings[method]['fastest']
                except:
                    longest_timings[method] = {}
                    slowest = 0.0
                    fastest = 0.0
                    counter = 0
                age = float(end_time - start_time)
                if age < fastest:
                    fastest = age
                if age > slowest:
                    counter += 1
                    slowest = age
                longest_timings[method]['fastest'] = fastest
                longest_timings[method]['slowest'] = slowest
                longest_timings[method]['counter'] = counter
                if counter > highest_counter:
                    slowness_method = method
                    highest_counter = counter
                    method_slowness = slowest - fastest
                    msg = ("Method %s gets slower (%s)."
                        % (slowness_method, method_slowness))
                    print(msg)

            if config.print_timing_warnings:
                age = float(end_time - start_time)
                if age > config.debug_timing_limit:
                    if _otpme_class_debug:
                        msg = (_("WARNING: Method %s took %s seconds")
                                % (method, "%.2f" % age))
                    else:
                        msg = (_("WARNING: Function %s took %s seconds")
                                % (method, "%.2f" % age))
                    print(msg)

        if method_tracing_start is func:
            method_tracing_start = None

        return result

    # Update func/method.
    functools.update_wrapper(debug_wrapper, func)
    if not hasattr(debug_wrapper, '__wrapped__'):
        # Python 2.7
        debug_wrapper.__wrapped__ = func

    return debug_wrapper

#class OTPmeDebug(type):
#    """ Meta class to add a debug decorator to all class methods. """
#    def __new__(cls, name, bases, attrs):
#        for attr_name, attr_value in attrs.iteritems():
#            if isinstance(attr_value, types.FunctionType):
#                attrs[attr_name] = decorator(attr_value, _otpme_class_debug=True)
#        return super(OTPmeDebug, cls).__new__(cls, name, bases, attrs)
#
#   #def decorator(cls, func):
#   #   def wrapper(*args, **kwargs):
#   #      print("before",func.func_name)
#   #      result = func(*args, **kwargs)
#   #      print("after",func.func_name)
#   #      return result
#   #   return wrapper
#
#def add_decorator(module_items, module_name):
#    """
#    Add debug decorator if the method/function module matches module name.
#    """
#    for k,v in module_items.items():
#        if isinstance(v, types.FunctionType):
#            if v.__module__ != module_name:
#                continue
#            #print(module_name, v.__name__, k)
#            module_items[k] = decorator(v)

def add_debug_decorators():
    """ Add debug decorators to functions and classes. """
    global adding_decorators
    adding_decorators = True
    try:
        if os.environ['OTPME_DEBUG_NEED_DECORATOR'] == "True":
            from otpme.lib import preload
            msg = ("NOTICE: Make sure %s is up-to-date to catch all modules."
                    % preload.__file__.replace(".pyc", ".py"))
            message(msg)
            for x in preload.preload_modules:
                if x == __name__:
                    continue
                msg = "Adding debug decorators: %s" % x
                module = importlib.import_module(x)
                message(msg)
                add_decorator(module)
    finally:
        adding_decorators = False

def add_decorator(module):
    """
    Add debug decorator if the method/function module matches module name.
    """
    from otpme.lib import config
    for x in dir(module):
        module_name = module.__name__
        f = getattr(module, x)
        if isinstance(f, type):
            if f.__module__ != module_name:
                continue
        #if isinstance(f, type):
        if f.__class__.__name__ == "type":
            for y in dir(f):
                try:
                    m = getattr(f, y)
                    m_module = m.__module__
                except:
                    continue
                if m_module != module_name:
                    continue
                #class_method = False
                method_path = "%s.%s.%s" % (m.__module__, x, y)
                add_method = True
                for x_path in BLACKLIST_METHODS:
                    if x_path in method_path:
                        add_method = False
                        break
                if config.debug_func_names:
                    add_method = False
                    for f_regex in config.debug_func_names:
                        f_re = re.compile(f_regex)
                        if f_re.match(method_path):
                            add_method = True
                            break
                if not add_method:
                    continue
                ##if m.__self__ == f:
                ##    class_method = True
                #else:
                #    msg = ("Unable to get method type: %s" % method_path)
                #    raise OTPmeException(msg)
                ## FIXME: How to add decorator to class method with @classmethod??
                ##        "TypeError: unbound method xy() must be called with..."
                #if class_method:
                #    msg = ("Skipping @classmethod: %s" % method_path)
                #    error_message(msg)
                #    continue
                m_decorator = decorator(m, _otpme_class_debug=True)
                setattr(f, y, m_decorator)

        #elif isinstance(f, types.FunctionType):
        if f.__class__.__name__ == "function":
            add_method = True
            method_path = "%s.%s" % (f.__module__, f.__name__)
            if config.debug_func_names:
                add_method = False
                for f_regex in config.debug_func_names:
                    f_re = re.compile(f_regex)
                    if f_re.match(method_path):
                        add_method = True
                        break
            for x_path in BLACKLIST_FUNCTIONS:
                if x_path in method_path:
                    add_method = False
                    break
            if not add_method:
                continue
            f_decorator = decorator(f)
            setattr(module, x, f_decorator)

def show_objects_with_reference():
    import gc
    import tracemalloc
    from collections import defaultdict

    # tracemalloc muss vor der Objekterstellung gestartet werden
    tracemalloc.start()

    counter = defaultdict(int)
    origins = defaultdict(list)

    for obj in gc.get_objects():
        obj_type = type(obj).__name__
        counter[obj_type] += 1

        # Traceback für dieses Objekt finden
        try:
            tb = tracemalloc.get_object_traceback(obj)
            if tb:
                # Nur die erste (relevanteste) Frame nehmen
                frame = tb[0]
                origin = f"{frame.filename}:{frame.lineno}"
                origins[obj_type].append(origin)
        except:
            pass

    print("\n=== Objects with Origins ===")
    for obj_type, count in sorted(counter.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"\n{obj_type}: {count} instances")
        if obj_type in origins:
            # Die häufigsten Ursprungsorte zeigen
            origin_counter = defaultdict(int)
            for origin in origins[obj_type]:
                origin_counter[origin] += 1

            for origin, origin_count in sorted(origin_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {origin_count:3d}x from {origin}")

def show_object_sizes():
    from pympler import muppy, summary
    all_objects = muppy.get_objects()
    sum1 = summary.summarize(all_objects)
    summary.print_(sum1)
