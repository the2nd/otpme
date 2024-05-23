# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>

def example_function(arg1, arg2=False, arg3=30, arg4=None, arg5=None):
    """
    Example OTPme function docstring.

    The first line is a short summary of the function with a tailing dot
    followed by a blank line. The following lines are the detailed description
    of what the function does. You can use reStructuredText formatting. There
    are no sections. But you can use different keywords (which start with a '@')
    to define arguments, exceptions, return values etc. and their data type. The
    debug.decorator() can be used to do some basic runtime type checking based
    on the docstring definitions.

    Even we dont need or want type checking in python, because of Duck Typing:
        https://en.wikipedia.org/wiki/Duck_typing

    It is still useful while debugging. For python3 there is support for type
    hints:

    https://docs.python.org/3/library/typing.html

    But as we are still forced to python2 because of different third party
    modules we use in OTPme, the docstring variant is chosen. There indeed is
    a python2 compatible comments based syntax for type hints. But it seems
    to be rather hard to parse them with a decorator to do runtime type
    checking.

    @arg:arg1:str First mandatory argument.
    @arg:arg2:bool Second mandatory argument.
    @oarg:arg3:int First optional argument.
    @oarg:arg4:list
        Argument descriptions may span multiple lines and you can use
        reStructuredText formatting.
            Valid list values are:
                - entry1
                - entry2
                - entry3
    @oarg:arg5:class
        The provided class must support the xxx() method...
    @yields:int The next xxx.
    @note: Do not do ....
    @raises:Exception If anything fails.
    @raises:TypeEror If any arg with wrong type is passed.
    @returns:str Sites in a text table.

    @example:
        result = example_function(arg1="mytext", arg2=50)

    @todo:
        * implement stuff a
        * implement stuff b

    """
    pass
