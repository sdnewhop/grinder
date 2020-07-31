#!/usr/bin/env python3

import sys
from functools import wraps
from os import system
from time import time, strftime, gmtime


def exception_handler(expected_exception):
    """
    Custom exception handler that wraps almost
    all functions in Grinder. This wrapper
    catches all kind of unexpected exceptions,
    provide an exception for keyboard stopping in any
    function (especially in case of multiprocessing/
    multithreading locking), and also provides
    "clean" exit with terminal input returning (again,
    in a case when you try to stop Grinder in a dirty
    way when he is in multiprocessing case)
    :param expected_exception: exception that will be processed here
    :return: wrapped function
    """
    def real_decorator(function):
        def func_wrapper(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except KeyboardInterrupt:
                system("stty sane")
                sys.exit(1)
            except SystemExit:
                system("stty sane")
                sys.exit(1)
            except Exception as unexp_error:
                raise expected_exception(unexp_error) from unexp_error

        return func_wrapper

    return real_decorator


def timer(function):
    """
    Timer that used to count runtime
    of different functions. Simple.
    :param function: wrapping function
    :return: wrapped function
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        start = time()
        result = function(*args, **kwargs)
        end = time()
        seconds = round(end - start, 2)
        print(f"Done in {seconds}s ({str(strftime('%H:%M:%S', gmtime(seconds)))})")
        return result

    return wrapper
