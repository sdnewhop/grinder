#!/usr/bin/env python3

import sys
from functools import wraps
from os import path, makedirs, system
from time import time, strftime, gmtime


def exception_handler(expected_exception):
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
    @wraps(function)
    def wrapper(*args, **kwargs):
        start = time()
        result = function(*args, **kwargs)
        end = time()
        seconds = round(end - start, 2)
        print(f"Done in {seconds}s ({str(strftime('%M:%S', gmtime(seconds)))})")
        return result

    return wrapper
