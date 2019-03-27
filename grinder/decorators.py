#!/usr/bin/env python3

import sys
from functools import wraps
from os import path, makedirs, system
from time import time


def exception_handler(expected_exception):
    def real_decorator(function):
        def func_wrapper(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except KeyboardInterrupt:
                print("Keyboard Interrupt Detected. Operation aborted. Bye!")
                system("stty sane")
                sys.exit(1)
            except SystemExit:
                system("stty sane")
                sys.exit(1)
            except Exception as unexp_error:
                raise expected_exception(unexp_error) from unexp_error

        return func_wrapper

    return real_decorator


def create_results_directory(directory: str = None):
    def real_decorator(function):
        def func_wrapper(*args, **kwargs):
            full_results_path = f"./{kwargs.get('dest_dir') or directory}"
            if not path.exists(full_results_path):
                makedirs(full_results_path)
            return function(*args, **kwargs)

        return func_wrapper

    return real_decorator


def create_subdirectory(subdirectory: str, rootdirectory: str = None):
    def real_decorator(function):
        def func_wrapper(*args, **kwargs):
            full_results_path = (
                f"./{kwargs.get('dest_dir') or rootdirectory}/{subdirectory}"
            )
            if not path.exists(full_results_path):
                makedirs(full_results_path)
            return function(*args, **kwargs)

        return func_wrapper

    return real_decorator


def timer(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        start = time()
        result = function(*args, **kwargs)
        end = time()
        print(f"Done in {round(end - start, 2)}s")
        return result

    return wrapper
