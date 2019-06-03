#!/usr/bin/env python3
from importlib.machinery import SourceFileLoader
from pathlib import Path

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultValues
from grinder.errors import GrinderScriptExecutorRunScriptError


class PyScriptExecutor:
    @staticmethod
    @exception_handler(expected_exception=GrinderScriptExecutorRunScriptError)
    def run_script(host_info, py_script):
        """
        Import additional script and run it

        :param host_info (dict): information about host
        :param py_script (str): python script filename
        :return: data from additional script
        """
        if isinstance(py_script, str) and py_script.endswith(".py"):
            full_path = (
                Path(".").joinpath(DefaultValues.CUSTOM_SCRIPTS_DIRECTORY).joinpath(DefaultValues.PY_SCRIPTS_DIRECTORY).joinpath(py_script)
            )
            try:
                module = SourceFileLoader("main", str(full_path)).load_module()
                return module.main(host_info)
            except:
                return
