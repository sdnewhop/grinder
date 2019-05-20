#!/usr/bin/env python3
from importlib.machinery import SourceFileLoader
from pathlib import Path

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultValues
from grinder.errors import GrinderScriptExecutorRunScriptError

class PyScriptExecutor:
    def __init__(self, queries_info):
        """
        Init python script executor
        with queries file to get script names

        :param queries_info (list): list from queries file
        :return None
        """
        self.queries_info = queries_info
    
    @exception_handler(expected_exception=GrinderScriptExecutorRunScriptError)
    def run_script(self, host_info):
        """
        Import additional script and run it

        :param host_info (dict): current host information
        :return: data from additional script
        """
        script = None
        for product in self.queries_info:
            if (product.get("vendor"), product.get("product")) == (host_info.get("vendor"), host_info.get("product")):
                script = product.get("script")
        if not script:
            return
        if isinstance(script, str) and script.endswith(".py"):
            full_path = Path(".").joinpath(DefaultValues.PY_SCRIPTS_DIRECTORY).joinpath(script)
            try:
                module = SourceFileLoader("main", str(full_path)).load_module()
                return module.main(host_info)
            except:
                return