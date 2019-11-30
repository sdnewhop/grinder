#!/usr/bin/env python3

from multiprocessing import Process, JoinableQueue, Manager
from os import system
from importlib.machinery import SourceFileLoader
from pathlib import Path

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultValues
from grinder.errors import GrinderScriptExecutorRunScriptError


class PyProcessingResults:
    """
    Collect python scripts results
    """

    RESULTS = Manager().dict({})


class PyProcessing(Process):
    """
    Create custom python script process
    """
    def __init__(self, queue: JoinableQueue):
        Process.__init__(self)
        self.queue = queue

    @staticmethod
    @exception_handler(expected_exception=GrinderScriptExecutorRunScriptError)
    def _exec_script(host_info, py_script):
        """
        Import additional script and run it

        :param host_info: information about host
        :param py_script: python script filename
        :return: data from additional script
        """
        if isinstance(py_script, str) and py_script.endswith(".py"):
            full_path = (
                Path(".")
                .joinpath(DefaultValues.CUSTOM_SCRIPTS_DIRECTORY)
                .joinpath(DefaultValues.PY_SCRIPTS_DIRECTORY)
                .joinpath(py_script)
            )
            module = SourceFileLoader("main", str(full_path)).load_module()
            return module.main(host_info)

    def run(self) -> None:
        """
        Run custom python script

        :return: None
        """
        while True:
            current_progress, host_info, py_script = self.queue.get()
            result = self._exec_script(host_info, py_script)
            PyProcessingResults.RESULTS.update({host_info.get("ip"): result})
            print(f"Host {current_progress[0]}/{current_progress[1]} ({current_progress[2]}): "
                  f"script \"{py_script}\" done for {host_info.get('ip')}:{host_info.get('port')}")
            self.queue.task_done()


class PyProcessingManager:
    def __init__(self, ip_script_mapping: dict, hosts_info: dict, workers: int = 100):
        self.ip_script_mapping = ip_script_mapping
        self.hosts_info = hosts_info
        self.workers = workers

    def organize_processes(self) -> None:
        queue = JoinableQueue()
        for _ in range(self.workers):
            process = PyProcessing(queue)
            process.daemon = True
            process.start()
        hosts_length = len(self.hosts_info)
        for index, (ip, host_info) in enumerate(self.hosts_info.items()):
            py_script = self.ip_script_mapping.get(ip)
            if not py_script:
                continue
            percentage = round((index / hosts_length) * 100, 2)
            queue.put(((index, hosts_length, f"{percentage}%"), host_info, py_script))
        queue.join()

    def start(self) -> None:
        self.organize_processes()

    @staticmethod
    def get_results() -> dict:
        return PyProcessingResults.RESULTS

    @staticmethod
    def get_results_count() -> int:
        return len(PyProcessingResults.RESULTS)

    def __del__(self):
        system("stty sane")