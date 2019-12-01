#!/usr/bin/env python3

from multiprocessing import Process, JoinableQueue, Manager
from os import system
from importlib.machinery import SourceFileLoader
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr

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
    def __init__(self, queue: JoinableQueue, mute: bool = False):
        Process.__init__(self)
        self.queue = queue
        self.mute = mute

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

    def _exec_mute_switcher(self, host_info: dict, py_script: str) -> any:
        """
        Check do we need stdout/stderr or not

        :return: result of script execution
        """
        if not self.mute:
            return self._exec_script(host_info, py_script)
        with redirect_stderr(None), redirect_stdout(None):
            return self._exec_script(host_info, py_script)

    def run(self) -> None:
        """
        Run custom python script

        :return: None
        """
        while True:
            current_progress, host_info, py_script = self.queue.get()
            try:
                result = self._exec_mute_switcher(host_info=host_info, py_script=py_script)
            except GrinderScriptExecutorRunScriptError as unexp_script_error:
                print(f"Caught error on host {host_info.get('ip')}:{host_info.get('port')}: {str(unexp_script_error)}")
                self.queue.task_done()
                continue
            PyProcessingResults.RESULTS.update({host_info.get("ip"): result})
            print(f"Host {current_progress[0]}/{current_progress[1]} ({current_progress[2]}): "
                  f"script \"{py_script}\" done for {host_info.get('ip')}:{host_info.get('port')}")
            self.queue.task_done()


class PyProcessingManager:
    def __init__(self, ip_script_mapping: dict, hosts_info: dict, workers: int = 100, mute: bool = False):
        self.ip_script_mapping = ip_script_mapping
        self.hosts_info = hosts_info
        self.workers = workers
        self.mute = mute

    def organize_processes(self) -> None:
        queue = JoinableQueue()
        for _ in range(self.workers):
            process = PyProcessing(queue, mute=self.mute)
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