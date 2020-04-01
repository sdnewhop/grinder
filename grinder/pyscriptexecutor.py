#!/usr/bin/env python3

from multiprocessing import Process, JoinableQueue, Manager
from os import system
from importlib.machinery import SourceFileLoader
from types import ModuleType
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from time import sleep

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultValues
from grinder.errors import (
    GrinderScriptExecutorRunScriptError,
    PyScriptExecutorOrganizeProcessesError,
    PyScriptExecutorRunProcessError,
)


class PyProcessingValues:
    """
    Different values for managers and queues
    """

    POLLING_RATE = 0.5
    EMPTY_QUEUE_POLLING_RATE = 1.0


class PyProcessingResults:
    """
    Collect python scripts results
    """

    RESULTS = Manager().dict({})


class PyProcessing(Process):
    """
    Create a custom process to run python scripts as an independent worker
    """

    def __init__(self, queue: JoinableQueue, mute: bool = False):
        """
        Initialize the process worker

        :param queue: general joinable task queue
        :param mute: bool flag for running scripts in silent mode (w/o output at all)
        """
        Process.__init__(self)
        self.queue = queue
        self.mute = mute
        self.base_path = self._initialize_base_path()

    @staticmethod
    def _initialize_base_path() -> Path:
        """
        Initialize the base path to the directory with additional python scripts

        :return: path to the directory with python scripts as a pathlib object
        """
        return (
            Path(".")
            .joinpath(DefaultValues.CUSTOM_SCRIPTS_DIRECTORY)
            .joinpath(DefaultValues.PY_SCRIPTS_DIRECTORY)
        )

    @exception_handler(expected_exception=GrinderScriptExecutorRunScriptError)
    def _exec_script(self, host_info, py_script) -> any:
        """
        Import an additional script and run it

        :param host_info: host information
        :param py_script: python script filename
        :return: script execution result
        """
        if isinstance(py_script, str) and py_script.endswith(".py"):
            full_path = self.base_path.joinpath(py_script)
            py_script_wo_extension = py_script.replace(".py", "")
            loader = SourceFileLoader("main", str(full_path))
            module = ModuleType(loader.name)
            loader.exec_module(module)
            script_result = {py_script_wo_extension: module.main(host_info)}
            if not self.mute:
                return script_result
            with redirect_stderr(None), redirect_stdout(None):
                return script_result

    @exception_handler(expected_exception=PyScriptExecutorRunProcessError)
    def run(self) -> None:
        """
        Run an additional script in a separate isolated process

        :return: None
        """

        # Note: we use 'while True' with queue checker inside to prevent
        # process dying at the beginning, because we start with empty
        # queue

        while True:
            if self.queue.empty():
                # Wait while queue will get some tasks to do
                sleep(PyProcessingValues.EMPTY_QUEUE_POLLING_RATE)
                continue
            log_progress, log_host, py_script = "Error", "Unknown host", "Unknown script"
            try:
                current_progress, host_info, py_script = self.queue.get()
                ip = host_info.get("ip")
                port = host_info.get("port")

                # Poll with POLLING_RATE interval
                sleep(PyProcessingValues.POLLING_RATE)

                # Setup logging
                log_progress = f"[{current_progress[0]}/{current_progress[1]}] ({current_progress[2]})"
                log_host = f"{ip}:{port}"

                try:
                    result = self._exec_script(host_info=host_info, py_script=py_script)
                except GrinderScriptExecutorRunScriptError as unexp_script_error:
                    print(
                        f"{log_progress} -> Caught error on host {log_host}: {str(unexp_script_error)}"
                    )
                    self.queue.task_done()
                    continue
                try:
                    if ip not in PyProcessingResults.RESULTS.keys():
                        PyProcessingResults.RESULTS.update({ip: result})
                    else:
                        old_result = PyProcessingResults.RESULTS.get(ip)
                        old_result.update(result)
                        PyProcessingResults.RESULTS[ip] = old_result
                except (AttributeError, ConnectionRefusedError):
                    print(
                        f"{log_progress} -> Caught manager error on host {log_host}: simultaneous shared-dict call"
                    )
                    self.queue.task_done()
                    continue
            except Exception as script_err:
                print(f'{log_progress} -> script "{py_script}" crash for {log_host}: {str(script_err)}')
                self.queue.task_done()
            else:
                print(f'{log_progress} -> script "{py_script}" done for {log_host}')
                self.queue.task_done()


class PyProcessingManager:
    """
    Process Manager for additional scripts
    """

    def __init__(
        self,
        ip_script_mapping: dict,
        hosts_info: dict,
        workers: int = 100,
        mute: bool = False,
    ):
        """
        Initialize a process manager with a set of scripts, host information and additional flags

        :param ip_script_mapping: mapping ip addresses to run scripts
        :param hosts_info: host information list
        :param workers: number of running processes
        :param mute: bool flag for running scripts in silent mode (w/o output at all)
        """
        self.ip_script_mapping = ip_script_mapping
        self.hosts_info = hosts_info
        self.workers = workers
        self.mute = mute

    @exception_handler(expected_exception=PyScriptExecutorOrganizeProcessesError)
    def organize_processes(self) -> None:
        """
        Organization of a set of processes and dividing the execution queue between them

        :return: None
        """
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
            # In case of:
            # "py_script": "package/script.py"
            if isinstance(py_script, str):
                queue.put(((index, hosts_length, f"{percentage}%"), host_info, py_script))
            # In case of:
            # "py_script": ["package1/script1.py", "package2/script2.py", ...]
            elif isinstance(py_script, list):
                for script in py_script:
                    if not script:
                        continue
                    queue.put(((index, hosts_length, f"{percentage}%"), host_info, script))
            # In case of:
            # "py_script": {"script1": "package1/script1.py", "script2": "package2/script2.py"}
            elif isinstance(py_script, dict):
                for script_name, script_file in py_script.items():
                    if not script_file:
                        continue
                    queue.put(((index, hosts_length, f"{percentage}%"), host_info, script_file))
        queue.join()

    def start(self) -> None:
        """
        Launch process manager

        :return: None
        """
        self.organize_processes()

    @staticmethod
    def get_results() -> dict:
        """
        Return process manager results

        :return: dictionary with {ip: results} format
        """
        return PyProcessingResults.RESULTS

    @staticmethod
    def get_results_count() -> int:
        """
        Return overall quantity of results

        :return: None
        """
        return len(PyProcessingResults.RESULTS)

    def __del__(self) -> None:
        """
        Clean up everything

        :return: None
        """
        system("stty sane")
