#!/usr/bin/env python3

from datetime import datetime
from multiprocessing import Process, JoinableQueue, Manager, freeze_support
from os import system
from time import sleep

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultProcessManagerValues
from grinder.errors import (
    NmapProcessingRunError,
    NmapProcessingManagerOrganizeProcessesError,
)
from grinder.nmapconnector import NmapConnector


class NmapProcessingDefaultManagerValues:
    """
    Define default manager values
    """

    POLLING_RATE = 0.5
    EMPTY_QUEUE_POLLING_RATE = 1.0


class NmapProcessing(Process):
    """
    Create custom Nmap process. The reason to create
    custom Nmap process is that we need a mechanism
    to organize queue or process pool to work with
    it more flexible and accurate than with standard
    methods like Pool, etc. Also, custom process provides
    for us a more flexible way of queue organizing.
    """

    def __init__(
        self,
        queue: JoinableQueue,
        arguments: str,
        ports: str,
        sudo: bool,
        hosts_quantity: int,
        results_pool: dict,
    ):
        Process.__init__(self)
        self.queue = queue
        self.arguments = arguments
        self.ports = ports
        self.sudo = sudo
        self.quantity = hosts_quantity
        self.results_pool = results_pool

    @exception_handler(expected_exception=NmapProcessingRunError)
    def run(self) -> None:
        """
        Run Nmap process
        :return: None
        """

        # Note: we use 'while True' with queue checker inside to prevent
        # process dying at the beginning, because we start with empty
        # queue

        while True:
            if self.queue.empty():
                # Wait while queue will get some tasks to do
                sleep(NmapProcessingDefaultManagerValues.EMPTY_QUEUE_POLLING_RATE)
                continue
            try:
                # Poll with POLLING_RATE interval
                sleep(NmapProcessingDefaultManagerValues.POLLING_RATE)

                # Get host info from queue
                index, host = self.queue.get()
                if (index, host) == (None, None):
                    self.queue.task_done()
                    return

                host_ip = host.get("ip", "")
                host_port = host.get("port", "")
                port_postfix = "Default"

                if not self.ports and host_port:
                    port_postfix = host_port
                if self.ports:
                    port_postfix = self.ports

                print(
                    f"⭕ "
                    f"Current scan host ({index + 1}/{self.quantity}): "
                    f"{host_ip}:{port_postfix} "
                    f"(started at: {str(datetime.now().strftime('%H:%M:%S'))})"
                )

                nm = NmapConnector()
                nm.scan(
                    host=host_ip,
                    arguments=self.arguments,
                    ports=self.ports or str(host_port),
                    sudo=self.sudo,
                )

                results = nm.get_results()
                if results.get(host_ip).values():
                    self.results_pool.update({host_ip: results.get(host_ip)})
            except:
                pass
            self.queue.task_done()
            if self.queue.empty():
                return


class NmapProcessingManager:
    """
    Custom Nmap scanner processes manager.
    Here we organize a custom queue with a
    defined quantity of workers and start it on hosts.
    """

    def __init__(
        self,
        hosts: list,
        ports=DefaultProcessManagerValues.PORTS,
        sudo=DefaultProcessManagerValues.SUDO,
        arguments=DefaultProcessManagerValues.ARGUMENTS,
        workers=DefaultProcessManagerValues.WORKERS,
    ):
        freeze_support()
        self.manager = Manager()
        self.results_pool = self.manager.dict({})
        self.hosts = hosts
        self.workers = workers
        self.arguments = arguments
        self.ports = ports
        self.sudo = sudo

    @exception_handler(expected_exception=NmapProcessingManagerOrganizeProcessesError)
    def organize_processes(self) -> None:
        """
        Create process queue
        :return: None
        """
        queue = JoinableQueue()
        processes = []
        for _ in range(self.workers):
            freeze_support()
            process = NmapProcessing(
                queue,
                self.arguments,
                self.ports,
                self.sudo,
                len(self.hosts),
                self.results_pool,
            )
            process.daemon = True
            processes.append(process)
        for process in processes:
            try:
                process.start()
            except OSError:
                pass
        for index, host in enumerate(self.hosts):
            queue.put((index, host))
        for _ in range(self.workers):
            queue.put((None, None))
        queue.join()
        for process in processes:
            if process.is_alive():
                process.terminate()

    def start(self) -> None:
        """
        Start multiple workers scanning
        :return: None
        """
        self.organize_processes()

    def get_results(self) -> dict:
        """
        Return dictionary with Nmap results
        :return: Nmap results
        """
        return self.results_pool

    def get_results_count(self) -> int:
        """
        Return quantity of Nmap results
        :return: quantity of results
        """
        return len(self.results_pool)

    def __del__(self):
        """
        Fix in a case when we have finished scanning,
        but some processes are still not. In this case,
        we can lose control over the terminal or console,
        so "stty sane" command will return it to us.
        :return: None
        """
        system("stty sane")
