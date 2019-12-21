#!/usr/bin/env python3

from multiprocessing import Process, JoinableQueue, Manager
from os import system
from time import sleep
from datetime import datetime

from grinder.decorators import exception_handler
from grinder.errors import (
    NmapProcessingRunError,
    NmapProcessingManagerOrganizeProcessesError,
)
from grinder.nmapconnector import NmapConnector
from grinder.defaultvalues import DefaultProcessManagerValues


class NmapProcessingDefaultManagerValues:
    """
    Define default manager values
    """
    POLLING_RATE = 0.5
    EMPTY_QUEUE_POLLING_RATE = 1.0


class NmapProcessingResults:
    """
    This is results collector to gain
    results directly from a process
    """

    RESULTS = Manager().dict({})


class NmapProcessing(Process):
    """
    Create custom Nmap process. The reason to create
    custom Nmap process is that we need a mechanism
    to organize queue or process pool to work with
    it more flexible and accurate than with standard
    methods like Pool, etc. Also, custom process provides
    for us a more flexible way of queue organizing.
    """

    def __init__(self, queue: JoinableQueue, arguments: str, ports: str, sudo: bool, hosts_quantity: int):
        Process.__init__(self)
        self.queue = queue
        self.arguments = arguments
        self.ports = ports
        self.sudo = sudo
        self.quantity = hosts_quantity

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
                index, host = self.queue.get()
                sleep(NmapProcessingDefaultManagerValues.POLLING_RATE)

                host_ip = host.get("ip", "")
                host_port = host.get("port", "")
                port_postfix = "Default"

                if not self.ports and host_port:
                    port_postfix = host_port
                if self.ports:
                    port_postfix = self.ports

                print(
                    f"⭕ "
                    f"Current scan host ({index}/{self.quantity}): "
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
                    NmapProcessingResults.RESULTS.update({host_ip: results.get(host_ip)})
            except:
                self.queue.task_done()
            else:
                self.queue.task_done()


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
        for index, host in enumerate(self.hosts):
            queue.put((index, host))
        processes = []
        for _ in range(self.workers):
            process = NmapProcessing(queue, self.arguments, self.ports, self.sudo, len(self.hosts))
            process.daemon = True
            processes.append(process)
        for process in processes:
            process.start()
        queue.join()

    def start(self) -> None:
        """
        Start multiple workers scanning
        :return: None
        """
        self.organize_processes()

    @staticmethod
    def get_results() -> dict:
        """
        Return dictionary with Nmap results
        :return: Nmap results
        """
        return NmapProcessingResults.RESULTS

    @staticmethod
    def get_results_count() -> int:
        """
        Return quantity of Nmap results
        :return: quantity of results
        """
        return len(NmapProcessingResults.RESULTS)

    def __del__(self):
        """
        Fix in a case when we have finished scanning,
        but some processes are still not. In this case,
        we can lose control over the terminal or console,
        so "stty sane" command will return it to us.
        :return: None
        """
        system("stty sane")
