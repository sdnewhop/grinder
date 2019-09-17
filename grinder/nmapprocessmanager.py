#!/usr/bin/env python3

from multiprocessing import Process, JoinableQueue, Manager
from os import system
from datetime import datetime

from grinder.decorators import exception_handler
from grinder.errors import (
    NmapProcessingRunError,
    NmapProcessingManagerOrganizeProcessesError,
)
from grinder.nmapconnector import NmapConnector
from grinder.defaultvalues import DefaultProcessManagerValues


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

    def __init__(self, queue: JoinableQueue, arguments: str, ports: str, sudo: bool):
        Process.__init__(self)
        self.queue = queue
        self.arguments = arguments
        self.ports = ports
        self.sudo = sudo

    @exception_handler(expected_exception=NmapProcessingRunError)
    def run(self) -> None:
        """
        Run Nmap process
        :return: None
        """
        while True:
            index, hosts_quantity, host = self.queue.get()
            host_ip = host.get("ip")
            host_port = str(host.get("port"))

            port_postfix = "Default"
            if not self.ports and host_port:
                port_postfix = host_port
            if self.ports:
                port_postfix = str(self.ports)
            current_time = datetime.now().strftime("%H:%M:%S")
            print(
                f"⭕ Current scan host ({index}/{hosts_quantity}): {host_ip}:{port_postfix} (started at: {str(current_time)})"
            )
            nm = NmapConnector()
            nm.scan(
                host=host_ip,
                arguments=self.arguments,
                ports=(self.ports or host_port),
                sudo=self.sudo,
            )
            results = nm.get_results()
            if not results.get(host_ip):
                self.queue.task_done()
                return
            if results.get(host_ip).values():
                NmapProcessingResults.RESULTS.update({host_ip: results.get(host_ip)})
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
        for _ in range(self.workers):
            process = NmapProcessing(queue, self.arguments, self.ports, self.sudo)
            process.daemon = True
            process.start()
        hosts_quantity = len(self.hosts)
        for index, host in enumerate(self.hosts):
            queue.put((index, hosts_quantity, host))
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
