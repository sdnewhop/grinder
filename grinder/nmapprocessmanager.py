#!/usr/bin/python3

from os import system
from multiprocessing import Process, JoinableQueue, Manager

from grinder.nmapconnector import NmapConnector
from grinder.errors import NmapProcessingRunError, NmapProcessingManagerOrganizeProcessesError
from grinder.decorators import exception_handler


class NmapProcessingResults():
    RESULTS = Manager().dict({})

class NmapProcessing(Process):
    def __init__(self, queue: JoinableQueue, arguments: str, ports: str, sudo: bool):
        Process.__init__(self)
        self.queue = queue
        self.arguments = arguments
        self.ports = ports
        self.sudo = sudo

    @exception_handler(expected_exception=NmapProcessingRunError)
    def run(self):
        while True:
            host = self.queue.get()
            nm = NmapConnector()
            nm.scan(host=host, arguments=self.arguments, ports=self.ports, sudo=self.sudo)
            results = nm.get_results()
            print(f'Current scan host: {host}')
            if results.get(host).values():
                NmapProcessingResults.RESULTS.update({host: results.get(host)})
            self.queue.task_done()

class NmapProcessingManager():
    def __init__(self, hosts: list, ports=None, sudo=False, arguments='-Pn -A', workers=5):
        self.hosts = hosts
        self.workers = workers
        self.arguments = arguments
        self.ports = ports
        self.sudo = sudo

    @exception_handler(expected_exception=NmapProcessingManagerOrganizeProcessesError)
    def organize_processes(self):
        queue = JoinableQueue()
        for _ in range(self.workers):
            process = NmapProcessing(queue, self.arguments, self.ports, self.sudo)
            process.daemon = True
            process.start()
        for host in self.hosts:
            queue.put(host)
        queue.join()

    def start(self):
        self.organize_processes()
    
    def get_results(self):
        return NmapProcessingResults.RESULTS
    
    def get_results_count(self):
        return len(NmapProcessingResults.RESULTS)

    def __del__(self):
        system('stty sane')
        