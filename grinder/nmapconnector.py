#!/usr/bin/env python3

from nmap import PortScanner

from grinder.decorators import exception_handler
from grinder.errors import (
    NmapConnectorInitError,
    NmapConnectorScanError,
    NmapConnectorGetResultsError,
    NmapConnectorGetResultsCountError,
)


class NmapConnector:
    @exception_handler(expected_exception=NmapConnectorInitError)
    def __init__(self):
        self.nm = PortScanner()
        self.results: dict = {}

    @exception_handler(expected_exception=NmapConnectorScanError)
    def scan(self, host: str, arguments: str, ports: str, sudo: bool) -> None:
        if arguments and ports:
            self.nm.scan(hosts=host, arguments=arguments, ports=ports, sudo=sudo)
        elif arguments:
            self.nm.scan(hosts=host, arguments=arguments, sudo=sudo)
        else:
            self.nm.scan(hosts=host, sudo=sudo)
        self.results = {host: self.nm[host] for host in self.nm.all_hosts()}

    @exception_handler(expected_exception=NmapConnectorGetResultsError)
    def get_results(self) -> dict:
        return self.results

    @exception_handler(expected_exception=NmapConnectorGetResultsCountError)
    def get_results_count(self) -> int:
        return len(self.results)
