#!/usr/bin/env python3

from nmap import PortScanner
from ipaddress import ip_address

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

    def check_ip_v6(self, host: str):
        if "IPv6Address" in str(type(ip_address(host))):
            return True

    @exception_handler(expected_exception=NmapConnectorScanError)
    def scan(self, host: str, arguments: str = "", ports: str = "", sudo: bool = False) -> None:
        # Add special Nmap key to scan ipv6 hosts
        if self.check_ip_v6(host):
            arguments += " -6"
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
