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

    @staticmethod
    def check_ip_v6(host: str):
        """
        Check if presented IP address is IPv6 (not IPv4 as expected)
        :param host: IP address of some host
        :return: bool answer to question "Is host address are IPv6?"
        """
        if "IPv6Address" in str(type(ip_address(host))):
            return True

    @exception_handler(expected_exception=NmapConnectorScanError)
    def scan(
        self, host: str, arguments: str = "", ports: str = "", sudo: bool = False
    ) -> None:
        """
        The most basic Nmap caller. This is the "lowest" function in terms
        of Grinder Framework, all calls here are going to python-nmap
        library. In this function we just puts right arguments, parameters
        and other things to call Nmap.
        :param host: ip of the host to scan
        :param arguments: arguments for Nmap
        :param ports: ports to scan with Nmap
        :param sudo: is sudo required to Nmap scan?
        :return: None
        """

        # Add special Nmap key to scan ipv6 hosts
        if self.check_ip_v6(host):
            arguments += " -6"

        # If user wants to scan for top-ports,
        # let's remove other ports from nmap scan
        if "top-ports" in arguments:
            self.nm.scan(hosts=host, arguments=arguments, sudo=sudo)

        # Else if user doesn't want scan for top-ports,
        # let's scan with defined ports
        elif arguments and ports:
            self.nm.scan(hosts=host, arguments=arguments, ports=ports, sudo=sudo)

        # Else if ports are not defined, let's
        # scan with default ports
        elif arguments:
            self.nm.scan(hosts=host, arguments=arguments, sudo=sudo)

        # Else if arguments are not defined, let's
        # scan with default arguments
        elif ports:
            self.nm.scan(hosts=host, ports=ports, sudo=sudo)

        # If arguments are not set too, make
        # simple scan
        else:
            self.nm.scan(hosts=host, sudo=sudo)
        self.results = {host: self.nm[host] for host in self.nm.all_hosts()}

    @exception_handler(expected_exception=NmapConnectorGetResultsError)
    def get_results(self) -> dict:
        """
        Return Nmap scan results
        :return: dictionary with results {host: info}
        """
        return self.results

    @exception_handler(expected_exception=NmapConnectorGetResultsCountError)
    def get_results_count(self) -> int:
        """
        Return quantity of results
        :return: quantity of results
        """
        return len(self.results)
