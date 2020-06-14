#!/usr/bin/env python3

import logging

import masscan

from grinder.decorators import exception_handler
from grinder.errors import (
    MasscanConnectorInitError,
    MasscanConnectorScanError,
    MasscanConnectorGetResultsError,
    MasscanConnectorGetResultsCountError,
)


class MasscanConnector:
    @exception_handler(expected_exception=MasscanConnectorInitError)
    def __init__(self):
        self.masscan = masscan.PortScanner()
        self.results: dict = {}

        masscan.logger.setLevel(logging.CRITICAL)

    @exception_handler(expected_exception=MasscanConnectorScanError)
    def scan(
            self,
            host: str,
            rate: int or None = None,
            arguments: str = "",
            ports: str = "",
            sudo: bool = False,
    ) -> None:
        """
        The basic Masscan caller. This is the "lowest" function in terms
        of Grinder Framework, all calls here are going to python-masscan
        library. In this function we just puts right arguments, parameters
        and other things to call Masscan.
        :param host: ip of the host to scan
        :param rate: packet rate argument for Masscan
        :param arguments: arguments for Masscan
        :param ports: ports to scan with Masscan
        :param sudo: is sudo required to Masscan scan?
        :return: None
        """

        if rate:
            arguments += f" --rate {rate}"

        # Else if user doesn't want scan for top-ports,
        # let's scan with defined ports
        # elif arguments and ports:
        if arguments and ports:
            self.masscan.scan(hosts=host, arguments=arguments, ports=ports, sudo=sudo)

        # Else if ports are not defined, let's
        # scan with default ports
        elif arguments:
            self.masscan.scan(hosts=host, arguments=arguments, sudo=sudo)

        # Else if arguments are not defined, let's
        # scan with default arguments
        elif ports:
            self.masscan.scan(hosts=host, arguments="", ports=ports, sudo=sudo)

        # If arguments are not set too, make
        # simple scan
        else:
            self.masscan.scan(hosts=host, arguments="", sudo=sudo)

        self.results = {host: self.masscan[host] for host in self.masscan.all_hosts}

    @exception_handler(expected_exception=MasscanConnectorGetResultsError)
    def get_results(self) -> dict:
        """
        Return Masscan scan results
        :return: dictionary with results {host: info}
        """
        return self.results

    @exception_handler(expected_exception=MasscanConnectorGetResultsCountError)
    def get_results_count(self) -> int:
        """
        Return quantity of results
        :return: quantity of results
        """
        return len(self.results)
