#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
from os import environ
from sys import version_info, argv, exit

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultValues
from grinder.errors import (
    GrinderInterfaceLoadEnvironmentKeyError,
    GrinderInterfaceParseArgsError,
    GrinderInterfaceGetShodanKeyError,
)


class GrinderInterface:
    def __init__(self):
        self.args: list = []

    @staticmethod
    def check_python_version() -> None:
        """
        This function checks a python version to be
        sure that all of the features will be supported.
        :return: None
        """
        if version_info < (3, 6):
            print("Required python version is 3.6 or greater.")
            exit(1)

    @exception_handler(expected_exception=GrinderInterfaceLoadEnvironmentKeyError)
    def load_shodan_key_from_env(self) -> str:
        """
        Return Shodan API key from environment variable
        :return: Shodan API key
        """
        return environ.get("SHODAN_API_KEY")

    @exception_handler(expected_exception=GrinderInterfaceLoadEnvironmentKeyError)
    def load_censys_keys_from_env(self) -> tuple:
        """
        Return Censys API ID, API Secret from environment variables
        :return: pair API ID + API Secret
        """
        return environ.get("CENSYS_API_ID"), environ.get("CENSYS_API_SECRET")

    @exception_handler(expected_exception=GrinderInterfaceLoadEnvironmentKeyError)
    def load_vulners_key_from_env(self) -> str:
        """
        Return Vulners API key from environment variable
        :return: Vulners API key
        """
        return environ.get("VULNERS_API_KEY")

    @exception_handler(expected_exception=GrinderInterfaceParseArgsError)
    def parse_args(self) -> Namespace:
        """
        Arguments parser for CLI arguments
        :return: namespace/dictionary with CLI argument values
        """
        if len(argv) == 1:
            print(f"Usage: {argv[0]} -h for help")
            exit(1)
        parser = ArgumentParser(
            description="""
            The Grinder framework was created to automatically enumerate and fingerprint 
            different hosts on the Internet using different back-end systems"""
        )
        parser.add_argument(
            "-r", "--run", action="store_true", default=False, help="Run scanning"
        )
        parser.add_argument(
            "-u",
            "--update-markers",
            action="store_true",
            default=False,
            help="Update map markers",
        )
        parser.add_argument(
            "-q",
            "--queries-file",
            action="store",
            default="queries.json",
            help="JSON File with Shodan queries",
        )

        parser.add_argument(
            "-sk", "--shodan-key", action="store", default=None, help="Shodan API key"
        )
        parser.add_argument(
            "-vk", "--vulners-key", action="store", default=None, help="Vulners API key"
        )
        parser.add_argument(
            "-oh", "--one-host", action="store", default=None, help="One host scan, write ip address or domain name"
        )

        parser.add_argument(
            "-cu",
            "--count-unique",
            action="store_true",
            default=False,
            help="Count unique entities",
        )
        parser.add_argument(
            "-cp",
            "--create-plots",
            action="store_true",
            default=False,
            help="Create graphic plots",
        )
        parser.add_argument(
            "-ci", "--censys-id", action="store", default=None, help="Censys API ID key"
        )
        parser.add_argument(
            "-cs",
            "--censys-secret",
            action="store",
            default=None,
            help="Censys API SECRET key",
        )
        parser.add_argument(
            "-cm",
            "--censys-max",
            action="store",
            type=int,
            default=None,
            help="Censys default maximum results quantity",
        )
        parser.add_argument(
            "-sm",
            "--shodan-max",
            action="store",
            type=int,
            default=None,
            help="Shodan default maximum results quantity. ",
        )
        parser.add_argument(
            "-nm",
            "--nmap-scan",
            action="store_true",
            default=False,
            help="Initiate Nmap scanning",
        )
        parser.add_argument(
            "-nw",
            "--nmap-workers",
            action="store",
            type=int,
            default=10,
            help="Number of Nmap workers to scan",
        )
        parser.add_argument(
            "-vs",
            "--vulners-scan",
            action="store_true",
            default=False,
            help="Initiate Vulners API scanning",
        )
        parser.add_argument(
            "-vw",
            "--vulners-workers",
            action="store",
            type=int,
            default=10,
            help="Number of Vulners workers to scan",
        )
        parser.add_argument(
            "-ht",
            "--host-timeout",
            action="store",
            type=int,
            default=120,
            help="Default host timeout in seconds for scanning with Vulners and Nmap core",
        )
        parser.add_argument(
            "-tp",
            "--top-ports",
            action="store",
            type=int,
            default=None,
            help="Quantity of popular top-ports in addition to Shodan ports",
        )
        parser.add_argument(
            "-sc",
            "--script-check",
            action="store_true",
            default=False,
            help="Initiate custom scripts additional checks",
        )
        parser.add_argument(
            "-vc",
            "--vendor-confidence",
            action="store",
            default=None,
            help="Set confidence level for vendors",
        )
        parser.add_argument(
            "-qc",
            "--query-confidence",
            action="store",
            default=None,
            help="Set confidence level for queries",
        )
        parser.add_argument(
            "-v",
            "--vendors",
            nargs="*",
            default=[],
            help="Set list of vendors to search from queries file",
        )
        parser.add_argument(
            "-ml",
            "--max-limit",
            action="store",
            type=int,
            default=None,
            help="Maximum number of unique entities in plots and results",
        )
        parser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            default=False,
            help="Show more information",
        )
        parser.add_argument(
            "-ts",
            "--tls-scan",
            action="store_true",
            default=False,
            help="Check for possible TLS attacks and bugs (require TLS-Scanner)",
        )
        parser.add_argument(
            "-tsp",
            "--tls-scan-path",
            action="store",
            default=None,
            help="Path to TLS-Scanner.jar (if TLS-Scanner directory not in Grinder root, else not required)",
        )
        parser.add_argument(
            "-vr",
            "--vulners-report",
            action="store_true",
            default=False,
            help="Make additional vulners reports",
        )
        parser.add_argument(
            "-ni",
            "--not-incremental",
            action="store_true",
            default=False,
            help="Turn off incrememental scan - make clean scan (without previous results)",
        )

        self.args = parser.parse_args()
        if not self.args.shodan_key:
            self.args.shodan_key = self.load_shodan_key_from_env()
        if not self.args.vulners_key:
            self.args.vulners_key = self.load_vulners_key_from_env()
        if not (self.args.censys_id or self.args.censys_secret):
            self.args.censys_id, self.args.censys_secret = (
                self.load_censys_keys_from_env()
            )
        if self.args.debug:
            query_confidence_level = (
                self.args.query_confidence or "all queries, any confidence"
            )
            vendor_confidence_level = (
                self.args.vendor_confidence or "all vendors, any confidence"
            )
            vendors_list = self.args.vendors or "all vendors"

            print(
                f"Shodan API key: {self.args.shodan_key or DefaultValues.SHODAN_API_KEY}"
            )
            print(
                f"Censys API ID: {self.args.censys_id or DefaultValues.CENSYS_API_ID}"
            )
            print(
                f"Censys API SECRET: {self.args.censys_secret or DefaultValues.CENSYS_API_SECRET}"
            )
            print(
                f"Vulners API key: {self.args.vulners_key or DefaultValues.VULNERS_API_KEY}"
            )
            print(f"Query confidence level: {query_confidence_level}")
            print(f"Vendor confidence level: {vendor_confidence_level}")
            print(f"Vendors to scan: {vendors_list}")
            print(f"Shodan max results quantity: {self.args.shodan_max}")
            print(f"Censys max results quantity: {self.args.censys_max}")
        return self.args

    @exception_handler(expected_exception=GrinderInterfaceGetShodanKeyError)
    def get_shodan_key(self) -> str:
        """
        Return Shodan key if key is presented
        in arguments
        :return: Shodan API key
        """
        if self.args.shodan_key:
            return self.args.shodan_key
