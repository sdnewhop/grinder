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
        if version_info < (3, 6):
            print("Required python version is 3.6 or greater.")
            exit(1)

    @exception_handler(expected_exception=GrinderInterfaceLoadEnvironmentKeyError)
    def load_shodan_key_from_env(self) -> str:
        return environ.get("SHODAN_API_KEY")

    def load_censys_keys_from_env(self) -> tuple:
        return environ.get("CENSYS_API_ID"), environ.get("CENSYS_API_SECRET")

    @exception_handler(expected_exception=GrinderInterfaceParseArgsError)
    def parse_args(self) -> Namespace:
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
            "-c",
            "--confidence",
            action="store",
            default=None,
            help="Set confidence level",
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
        self.args = parser.parse_args()
        if not self.args.shodan_key:
            self.args.shodan_key = self.load_shodan_key_from_env()
        if not (self.args.censys_id or self.args.censys_secret):
            self.args.censys_id, self.args.censys_secret = (
                self.load_censys_keys_from_env()
            )
        if self.args.run:
            print(
                f"Shodan API key: {self.args.shodan_key or DefaultValues.SHODAN_API_KEY}"
            )
            print(
                f"Censys API ID: {self.args.censys_id or DefaultValues.CENSYS_API_ID}"
            )
            print(
                f"Censys API SECRET: {self.args.censys_secret or DefaultValues.CENSYS_API_SECRET}"
            )
        return self.args

    @exception_handler(expected_exception=GrinderInterfaceGetShodanKeyError)
    def get_shodan_key(self) -> str:
        if self.args.shodan_key:
            return self.args.shodan_key
