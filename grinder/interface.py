#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
from os import environ
from sys import version_info, argv, exit

from grinder.decorators import exception_handler
from grinder.errors import GrinderInterfaceLoadEnvironmentKeyError, GrinderInterfaceParseArgsError, \
    GrinderInterfaceGetShodanKeyError


class GrinderInterface:
    def __init__(self):
        self.args: list = []

    @staticmethod
    def check_python_version() -> None:
        if version_info < (3, 6):
            print('Required python version is 3.6 or greater.')
            exit(1)

    @exception_handler(expected_exception=GrinderInterfaceLoadEnvironmentKeyError)
    def load_key_from_env(self) -> str:
        key = environ.get('SHODAN_API_KEY')
        if not key:
            exit(1)
        return key

    @exception_handler(expected_exception=GrinderInterfaceParseArgsError)
    def parse_args(self) -> Namespace:
        if len(argv) == 1:
            print(f'Usage: {argv[0]} -h for help')
        parser = ArgumentParser(description='Batch collect Shodan results from multiple queries.')
        parser.add_argument('-r', '--run', action='store_true', default=False, help='Run scanning')
        parser.add_argument('-u', '--update-markers', action='store_true', default=False, help='Update map markers')
        parser.add_argument('-q', '--queries-file', action='store', default='queries.json',
                            help='JSON File with Shodan queries')
        parser.add_argument('-sk', '--shodan-key', action='store', default=None, help='Shodan API key')
        parser.add_argument('-cu', '--count-unique', action='store_true', default=False, help='Count unique entities')
        parser.add_argument('-cp', '--create-plots', action='store_true', default=False, help='Create graphic plots')
        self.args = parser.parse_args()
        if not self.args.shodan_key:
            self.args.shodan_key = self.load_key_from_env()
        return self.args

    @exception_handler(expected_exception=GrinderInterfaceGetShodanKeyError)
    def get_shodan_key(self) -> str:
        if self.args.shodan_key:
            return self.args.shodan_key
