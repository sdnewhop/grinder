#!/usr/bin/env python3

from sys import stdout

from colorama import init
from pyfiglet import figlet_format
from termcolor import cprint


class AsciiOpener:
    @staticmethod
    def print_opener() -> None:
        """
        This function draws a big GRINDER ASCII logo at startup.
        :return: None
        """
        init(strip=not stdout.isatty())
        cprint(figlet_format("GRINDER", font="cosmike"), "blue", attrs=["bold"])
