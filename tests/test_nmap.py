#!/usr/bin/env python3

import pytest

from grinder.nmapprocessmanager import NmapProcessingManager


def setup_module():
    global nm
    hosts = [f"8.8.8.{minor}".format(minor) for minor in range(100, 110)]
    nm = NmapProcessingManager(
        hosts=hosts, ports="80,443", sudo=False, arguments="-Pn -A", workers=10
    )


def test_nmap_scan():
    nm.start()


def test_results():
    nm.get_results()


def test_results_count():
    nm.get_results_count()
