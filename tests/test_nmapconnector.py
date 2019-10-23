#!/usr/bin/env python3

import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from unittest.mock import patch

from pytest import raises

from grinder.defaultvalues import DefaultNmapScanValues
from grinder.errors import (
    NmapConnectorInitError,
    NmapConnectorScanError,
    NmapConnectorGetResultsError,
    NmapConnectorGetResultsCountError,
)
from grinder.nmapconnector import NmapConnector


def setup_module() -> None:
    """
    Initialize HTTPServer for test NmapConnector scanning
    and NmapConnector for various tests
    :return:
    """
    global server
    server = HTTPServer(("localhost", 8080), SimpleHTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    global nm
    nm = NmapConnector()


def teardown_module() -> None:
    """
    Stop HTTPServer
    :return:
    """
    server.shutdown()


def test_nmapconnector_init() -> None:
    """
    Check if we can successfully create new NmapConnector instance
    :return:
    """
    nmapconnector = NmapConnector()


def test_nmapconnector_init_error() -> None:
    """
    Raise NmapConnectorInitError and check output of it
    :return:
    """
    with patch(
        "grinder.nmapconnector.NmapConnector.__init__",
        side_effect=NmapConnectorInitError("test"),
    ):
        with raises(NmapConnectorInitError) as init_error:
            NmapConnector()
        assert "Error occured in Nmap Connector module" in str(init_error.value)


def test_nmapconnector_scan_error() -> None:
    """
    Raise NmapConnectorScanError and check output of it
    :return:
    """
    with patch(
        "grinder.nmapconnector.NmapConnector.scan",
        side_effect=NmapConnectorScanError("test"),
    ):
        with raises(NmapConnectorScanError) as scan_error:
            nm.scan(
                host="127.0.0.1",
                arguments=DefaultNmapScanValues.ARGUMENTS,
                ports=DefaultNmapScanValues.PORTS,
                sudo=DefaultNmapScanValues.SUDO,
            )
        assert "Error occured in Nmap Connector module" in str(scan_error.value)


def test_nmpaconnector_scan_without_any_args() -> None:
    """
    Test NmapConnector scan running without any args
    :return:
    """
    with raises(NmapConnectorScanError) as scan_error:
        nm.scan(host="", arguments="", ports="", sudo=False)
    assert "'' does not appear to be an IPv4 or IPv6 address" in str(scan_error.value)


def test_nmpaconnector_scan_bad_argument() -> None:
    """
    Test NmapConnector scan running with bad arguments
    :return:
    """
    with raises(NmapConnectorScanError) as scan_error:
        nm.scan(
            host="127.0.0.1",
            arguments="--bad-argument",
            ports=DefaultNmapScanValues.PORTS,
            sudo=DefaultNmapScanValues.SUDO,
        )
    assert "Error occured in Nmap Connector module" in str(scan_error.value)


def test_nmapconnector_get_results() -> None:
    """
    Check if we can successfully get NmapConnector scan results
    :return:
    """
    get_resuts = nm.get_results()


def test_nmapconnector_get_results_error() -> None:
    """
    Raise NmapConnectorGetResultsError and check output of it
    :return:
    """
    with patch(
        "grinder.nmapconnector.NmapConnector.get_results",
        side_effect=NmapConnectorGetResultsError("test"),
    ):
        with raises(NmapConnectorGetResultsError) as get_results_error:
            nm.get_results()
        assert "Error occured in Nmap Connector module" in str(get_results_error.value)


def test_nmapconnector_get_results_count() -> None:
    """
    Check if we can successfully get NmapConnector scan results
    :return:
    """
    get_resuts_count = nm.get_results_count()


def test_nmapconnector_get_results_count_error() -> None:
    """
    Raise NmapConnectorGetResultsCountError and check output of it
    :return:
    """
    with patch(
        "grinder.nmapconnector.NmapConnector.get_results_count",
        side_effect=NmapConnectorGetResultsCountError("test"),
    ):
        with raises(NmapConnectorGetResultsCountError) as get_results_count_error:
            nm.get_results_count()
        assert "Error occured in Nmap Connector module" in str(
            get_results_count_error.value
        )
