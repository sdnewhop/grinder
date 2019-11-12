#!/usr/bin/env python3

from threading import Thread

from http.server import HTTPServer, SimpleHTTPRequestHandler
from socket import AF_INET6

from unittest.mock import patch
from pytest import raises

from grinder.defaultvalues import DefaultNmapScanValues
from grinder.nmapconnector import NmapConnector
from grinder.errors import (
    NmapConnectorInitError,
    NmapConnectorScanError,
    NmapConnectorGetResultsError,
    NmapConnectorGetResultsCountError,
)


class NmapTestDefaultValues:
    HOST4 = "127.0.0.1"
    HOST6 = "::1"
    PORT4 = 8080
    PORT6 = 8090


class HTTPServer6(HTTPServer):
    address_family = AF_INET6


def setup_module() -> None:
    """
    Initialize HTTPServer for test NmapConnector scanning
    and NmapConnector for various tests
    :return:
    """
    global server_v4
    server_v4 = HTTPServer(
        (NmapTestDefaultValues.HOST4, NmapTestDefaultValues.PORT4),
        SimpleHTTPRequestHandler,
    )
    s_v4 = Thread(target=server_v4.serve_forever, daemon=True)
    s_v4.start()

    global server_v6
    server_v6 = HTTPServer6(
        (NmapTestDefaultValues.HOST6, NmapTestDefaultValues.PORT6),
        SimpleHTTPRequestHandler,
    )
    s_v6 = Thread(target=server_v6.serve_forever, daemon=True)
    s_v6.start()

    global nm
    nm = NmapConnector()

    global empty_nm
    empty_nm = NmapConnector()

    global nm_v4
    nm_v4 = NmapConnector()

    global nm_v6
    nm_v6 = NmapConnector()


def teardown_module() -> None:
    """
    Stop HTTPServer
    :return:
    """
    server_v4.shutdown()
    server_v6.shutdown()


def test_nmapconnector_init() -> None:
    """
    Check if we can successfully create new NmapConnector instance
    :return:
    """
    NmapConnector()


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
        assert "Error occured in Nmap Connector module: test" == str(init_error.value)


def test_nmapconnector_scan_ipv4() -> None:
    """
    Check if we can successfully scan 127.0.0.1 host
    :return:
    """
    nm_v4.scan(
        host=NmapTestDefaultValues.HOST4,
        arguments=DefaultNmapScanValues.ARGUMENTS,
        ports=str(NmapTestDefaultValues.PORT4),
    )

    assert (
        nm_v4.get_results()
        .get(NmapTestDefaultValues.HOST4)
        .get("tcp")
        .get(NmapTestDefaultValues.PORT4, False)
    )


def test_nmapconnector_scan_ipv6() -> None:
    """
    Check if we can successfully scan ::1 host
    :return:
    """
    nm_v6.scan(
        host=NmapTestDefaultValues.HOST6,
        arguments=DefaultNmapScanValues.ARGUMENTS,
        ports=str(NmapTestDefaultValues.PORT6),
    )

    assert (
        nm_v6.get_results()
        .get(NmapTestDefaultValues.HOST6)
        .get("tcp")
        .get(NmapTestDefaultValues.PORT6, False)
    )


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
            nm.scan(host=NmapTestDefaultValues.HOST4)
        assert "Error occured in Nmap Connector module: test" == str(scan_error.value)


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
        nm.scan(host=NmapTestDefaultValues.HOST4, arguments="--bad-argument")
    assert "nmap: unrecognized option" in str(scan_error.value) \
           and "--bad-argument" in str(scan_error.value)


def test_nmapconnector_get_results_ipv4() -> None:
    """
    Check if we can successfully get NmapConnector
    scan results for IPv4
    :return:
    """
    assert nm_v4.get_results()


def test_nmapconnector_get_results_ipv6() -> None:
    """
    Check if we can successfully get NmapConnector
    scan results for IPv6
    :return:
    """
    assert nm_v6.get_results()


def test_nmapconnector_get_results_with_default_values() -> None:
    """
    Check if we can successfully get scan results
    from NmapConnector with default values
    :return:
    """
    assert empty_nm.get_results() == {}


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
        assert "Error occured in Nmap Connector module: test" == str(
            get_results_error.value
        )


def test_nmapconnector_get_results_count_ipv4() -> None:
    """
    Check if we can successfully get the count of
    NmapConnector scan results for IPv4
    :return:
    """
    assert nm_v4.get_results_count()


def test_nmapconnector_get_results_count_ipv6() -> None:
    """
    Check if we can successfully get the count of
    NmapConnector scan results for IPv6
    :return:
    """
    assert nm_v6.get_results_count()


def test_nmapconnector_get_results_count_with_default_values() -> None:
    """
    Check if we can successfully get scan results
    from NmapConnector with default values
    :return:
    """
    assert empty_nm.get_results_count() == 0


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
        assert "Error occured in Nmap Connector module: test" == str(
            get_results_count_error.value
        )
