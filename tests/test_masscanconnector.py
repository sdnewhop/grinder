#!/usr/bin/env python3

from unittest.mock import patch

from pytest import raises

from grinder.defaultvalues import DefaultMasscanScanValues
from grinder.errors import (
    MasscanConnectorInitError,
    MasscanConnectorScanError,
    MasscanConnectorGetResultsError,
    MasscanConnectorGetResultsCountError,
)
from grinder.masscanconnector import MasscanConnector


class MasscanTestDefaultValues:
    HOST = "8.8.8.8"
    PORTS = "53"


def setup_module() -> None:
    """
    Initialize MasscanConnector for various tests
    :return:
    """

    global mc
    mc = MasscanConnector()


def test_masscanconnector_init() -> None:
    """
    Check if we can successfully create new MasscanConnector instance
    :return:
    """
    MasscanConnector()


def test_masscanconnector_init_error() -> None:
    """
    Raise MasscanConnectorInitError and check output of it
    :return:
    """
    with patch(
        "grinder.masscanconnector.MasscanConnector.__init__",
        side_effect=MasscanConnectorInitError("test"),
    ):
        with raises(MasscanConnectorInitError) as init_error:
            MasscanConnector()
        assert "Error occured in Masscan Connector module: test" == str(
            init_error.value
        )


def test_masscanconnector_scan_ip() -> None:
    """
    Check if we can successfully scan 8.8.8.8 host
    :return:
    """

    mc.scan(
        host=MasscanTestDefaultValues.HOST,
        rate=DefaultMasscanScanValues.RATE,
        arguments=DefaultMasscanScanValues.ARGUMENTS,
        ports=str(MasscanTestDefaultValues.PORTS),
        sudo=DefaultMasscanScanValues.SUDO,
    )

    assert (
        mc.get_results()
        .get(MasscanTestDefaultValues.HOST)
        .get("tcp")
        .get(int(MasscanTestDefaultValues.PORTS), False)
    )


def test_masscanconnector_scan_error() -> None:
    """
    Raise MasscanConnectorScanError and check output of it
    :return:
    """
    with patch(
        "grinder.masscanconnector.MasscanConnector.scan",
        side_effect=MasscanConnectorScanError("test"),
    ):
        with raises(MasscanConnectorScanError) as scan_error:
            mc.scan(
                host=MasscanTestDefaultValues.HOST,
                ports=MasscanTestDefaultValues.PORTS,
                rate=DefaultMasscanScanValues.RATE,
                sudo=DefaultMasscanScanValues.SUDO,
            )
        assert "Error occured in Masscan Connector module: test" == str(
            scan_error.value
        )


def test_masscanconnector_scan_without_any_args() -> None:
    """
    Test MasscanConnector scan running without any args
    :return:
    """
    with raises(MasscanConnectorScanError) as scan_error:
        mc.scan(host="", arguments="", ports="", sudo=DefaultMasscanScanValues.SUDO)
    assert "FAIL: target IP address list empty" in str(scan_error.value)


def test_masscanconnector_scan_bad_argument() -> None:
    """
    Test MasscanConnector scan running with bad arguments
    :return:
    """

    with raises(MasscanConnectorScanError) as scan_error:
        mc.scan(
            host=MasscanTestDefaultValues.HOST,
            ports=MasscanTestDefaultValues.PORTS,
            rate=DefaultMasscanScanValues.RATE,
            arguments="bad-argument",
        )
    assert "FAIL: unknown command-line parameter" in str(scan_error.value)


def test_masscanconnector_get_results() -> None:
    """
    Check if we can successfully get MasscanConnector scan results
    :return:
    """
    assert mc.get_results()


def test_masscanconnector_get_results_error() -> None:
    """
    Raise MasscanConnectorGetResultsError and check output of it
    :return:
    """
    with patch(
        "grinder.masscanconnector.MasscanConnector.get_results",
        side_effect=MasscanConnectorGetResultsError("test"),
    ):
        with raises(MasscanConnectorGetResultsError) as get_results_error:
            mc.get_results()
        assert "Error occured in Masscan Connector module: test" == str(
            get_results_error.value
        )


def test_masscanconnector_get_results_count() -> None:
    """
    Check if we can successfully get the count of
    MasscanConnector scan results
    :return:
    """
    assert mc.get_results_count()


def test_masscanconnector_get_results_count_error() -> None:
    """
    Raise MasscanConnectorGetResultsCountError and check output of it
    :return:
    """
    with patch(
        "grinder.masscanconnector.MasscanConnector.get_results_count",
        side_effect=MasscanConnectorGetResultsCountError("test"),
    ):
        with raises(MasscanConnectorGetResultsCountError) as get_results_count_error:
            mc.get_results_count()
        assert "Error occured in Masscan Connector module: test" == str(
            get_results_count_error.value
        )
