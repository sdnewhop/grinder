#!/usr/bin/env python3
from pytest import fixture, raises
from unittest.mock import patch

from grinder.shodanconnector import ShodanConnector
from grinder.errors import ShodanConnectorInitError


@fixture
def shodan_key_value(shodan_key: str) -> str:
    """
    Return shodan key from CLI
    :param shodan_key: shodan key value
    :return: shodan key value
    """
    return shodan_key


def test_shodanconnector_init_invalid_api() -> None:
    """
    Test case when we put invalid API key
    at initilization. Nothing will happened
    (normally :)) because Shodan will not
    check if key is valid, it will only store
    it. But still let's check that everything
    will be okay.
    :return: None
    """
    ShodanConnector(api_key="Wrong")
    ShodanConnector(api_key="")
    ShodanConnector(api_key=None)
    ShodanConnector(api_key=123)


def test_shodanconnector_init_error(shodan_key_value: str) -> None:
    """
    Check error handling, error message, etc.
    :return: None
    """
    with patch(
        "grinder.shodanconnector.ShodanConnector.__init__",
        side_effect=ShodanConnectorInitError("test"),
    ):
        with raises(Exception) as init_err:
            ShodanConnector(api_key=shodan_key_value)
        assert "Error occured in Shodan Connector module" in str(init_err.value)
