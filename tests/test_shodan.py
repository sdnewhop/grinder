#!/usr/bin/env python3
from pytest import fixture, raises
from unittest.mock import patch
from pprint import pprint

from grinder.defaultvalues import DefaultValues
from grinder.shodanconnector import ShodanConnector
from grinder.errors import ShodanConnectorInitError, ShodanConnectorSearchError


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
    :param shodan_key_value: shodan key
    :return: None
    """
    with patch(
        "grinder.shodanconnector.ShodanConnector.__init__",
        side_effect=ShodanConnectorInitError("test"),
    ):
        with raises(Exception) as init_err:
            ShodanConnector(api_key=shodan_key_value)
        assert "Error occured in Shodan Connector module" in str(init_err.value)


def test_shodanconnector_search_empty_query(shodan_key_value: str, capsys) -> None:
    """
    Check behavior in case of empty query
    :param shodan_key_value: shodan key
    :return: None
    """
    api = ShodanConnector(api_key=shodan_key_value)
    for query in ["", None]:
        api.search(query=query)
        output = capsys.readouterr().out
        for expected_output in ["Shodan API error", "Empty search query"]:
            assert expected_output in output


def test_shodanconnector_max_records(shodan_key_value: str) -> None:
    """
    Check that max_records flag works as expected, 
    and returns only fixed quantity of hosts
    :param shodan_key_value: shodan key
    :return: None
    """
    api = ShodanConnector(api_key=shodan_key_value)
    for quantity in [5, 10, 25, 30]:
        api.search(query="nginx", max_records=quantity)
        assert len(api.get_results()) == quantity
        assert api.get_real_count() == quantity


def test_shodanconnector_search_error(shodan_key_value: str) -> None:
    """
    Check error handling and error message in case
    of custom error raising with module
    :param shodan_key_value: shodan key
    :return: None
    """
    api = ShodanConnector(api_key=shodan_key_value)
    with patch(
        "grinder.shodanconnector.ShodanConnector.search",
        side_effect=ShodanConnectorSearchError("test"),
    ):
        with raises(Exception) as search_err:
            api.search(query="nginx", max_records=100)
        assert "Error occured in Shodan Connector module" in str(search_err.value)


def test_shodanconnector_search_zero_max_records(shodan_key_value: str) -> None:
    """
    Check case when results are empty or max_records == 0
    :param shodan_key_value: shodan key
    :return: None
    """
    api = ShodanConnector(api_key=shodan_key_value)
    api.search(query="nginx", max_records=0)
    assert isinstance(api.get_results(), list) and api.get_results() == []
    assert api.get_real_count() == 0
    assert api.get_shodan_count() > 0


def test_shodanconnector_get_vulnerabilities(shodan_key_value: str) -> None:
    """
    Check vulnerabilities parsing method
    :param shodan_key_value: shodan key
    :return: None
    """
    api = ShodanConnector(api_key=shodan_key_value)
    api.search(query="apache", max_records=100)
    vulnerabilities = api.get_vulnerabilities()
    for ip, cve_list in vulnerabilities.items():
        for cve, information in cve_list.items():
            assert sorted(information.keys()) == sorted(
                ["cvss", "references", "summary"]
            )
            assert (
                len(information.get("references"))
                <= DefaultValues.SHODAN_MAX_VULNERABILITIES_REFERENCES
            )
