#!/usr/bin/env python3
from censys.ipv4 import CensysIPv4
from unittest.mock import patch
from pytest import raises, fixture

from grinder.censysconnector import CensysConnector
from grinder.errors import (
    CensysConnectorInitError,
    CensysConnectorSearchError,
    CensysConnectorGetResultsError
)


@fixture
def censys_id_value(censys_id: str) -> str:
    """
    Return censys id value from CLI
    :param censys_id: censys id value
    :return: censys id value
    """
    return censys_id


@fixture
def censys_secret_value(censys_secret: str) -> str:
    """
    Return censys secret value from CLI
    :param censys_secret: censys secret value
    :return: censys secret value
    """
    return censys_secret


def test_censysconnector_init_invalid_api(capsys) -> None:
    """
    Check that user will be noticed in case when
    his API ID or API SECRET is invalid
    :param capsys: catch output of the function
    :return: None
    """
    CensysConnector(api_id="not_valid", api_secret="not_valid")
    output = capsys.readouterr().out
    for expected_output in ["Censys invalid API keys error", "403 (unathorized)"]:
        assert expected_output in output


def test_censysconnector_init_not_configured_api(capsys) -> None:
    """
    Check that user will be noticed in case when
    censys API ID or API SECRET is totally empty
    :param capsys: catch output of the function
    :return: None
    """
    CensysConnector(api_id=None, api_secret=None)
    output = capsys.readouterr().out
    for expected_output in ["Censys API error", "401 (None)"]:
        assert expected_output in output


def test_censysconnector_init_valid_api(censys_id_value: str, censys_secret_value: str) -> None:
    """
    Check if we can properly initialize api with
    proper API IP and proper API SECRET. Check
    api object after it.
    :param censys_id_value: censys id
    :param censys_secret_value: censys secret
    :return: None
    """
    censys_connector = CensysConnector(
        api_id=censys_id_value, api_secret=censys_secret_value
    )
    assert isinstance(censys_connector.api, CensysIPv4)


def test_censysconnector_init_error(censys_id_value: str, censys_secret_value: str) -> None:
    """
    Raise CensysConnector error and check output of it,
    this function is not very useful but still required
    :param censys_id_value: censys id
    :param censys_secret_value: censys secret
    :return: None
    """
    with patch(
        "grinder.censysconnector.CensysConnector.__init__",
        side_effect=CensysConnectorInitError("test"),
    ):
        with raises(Exception) as init_err:
            CensysConnector(api_id=censys_id_value, api_secret=censys_secret_value)
        assert "Error occured in Censys Connector module" in str(init_err.value)


def test_censysconnector_search_api_malformed_request(
    censys_id_value: str, censys_secret_value: str, capsys
) -> None:
    """
    Check how we can handle malformed requests
    :param censys_id_value: censys id
    :param censys_secret_value: censys secret
    :param capsys: catch output of the function
    :return: None
    """
    api = CensysConnector(api_id=censys_id_value, api_secret=censys_secret_value)
    api.search(query=None)
    output = capsys.readouterr().out
    for expected_output in ["Censys API core exception", "400 (malformed_request)"]:
        assert expected_output in output


def test_censysconnector_search_too_much_results_error(
    censys_id_value: str, censys_secret_value: str, capsys
) -> None:
    """
    Check how we can handle situation when we got
    more results than we can afford with our API
    plan.

    Interesting fact, that if we will search
    with empty request, we will get a lot of
    trash - that's cool in case of this test,
    but kinda strange in case of API :)
    :param censys_id_value: censys id
    :param censys_secret_value: censys secret
    :param capsys: catch output of the function
    :return: None
    """
    api = CensysConnector(api_id=censys_id_value, api_secret=censys_secret_value)
    api.search(query="")
    output = capsys.readouterr().out
    assert (
        "Only the first 1,000 search results are available. Retry search with 1,000 results limit."
        in output
    )

    # check if we get 1.000 of results - it is
    # maximum quantity for free plan
    assert len(api.get_raw_results()) == 1000
    assert api.censys_results_count == 1000


def test_censysconnector_search_not_initialized_api(capsys) -> None:
    """
    Check case when our API object was not
    initialized properly (we put wrong key,
    not put key at all, etc.) but we still
    try to search for something
    :param capsys: catch output of the function
    :return: None
    """
    api = CensysConnector(api_id="not_valid", api_secret="not_valid")
    api.search(query="")
    output = capsys.readouterr().out
    for expected_output in ["Censys invalid API keys error", "403 (unathorized)"]:
        assert expected_output in output


def test_censysconnector_search_error(censys_id_value: str, censys_secret_value: str) -> None:
    """
    Raise CensysConnector error and check output of it
    :param censys_id_value: censys id
    :param censys_secret_value: censys secret
    :return: None
    """
    api = CensysConnector(api_id=censys_id_value, api_secret=censys_secret_value)
    with patch(
        "grinder.censysconnector.CensysConnector.search",
        side_effect=CensysConnectorSearchError("test"),
    ):
        with raises(Exception) as init_err:
            api.search("")
        assert "Error occured in Censys Connector module" in str(init_err.value)


def test_censysconnector_get_raw_results(censys_id_value: str, censys_secret_value: str) -> None:
    """
    Check raw results keys
    :param censys_id_value: censys id
    :param censys_secret_value: censys secret
    :return: None
    """
    api = CensysConnector(api_id=censys_id_value, api_secret=censys_secret_value)
    api.search(query="", max_records=10)
    results = api.get_raw_results()
    assert len(results) == 10
    for result in results:
        assert sorted(result.keys()) == sorted(
            [
                "ip",
                "location.country",
                "location.latitude",
                "location.longitude",
                "ports",
                "protocols",
            ]
        )


def test_censysconnector_get_results(censys_id_value: str, censys_secret_value: str) -> None:
    """
    Check results parser
    :param censys_id_value: censys id
    :param censys_secret_value: censys secret
    :return: None
    """
    api = CensysConnector(api_id=censys_id_value, api_secret=censys_secret_value)
    api.search(query="", max_records=10)
    results = api.get_results()
    assert len(results) == 10
    for result in results:
        assert sorted(result.keys()) == sorted(
            ["ip", "country", "lat", "lng", "port", "proto"]
        )


def test_censysconnector_get_results_error(censys_id_value: str, censys_secret_value: str) -> None:
    """
    Raise CensysConnector error and check output of it
    :param censys_id_value: censys id
    :param censys_secret_value: censys secret
    :return: None
    """
    api = CensysConnector(api_id=censys_id_value, api_secret=censys_secret_value)
    api.search(query="", max_records=10)
    with patch(
        "grinder.censysconnector.CensysConnector.get_results",
        side_effect=CensysConnectorGetResultsError("test"),
    ):
        with raises(Exception) as init_err:
            api.get_results()
        assert "Error occured in Censys Connector module" in str(init_err.value)
