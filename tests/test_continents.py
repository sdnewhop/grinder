#!/usr/bin/env python3
from pytest import raises

from grinder.continents import GrinderContinents
from grinder.errors import GrinderContinentsConvertError


def test_continents_valid_countries() -> None:
    """
    Check that GrinderContinents can correctly
    convert countries into continents (w/o Antarctica
    obviously).
    """
    unique_countries = {
        # Africa
        "Nigeria": 1,
        "Ethiopia": 1,
        # Asia
        "China": 1,
        "Indonesia": 1,
        # Europe
        "Russia": 1,
        "Germany": 1,
        # North America
        "United States": 1,
        "Mexico": 1,
        # Oceania
        "Australia": 1,
        "New Zealand": 1,
        # South and Central America,
        "Argentina": 1,
        "Bolivia": 1
    }
    continents = GrinderContinents.convert_continents(
        unique_countries=unique_countries
    )
    assert sorted(continents.keys()) == sorted([
        "Africa", "Asia", "Europe", "North America", "Oceania", "South and Central America"
    ])
    for continent, quantity in continents.items():
        assert quantity == 2


def test_continents_invalid_countries() -> None:
    """
    Check behavior when we put into continents parser
    some invalid countries. We expect to get empty
    continents dict.
    :return: None
    """
    invalid_data = {
        "not_valid_at_all_country": 1,
        "another_not_valid_country": 2
    }
    continents = GrinderContinents.convert_continents(
        unique_countries=invalid_data
    )
    assert isinstance(continents, dict) and len(continents.items()) == 0


def test_continents_antarctica_as_country() -> None:
    """
    Check case when Antarctica became country somehow,
    for example, if search engine put it by mistake
    or if search engine just can not detect it properly.
    :return: None
    """
    antarctica_case = {
        "Antarctica": 1
    }
    continents = GrinderContinents.convert_continents(
        unique_countries=antarctica_case
    )
    assert continents == antarctica_case


def test_continents_empty_countries() -> None:
    """
    Check behavior when we will pass empty dictionary
    with countries (or without countries, if more correct)
    :return: None
    """
    continents = GrinderContinents.convert_continents(
        unique_countries={}
    )
    assert continents == {}


def test_continents_countries_with_zero_quantity() -> None:
    """
    Check behavior when country quantity set as 0
    :return: None
    """
    unique_countries = {
        "Ethiopia": 0
    }
    continents = GrinderContinents.convert_continents(
        unique_countries=unique_countries
    )
    assert continents == {}


def test_continents_wrong_object() -> None:
    """
    Check behavior when not iterable or even
    another type object passed as argument
    to continents function. Normally in this
    case we will raise appropriate exception.
    :return: None
    """
    with raises(GrinderContinentsConvertError) as wrong_obj_err:
        GrinderContinents.convert_continents(unique_countries=None)
