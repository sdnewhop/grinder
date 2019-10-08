#!/usr/bin/env python3

from pathlib import Path
from grinder.core import GrinderCore
from tests.conftest import options


class TestCoreDefaultValues:
    TEST_QUERIES_PATH = Path(".").joinpath("test_data").joinpath("test_queries")
    EMPTY_ALL_FIELDS_QUERIES_PATH = TEST_QUERIES_PATH.joinpath(
        "empty_all_fields_queries.json"
    )
    EMPTY_CENSYS_QUERIES_PATH = TEST_QUERIES_PATH.joinpath("empty_censys_queries.json")
    EMPTY_ENTITY_QUERIES_PATH = TEST_QUERIES_PATH.joinpath("empty_entity_queries.json")
    EMPTY_FILE_QUERIES_PATH = TEST_QUERIES_PATH.joinpath("empty_file_queries.json")
    EMPTY_LIST_QUERIES_PATH = TEST_QUERIES_PATH.joinpath("empty_list_queries.json")
    EMPTY_PRODUCT_QUERIES_PATH = TEST_QUERIES_PATH.joinpath(
        "empty_product_queries.json"
    )
    EMPTY_QUERY_CONFIDENCE_PATH = TEST_QUERIES_PATH.joinpath(
        "empty_query_confidence_queries.json"
    )
    EMPTY_QUERY_FIELD_QUERIES_PATH = TEST_QUERIES_PATH.joinpath(
        "empty_query_field_queries.json"
    )
    EMPTY_SCRIPTS_QUERIES_PATH = TEST_QUERIES_PATH.joinpath(
        "empty_scripts_queries.json"
    )
    EMPTY_SHODAN_QUERIES_PATH = TEST_QUERIES_PATH.joinpath("empty_shodan_queries.json")
    EMPTY_VENDOR_CONFIDENCE_QUERIES_PATH = TEST_QUERIES_PATH.joinpath(
        "empty_vendor_confidence_queries.json"
    )
    EMPTY_VENDOR_QUERIES_PATH = TEST_QUERIES_PATH.joinpath("empty_vendor_queries.json")
    NO_ENTITIES_QUERIES_PATH = TEST_QUERIES_PATH.joinpath("no_entities_queries.json")
    NOT_LIST_QUERIES_PATH = TEST_QUERIES_PATH.joinpath("not_list_queries.json")
    WRONG_QUERY_CONFIDENCE_QUERIES_PATH = TEST_QUERIES_PATH.joinpath(
        "wrong_query_confidence_queries.json"
    )
    WRONG_VENDOR_CONFIDENCE_QUERIES_PATH = TEST_QUERIES_PATH.joinpath(
        "wrong_vendor_confidence_queries.json"
    )


def setup_module() -> None:
    """
    Initialize Grinder core
    :return: None
    """
    global grinder_core
    grinder_core = GrinderCore(
        shodan_api_key=options.shodan_key,
        censys_api_id=options.censys_id,
        censys_api_secret=options.censys_secret,
        vulners_api_key=options.vulners_key,
    )


def test_empty_all_fields_queries() -> None:
    """
    Test case when all fields of entity in query file
    are empty
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.EMPTY_ALL_FIELDS_QUERIES_PATH,
        not_incremental=True,
    )


def test_empty_censys_queries() -> None:
    """
    Test case when Censys queries are null
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.EMPTY_CENSYS_QUERIES_PATH,
        not_incremental=True,
    )


def test_empty_entity_queries() -> None:
    """
    Test case when entity in list is empty
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.EMPTY_ENTITY_QUERIES_PATH,
        not_incremental=True,
    )


def test_empty_file_queries() -> None:
    """
    Test case when input file is empty
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.EMPTY_FILE_QUERIES_PATH,
        not_incremental=True,
    )


def test_empty_list_queries() -> None:
    """
    Test case when input list in file is empty
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.EMPTY_LIST_QUERIES_PATH,
        not_incremental=True,
    )


def test_empty_product_queries() -> None:
    """
    Test case when entity got empty product field
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.EMPTY_PRODUCT_QUERIES_PATH,
        not_incremental=True,
    )


def test_empty_query_confidence() -> None:
    """
    Test case when query confidence is empty
    :return: None
    """
    for possible_query_confidence in [
        "certain",
        "firm",
        "tentative",
        "CERTAIN",
        "FIRM",
        "TENTATIVE",
        "WRONG",
        "EMPTY",
        None,
    ]:
        grinder_core.set_query_confidence(possible_query_confidence)
        grinder_core.batch_search(
            queries_filename=TestCoreDefaultValues.EMPTY_QUERY_CONFIDENCE_PATH,
            not_incremental=True,
        )


def test_empty_query_field_queries() -> None:
    """
    Test case when query field is empty (null)
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.EMPTY_QUERY_FIELD_QUERIES_PATH,
        not_incremental=True,
    )


def test_empty_scripts_queries() -> None:
    """
    Test case when scripts field is empty
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.EMPTY_SCRIPTS_QUERIES_PATH,
        not_incremental=True,
    )


def test_empty_shodan_queries() -> None:
    """
    Test case when shodan queries are empty
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.EMPTY_SHODAN_QUERIES_PATH,
        not_incremental=True,
    )


def test_empty_vendor_confidence_queries() -> None:
    """
    Test case when vendor confidence level is empty
    :return: None
    """
    for possible_vendor_confidence in [
        "certain",
        "firm",
        "tentative",
        "CERTAIN",
        "FIRM",
        "TENTATIVE",
        "WRONG",
        "EMPTY",
        None,
    ]:
        print("CONFIDENCE IS", possible_vendor_confidence)
        grinder_core.set_vendor_confidence(possible_vendor_confidence)
        grinder_core.batch_search(
            queries_filename=TestCoreDefaultValues.EMPTY_VENDOR_CONFIDENCE_QUERIES_PATH,
            not_incremental=True,
        )


def test_empty_vendor_queries() -> None:
    """
    Test case when vendor is null
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.EMPTY_VENDOR_QUERIES_PATH,
        not_incremental=True,
    )


def test_no_entities_queries() -> None:
    """
    Test case when no entities in list
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.NO_ENTITIES_QUERIES_PATH,
        not_incremental=True,
    )


def test_not_list_queries() -> None:
    """
    Test case when queries is wrong type json, not list
    :return: None
    """
    grinder_core.batch_search(
        queries_filename=TestCoreDefaultValues.NOT_LIST_QUERIES_PATH,
        not_incremental=True,
    )


def test_wrong_query_confidence_queries() -> None:
    """
    Test case when wrong query confidence was set in file
    :return: None
    """
    for possible_query_confidence in [
        "certain",
        "firm",
        "tentative",
        "CERTAIN",
        "FIRM",
        "TENTATIVE",
        "WRONG",
        "EMPTY",
        None,
    ]:
        grinder_core.set_query_confidence(possible_query_confidence)
        grinder_core.batch_search(
            queries_filename=TestCoreDefaultValues.WRONG_QUERY_CONFIDENCE_QUERIES_PATH,
            not_incremental=True,
        )


def test_wrong_vendor_confidence_queries() -> None:
    """
    Test case when wrong vendor confidence was set in file
    :return: None
    """
    for possible_vendor_confidence in [
        "certain",
        "firm",
        "tentative",
        "CERTAIN",
        "FIRM",
        "TENTATIVE",
        "WRONG",
        "EMPTY",
        None,
    ]:
        grinder_core.set_vendor_confidence(possible_vendor_confidence)
        grinder_core.batch_search(
            queries_filename=TestCoreDefaultValues.WRONG_VENDOR_CONFIDENCE_QUERIES_PATH,
            not_incremental=True,
        )
