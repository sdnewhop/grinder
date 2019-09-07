#!/usr/bin/env python3
from pytest import fixture, raises
from sqlite3 import connect
from sqlite3 import Connection as Connection_instance
from pathlib import Path

from grinder.dbhandling import GrinderDatabase
from grinder.errors import (
    GrinderDatabaseException,
    GrinderDatabaseOpenError,
    GrinderDatabaseCreateError,
    GrinderDatabaseInitialScanError,
    GrinderDatabaseUpdateTimeError,
    GrinderDatabaseUpdateResultsCountError,
    GrinderDatabaseAddBasicScanDataError,
    GrinderDatabaseAddScanDataError,
    GrinderDatabaseLoadResultsError,
)


class TestDatabaseValues:
    """
    Default database values for tests
    """

    TEST_DB_NAME = "test.db"


def setup_module() -> None:
    """
    Initialize database for tests
    :return: None
    """
    global db
    db = GrinderDatabase(db_name=TestDatabaseValues.TEST_DB_NAME)
    db.create_db()


@fixture
def connection() -> Connection_instance:
    """
    Create connection fixture to execute commands
    :return: Connection object of sqlite
    """
    connection = connect(TestDatabaseValues.TEST_DB_NAME)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def test_database_open_error() -> None:
    """
    Test if init function of GrinderDatabase
    raise exception properly
    :return: None
    """

    def raise_open_error():
        GrinderDatabase(
            db_name=Path(".")
            .joinpath("not_existing_path")
            .joinpath("not_existing_db.db")
        )

    with raises(GrinderDatabaseOpenError):
        raise_open_error()
    with raises(GrinderDatabaseException):
        raise_open_error()


def test_connection_fixture_instance(connection: Connection_instance) -> None:
    """
    Check if instance of connection is properly set.
    :param connection: sqlite3.Connection object
    :return: None
    """
    assert isinstance(connection, Connection_instance)


def test_pragma_foreign_keys(connection: Connection_instance):
    """
    Check if PRAGMA foreign keys is properly associated with
    current connection
    :param connection: sqlite3.Connection object
    :return: None
    """
    with connection:
        assert connection.execute("PRAGMA foreign_keys").fetchall() == [(1,)]


def test_database_existing_tables(connection: Connection_instance) -> None:
    """
    Check tables that currently exists
    in database (after creating)
    :param connection: sqlite3.Connection object
    :return: None
    """
    assert sorted(
        connection.execute("SELECT name FROM sqlite_master").fetchall()
    ) == sorted(
        [
            ("sqlite_sequence",),
            ("scan_information",),
            ("scan_data",),
            ("shodan_results",),
            ("censys_results",),
        ]
    )


def test_database_existing_scan_information_columns(
    connection: Connection_instance
) -> None:
    """
    Check column names of 'scan_information' table
    :param connection: sqlite3.Connection object
    :return: None
    """
    assert sorted(
        connection.execute("PRAGMA table_info(scan_information)").fetchall()
    ) == sorted(
        [
            (0, "id", "INTEGER", 0, None, 1),
            (1, "scan_name", "TEXT", 0, None, 0),
            (2, "scan_date", "TEXT", 0, None, 0),
            (3, "scan_start_time", "TEXT", 0, None, 0),
            (4, "scan_end_time", "TEXT", 0, None, 0),
            (5, "scan_duration", "TEXT", 0, None, 0),
            (6, "scan_total_products", "INT", 0, None, 0),
            (7, "scan_total_results", "INT", 0, None, 0),
        ]
    )


def test_database_existing_scan_data_columns(connection: Connection_instance) -> None:
    """
    Check column names of 'scan_data' table
    :param connection: sqlite3.Connection object
    :return: None
    """
    assert sorted(
        connection.execute("PRAGMA table_info(scan_data)").fetchall()
    ) == sorted(
        [
            (0, "id", "INTEGER", 0, None, 1),
            (1, "scan_information_id", "INTEGER", 0, None, 0),
            (2, "vendor", "TEXT", 0, None, 0),
            (3, "product", "TEXT", 0, None, 0),
            (4, "script", "TEXT", 0, None, 0),
            (5, "vendor_confidence", "TEXT", 0, None, 0),
        ]
    )


def test_database_existing_shodan_results_columns(
    connection: Connection_instance
) -> None:
    """
    Check column names of 'shodan_results' table
    :param connection: sqlite3.Connection object
    :return: None
    """
    assert sorted(
        connection.execute("PRAGMA table_info(shodan_results)").fetchall()
    ) == sorted(
        [
            (0, "id", "INTEGER", 0, None, 1),
            (1, "scan_data_id", "INTEGER", 0, None, 0),
            (2, "scan_information_id", "INTEGER", 0, None, 0),
            (3, "query", "TEXT", 0, None, 0),
            (4, "query_confidence", "TEXT", 0, None, 0),
            (5, "results_count", "INTEGER", 0, None, 0),
            (6, "results", "TEXT", 0, None, 0),
        ]
    )


def test_database_existing_censys_results_columns(
    connection: Connection_instance
) -> None:
    """
    Check column names of 'censys_results' table
    :param connection: sqlite3.Connection object
    :return: None
    """
    assert sorted(
        connection.execute("PRAGMA table_info(censys_results)").fetchall()
    ) == sorted(
        [
            (0, "id", "INTEGER", 0, None, 1),
            (1, "scan_data_id", "INTEGER", 0, None, 0),
            (2, "scan_information_id", "INTEGER", 0, None, 0),
            (3, "query", "TEXT", 0, None, 0),
            (4, "query_confidence", "TEXT", 0, None, 0),
            (5, "results_count", "INTEGER", 0, None, 0),
            (6, "results", "TEXT", 0, None, 0),
        ]
    )


def test_create_database_error() -> None:
    """
    Check if database creating will fail
    with proper exception in case when
    connection is None
    :return: None
    """
    connection_backup = db.connection
    db.connection = None
    with raises(GrinderDatabaseCreateError):
        db.create_db()
    with raises(GrinderDatabaseException):
        db.create_db()
    db.connection = connection_backup


def test_initiate_scan_error() -> None:
    """
    Check if database initiate scan function
    will fail with proper exception in case
    when connection is None
    :return: None
    """
    connection_backup = db.connection
    db.connection = None
    with raises(GrinderDatabaseInitialScanError):
        db.initiate_scan(queries_filename="")
    with raises(GrinderDatabaseException):
        db.initiate_scan(queries_filename="")
    db.connection = connection_backup


def test_initiate_scan_success(connection: Connection_instance) -> None:
    """
    Check if database initiate scan process
    is successfully finished
    :param connection: sqlite3.Connection object
    :return: None
    """
    db.initiate_scan(queries_filename="pytest")
    scan_initiate_info = connection.execute(
        """
        SELECT * FROM scan_information 
        WHERE scan_information.id = (
            SELECT max(id) 
            FROM scan_information
        )
        """
    ).fetchall()
    scan_initiate_row = scan_initiate_info[0]
    assert isinstance(scan_initiate_row[0], int)
    assert isinstance(scan_initiate_row[1], str)
    assert scan_initiate_row[1] == db.scan_name
    assert isinstance(scan_initiate_row[2], str)
    assert scan_initiate_row[2] == str(db.scan_date)
    assert isinstance(scan_initiate_row[3], str)
    assert scan_initiate_row[3] == str(db.scan_start_time.time().strftime("%H:%M:%S"))
    for i in range(4, 8):
        assert scan_initiate_row[i] is None


def test_update_end_time_error(connection: Connection_instance) -> None:
    """
    Check if database process of current scan
    time updating is properly handled when
    error is coming
    :param connection: sqlite3.Connection object
    :return: None
    """
    connection_backup = db.connection
    db.connection = None
    with raises(GrinderDatabaseUpdateTimeError):
        db.update_end_time()
    with raises(GrinderDatabaseException):
        db.update_end_time()
    db.connection = connection_backup


def test_update_end_time_success(connection: Connection_instance) -> None:
    """
    Check if end time of scanning is successfully updated
    :param connection: sqlite3.Connection object
    :return: None
    """
    db.update_end_time()
    end_time_values = connection.execute(
        """
        SELECT * FROM scan_information 
        WHERE scan_information.id = (
            SELECT max(id) 
            FROM scan_information
        )
        """
    ).fetchall()
    end_time, end_duration = end_time_values[0][4:6]
    assert end_time == str(db.scan_end_time.time().strftime("%H:%M:%S"))
    assert end_duration == str(db.scan_duration)


def test_update_results_count_error(connection: Connection_instance) -> None:
    """
    Update last scan results count - check for
    properly error handling
    :param connection: sqlite3.Connection object
    :return: None
    """
    connection_backup = db.connection
    db.connection = None
    with raises(GrinderDatabaseUpdateResultsCountError):
        db.update_results_count()
    with raises(GrinderDatabaseException):
        db.update_results_count()
    db.connection = connection_backup


def test_update_results_count_success(connection: Connection_instance) -> None:
    """
    Update last scan results count - check if values
    are properly set
    :param connection: sqlite3.Connection object
    :return: None
    """
    db.update_results_count(total_products=42, total_results=1337)
    end_results_values = connection.execute(
        """
        SELECT * FROM scan_information 
        WHERE scan_information.id = (
            SELECT max(id) 
            FROM scan_information
        )
        """
    ).fetchall()
    total_products, total_results = end_results_values[0][6:]
    assert total_products == 42
    assert total_results == 1337


def test_add_basic_scan_data_error(connection: Connection_instance) -> None:
    """
    Test scan data adding with error handling
    :param connection: sqlite3.Connection object
    :return: None
    """
    connection_backup = db.connection
    db.connection = None

    def add_scan_data():
        db.add_basic_scan_data(
            vendor="pytest_vendor",
            product="pytest_product",
            script="pytest_script",
            vendor_confidence="pytest_confidence",
        )

    with raises(GrinderDatabaseAddBasicScanDataError):
        add_scan_data()
    with raises(GrinderDatabaseException):
        add_scan_data()
    db.connection = connection_backup


def test_add_basic_scan_data_success(connection: Connection_instance) -> None:
    """
    Test basic scan data adding without errors
    :param connection: sqlite3.Connection object
    :return: None
    """
    db.add_basic_scan_data(
        vendor="pytest_vendor",
        product="pytest_product",
        script="pytest_script",
        vendor_confidence="pytest_confidence",
    )
    scan_data_results = connection.execute(
        """
        SELECT * FROM scan_data 
        WHERE id = (
            SELECT max(id) 
            FROM scan_data
        )
        """
    ).fetchall()[0]
    assert isinstance(scan_data_results[0], int)
    assert isinstance(scan_data_results[1], int)
    assert scan_data_results[2] == "pytest_vendor"
    assert scan_data_results[3] == "pytest_product"
    assert scan_data_results[4] == "pytest_script"
    assert scan_data_results[5] == "pytest_confidence"


def test_add_shodan_scan_data_error(connection: Connection_instance) -> None:
    """
    Check adding of shodan scan data result with error handling
    :param connection: sqlite3.Connection object
    :return: None
    """
    connection_backup = db.connection
    db.connection = None

    def add_scan_data():
        db.add_shodan_scan_data(
            query={"query": "pyquery", "query_confidence": "pyconfidence"},
            results_count=1234,
            results=[{"pykey": "pyvalue"}],
        )

    with raises(GrinderDatabaseAddScanDataError):
        add_scan_data()
    with raises(GrinderDatabaseException):
        add_scan_data()
    db.connection = connection_backup


def test_add_shodan_scan_data_success(connection: Connection_instance) -> None:
    """
    Check if we can successfully put shodan results into database
    :param connection: sqlite3.Connection object
    :return: None
    """
    db.add_shodan_scan_data(
        query={"query": "pyquery", "query_confidence": "pyconfidence"},
        results_count=1234,
        results=[{"ip": "pyvalue"}],
    )
    shodan_data_results = connection.execute(
        """
        SELECT * FROM shodan_results 
        WHERE id = (
            SELECT max(id) 
            FROM shodan_results
        )
        """
    ).fetchall()[0]
    assert isinstance(shodan_data_results[0], int)
    assert isinstance(shodan_data_results[1], int)
    assert isinstance(shodan_data_results[2], int)
    assert shodan_data_results[3] == "pyquery"
    assert shodan_data_results[4] == "pyconfidence"
    assert shodan_data_results[5] == 1234
    assert shodan_data_results[6] == '[{"ip":"pyvalue"}]'


def test_add_censys_scan_data_error(connection: Connection_instance) -> None:
    """
    Check adding of censys scan data result with error handling
    :param connection: sqlite3.Connection object
    :return: None
    """
    connection_backup = db.connection
    db.connection = None

    def add_scan_data():
        db.add_censys_scan_data(
            query={"query": "pyquery", "query_confidence": "pyconfidence"},
            results_count=1234,
            results=[{"pykey": "pyvalue"}],
        )

    with raises(GrinderDatabaseAddScanDataError):
        add_scan_data()
    with raises(GrinderDatabaseException):
        add_scan_data()
    db.connection = connection_backup


def test_add_censys_scan_data_success(connection: Connection_instance) -> None:
    """
    Check if we can successfully put shodan results into database
    :param connection: sqlite3.Connection object
    :return: None
    """
    db.add_censys_scan_data(
        query={"query": "pyquery", "query_confidence": "pyconfidence"},
        results_count=1234,
        results=[{"ip": "pyvalue"}],
    )
    shodan_data_results = connection.execute(
        """
        SELECT * FROM censys_results 
        WHERE id = (
            SELECT max(id) 
            FROM censys_results
        )
        """
    ).fetchall()[0]
    assert isinstance(shodan_data_results[0], int)
    assert isinstance(shodan_data_results[1], int)
    assert isinstance(shodan_data_results[2], int)
    assert shodan_data_results[3] == "pyquery"
    assert shodan_data_results[4] == "pyconfidence"
    assert shodan_data_results[5] == 1234
    assert shodan_data_results[6] == '[{"ip":"pyvalue"}]'


def test_load_last_results_error() -> None:
    """
    Check if exceptions correctly handled with
    load last results function
    :return: None
    """
    connection_backup = db.connection
    db.connection = None

    with raises(GrinderDatabaseLoadResultsError):
        db.load_last_results()
    with raises(GrinderDatabaseException):
        db.load_last_results()
    db.connection = connection_backup


def test_load_last_results_success() -> None:
    """
    Check if last results from database
    were successfully loaded
    :return: None
    """
    assert db.load_last_results() == {"pyvalue": {"ip": "pyvalue"}}


def test_load_last_results_by_name_error() -> None:
    """
    Check if exceptions correctly handled with
    load last results by name function
    :return: None
    """
    connection_backup = db.connection
    db.connection = None

    with raises(GrinderDatabaseLoadResultsError):
        db.load_last_results_by_name()
    with raises(GrinderDatabaseException):
        db.load_last_results_by_name()
    db.connection = connection_backup


def test_load_last_results_by_name_success() -> None:
    """
    Check if last results taken from database
    by name is valid
    :return: None
    """
    assert db.load_last_results_by_name(
        scan_name="pytest", engine_table="shodan_results"
    ) == {"pyvalue": {"ip": "pyvalue"}}
    assert db.load_last_results_by_name(
        scan_name="pytest", engine_table="censys_results"
    ) == {"pyvalue": {"ip": "pyvalue"}}
    assert (
        db.load_last_results_by_name(
            scan_name="not_exists", engine_table="censys_results"
        )
        == {}
    )
    assert (
        db.load_last_results_by_name(scan_name="not_exists", engine_table="not_exists")
        == {}
    )


def test_load_all_results_by_name_error() -> None:
    """
    Check if all results taken from database
    are correctly handling in case of error
    :return: None
    """
    connection_backup = db.connection
    db.connection = None

    with raises(GrinderDatabaseLoadResultsError):
        db.load_all_results_by_name()
    with raises(GrinderDatabaseException):
        db.load_last_results_by_name()
    db.connection = connection_backup


def test_load_all_results_by_name_success() -> None:
    """
    Check if we can properly take results of all
    scans from our db
    :return: None
    """
    assert db.load_all_results_by_name(
        scan_name="pytest", engine_table="shodan_results"
    ) == {"pyvalue": {"ip": "pyvalue"}}


def test_load_multiple_last_results_by_name_error() -> None:
    """
    Check if we can handle error in getting
    results for shodan and censys from our database
    :return: None
    """
    connection_backup = db.connection
    db.connection = None

    with raises(GrinderDatabaseLoadResultsError):
        db.load_multiple_last_results_by_name()
    with raises(GrinderDatabaseException):
        db.load_multiple_last_results_by_name()
    db.connection = connection_backup


def test_load_multiple_last_resuls_by_name_success() -> None:
    """
    Check if we can successfully load results
    by name from shodan and censys
    :return: None
    """
    assert db.load_multiple_last_results_by_name() == {"pyvalue": {"ip": "pyvalue"}}


def test_custom_database_getters_handlers_error() -> None:
    """
    Check if all exceptions are correct and handled
    as expected
    :return: None
    """
    possible_functions = [
        db.load_last_shodan_results,
        db.load_last_censys_results,
        db.load_last_shodan_results_by_scan_name,
        db.load_last_censys_results_by_scan_name,
        db.load_all_shodan_results_by_scan_name,
        db.load_all_censys_results_by_scan_name,
    ]
    for function in possible_functions:
        connection_backup = db.connection
        db.connection = None

        with raises(GrinderDatabaseLoadResultsError):
            function()
        with raises(GrinderDatabaseException):
            function()
        db.connection = connection_backup


def test_custom_database_getters_handlers_success() -> None:
    """
    Test different custom functions with predefined values
    :return: None
    """
    expected_dict = {"pyvalue": {"ip": "pyvalue"}}
    assert db.load_last_shodan_results() == expected_dict
    assert db.load_last_censys_results() == expected_dict
    assert db.load_last_shodan_results_by_scan_name() == expected_dict
    assert db.load_last_censys_results_by_scan_name() == expected_dict
    assert db.load_all_shodan_results_by_scan_name() == expected_dict
    assert db.load_all_censys_results_by_scan_name() == expected_dict
