#!/usr/bin/env python3

import sqlite3
from datetime import datetime
from json import dumps as json_dumps
from json import loads as json_loads

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultDatabaseValues
from grinder.errors import (
    GrinderDatabaseOpenError,
    GrinderDatabaseCreateError,
    GrinderDatabaseInitialScanError,
    GrinderDatabaseAddScanDataError,
    GrinderDatabaseCloseError,
    GrinderDatabaseUpdateTimeError,
    GrinderDatabaseLoadResultsError,
    GrinderDatabaseUpdateResultsCountError,
    GrinderDatabaseAddBasicScanDataError,
)


class GrinderDatabase:
    @exception_handler(expected_exception=GrinderDatabaseOpenError)
    def __init__(self, db_name: str = ""):
        """
        Initialize sqlite3 database to work with. Turn on
        foreign keys to make linked tables with scan info.

        :param db_name: name of database file
        """
        self.connection = sqlite3.connect(db_name or DefaultDatabaseValues.DB_NAME)
        self.connection.execute("PRAGMA foreign_keys = ON")

        self.scan_name = None
        self.scan_date = None
        self.scan_start_time = None
        self.scan_end_time = None
        self.scan_duration = None

    @exception_handler(expected_exception=GrinderDatabaseCreateError)
    def create_db(self) -> None:
        """
        Create necessary tables. For example, basically
        we need next tables:
        - scan_information - basic table with all main information about scan
        - scan_data - information about product, vendor, script running and confidence
        - shodan_results/censys_results - for results from backend search engines
        - masscan_results - for results from masscan scan
        :return: None
        """
        with self.connection as db_connection:
            db_connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                scan_information(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_name TEXT,
                    scan_date TEXT,
                    scan_start_time TEXT,
                    scan_end_time TEXT,
                    scan_duration TEXT,
                    scan_total_products INT,
                    scan_total_results INT
                )
                """
            )
            db_connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                scan_data(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_information_id INTEGER,
                    vendor TEXT,
                    product TEXT,
                    script TEXT,
                    vendor_confidence TEXT,

                    FOREIGN KEY (scan_information_id) REFERENCES scan_information(id)
                )
                """
            )
            db_connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                shodan_results(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_data_id INTEGER,
                    scan_information_id INTEGER,
                    query TEXT,
                    query_confidence TEXT,
                    results_count INTEGER,
                    results TEXT,

                    FOREIGN KEY (scan_data_id) REFERENCES scan_data(id),
                    FOREIGN KEY (scan_information_id) REFERENCES scan_information(id)
                )
                """
            )
            db_connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                censys_results(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_data_id INTEGER,
                    scan_information_id INTEGER,
                    query TEXT,
                    query_confidence TEXT,
                    results_count INTEGER,
                    results TEXT,

                    FOREIGN KEY (scan_data_id) REFERENCES scan_data(id),
                    FOREIGN KEY (scan_information_id) REFERENCES scan_information(id)
                )
                """
            )
            db_connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                masscan_results(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_data_id INTEGER,
                    scan_information_id INTEGER,
                    query TEXT,
                    query_confidence TEXT,
                    results_count INTEGER,
                    results TEXT,

                    FOREIGN KEY (scan_data_id) REFERENCES scan_data(id),
                    FOREIGN KEY (scan_information_id) REFERENCES scan_information(id)
                )
                """
            )

    @exception_handler(expected_exception=GrinderDatabaseInitialScanError)
    def initiate_scan(self, queries_filename: str) -> None:
        """
        Start scan and initialize start values. For example,
        we need to save scan date, scan time and name of the
        scan to load this results again after a while
        with a new scan (incremental scanning)
        :param queries_filename: filename in format like "servers", "sd-wans"
        :return: None
        """
        self.scan_date = datetime.today().strftime("%Y-%m-%d")
        self.scan_start_time = datetime.now()
        self.scan_name = queries_filename

        with self.connection as db_connection:
            db_connection.execute(
                """
                INSERT OR REPLACE INTO
                scan_information(
                    scan_date,
                    scan_start_time,
                    scan_name
                ) VALUES (?, ?, ?)
                """,
                (
                    str(self.scan_date),
                    str(self.scan_start_time.time().strftime("%H:%M:%S")),
                    str(self.scan_name),
                ),
            )

    def set_scan_name(self, queries_filename: str) -> None:
        """

        :param queries_filename:
        :return:
        """
        self.scan_name = queries_filename

    @exception_handler(expected_exception=GrinderDatabaseUpdateTimeError)
    def update_end_time(self) -> None:
        """
        Update end scanning variables. For example, end
        of scanning time, and scan duration.
        :return: None
        """
        try:
            self.scan_end_time = datetime.now()
            self.scan_duration = self.scan_end_time - self.scan_start_time
        # Case when we try to update end time without start time is possible:
        # for example, we still can call save to database handler
        # if some error happened
        except TypeError as scan_wasnt_initialized:
            return
        with self.connection as db_connection:
            db_connection.execute(
                """
                UPDATE scan_information
                    SET scan_end_time = ?,
                        scan_duration = ?
                    WHERE id = (
                        SELECT max(id) FROM scan_information
                    )
                """,
                (
                    str(self.scan_end_time.time().strftime("%H:%M:%S")),
                    str(self.scan_duration),
                ),
            )

    @exception_handler(expected_exception=GrinderDatabaseUpdateResultsCountError)
    def update_results_count(self, total_products: int, total_results: int) -> None:
        """
        Update results count, total results and total
        scanned products.
        :param total_products: total quantity of products
        :param total_results: total quantity of results
        :return: None
        """
        with self.connection as db_connection:
            db_connection.execute(
                """
                UPDATE scan_information
                    SET scan_total_products = ?,
                        scan_total_results = ?
                    WHERE id = (
                        SELECT max(id) FROM scan_information
                    )
                """,
                (
                    total_products,
                    total_results
                ),
            )

    @exception_handler(expected_exception=GrinderDatabaseAddBasicScanDataError)
    def add_basic_scan_data(
        self, vendor: str, product: str, script: str, vendor_confidence: str
    ) -> None:
        """
        Add scan data information for current product, vendor
        :param vendor: vendor name, like "Cisco"
        :param product: product name, like "LinkSys"
        :param script: script that need to be runned, empty if none
        :param vendor_confidence: confidence of vendor - certain, firm, tentative
        :return: None
        """
        with self.connection as db_connection:
            db_connection.execute(
                """
                INSERT OR REPLACE INTO
                scan_data(
                    scan_information_id,
                    vendor,
                    product,
                    script,
                    vendor_confidence
                ) VALUES (
                    (SELECT max(id) FROM scan_information),
                    ?, ?, ?, ?)
                """,
                (
                    vendor,
                    product,
                    script,
                    vendor_confidence
                ),
            )

    @exception_handler(expected_exception=GrinderDatabaseAddScanDataError)
    def add_shodan_scan_data(
        self, query: dict, results_count: int, results: dict or list
    ) -> None:
        """
        Add results from shodan for current query
        :param query: result for current query
        :param results_count: quantity of results
        :param results: results itself
        :return: None
        """
        with self.connection as db_connection:
            db_connection.execute(
                """
                INSERT OR REPLACE INTO
                shodan_results(
                    scan_data_id,
                    scan_information_id,
                    query,
                    query_confidence,
                    results_count,
                    results
                ) VALUES (
                    (SELECT max(id) FROM scan_data),
                    (SELECT max(id) FROM scan_information),
                    ?,
                    ?,
                    ?,
                    json(?)
                )
                """,
                (
                    query.get("query"),
                    query.get("query_confidence"),
                    results_count,
                    json_dumps(results),
                ),
            )

    @exception_handler(expected_exception=GrinderDatabaseAddScanDataError)
    def add_censys_scan_data(
        self, query: dict, results_count: int, results: dict or list
    ) -> None:
        """
        Add results from censys for current query
        :param query: result for current query
        :param results_count: quantity of results
        :param results: results itself
        :return: None
        """
        with self.connection as db_connection:
            db_connection.execute(
                """
                INSERT OR REPLACE INTO
                censys_results(
                    scan_data_id,
                    scan_information_id,
                    query,
                    query_confidence,
                    results_count,
                    results
                ) VALUES (
                    (SELECT max(id) FROM scan_data),
                    (SELECT max(id) FROM scan_information),
                    ?,
                    ?,
                    ?,
                    json(?)
                )
                """,
                (
                    query.get("query"),
                    query.get("query_confidence"),
                    results_count,
                    json_dumps(results),
                ),
            )

    @exception_handler(expected_exception=GrinderDatabaseAddScanDataError)
    def add_masscan_scan_data(
        self, query: dict, results_count: int, results: dict or list
    ) -> None:
        """
        Add results from masscan for current query
        :param query: result for current query
        :param results_count: quantity of results
        :param results: results itself
        :return: None
        """
        with self.connection as db_connection:
            db_connection.execute(
                """
                INSERT OR REPLACE INTO
                masscan_results(
                    scan_data_id,
                    scan_information_id,
                    query,
                    query_confidence,
                    results_count,
                    results
                ) VALUES (
                    (SELECT max(id) FROM scan_data),
                    (SELECT max(id) FROM scan_information),
                    ?,
                    ?,
                    ?,
                    json(?)
                )
                """,
                (
                    query.get("hosts"),
                    query.get("query_confidence"),
                    results_count,
                    json_dumps(results),
                ),
            )

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_last_results(self) -> dict:
        """
        Load latest scan results from database, without scan linking.
        This function collects last result from censys scan, last
        result from shodan scan and last result from masscan scan,
        and combine it together with union select. Needed if you
        only need to load any last results combination.
        :return: dict with results
        """
        with self.connection as db_connection:
            sql_results = db_connection.execute(
                """
                SELECT json_extract(results, '$')
                FROM shodan_results
                WHERE scan_information_id = (
                    SELECT max(id) FROM scan_information
                    WHERE scan_total_results != 0
                )
                UNION SELECT json_extract(results, '$')
                FROM censys_results
                WHERE scan_information_id = (
                    SELECT max(id) FROM scan_information
                    WHERE scan_total_results != 0
                )
                UNION SELECT json_extract(results, '$')
                FROM masscan_results
                WHERE scan_information_id = (
                    SELECT max(id) FROM scan_information
                    WHERE scan_total_results != 0
                )
                """
            ).fetchall()
            if not sql_results:
                return {}
            results_parsed = [json_loads(item[0]) for item in sql_results]
            results_combined = [
                result for query_result in results_parsed for result in query_result
            ]
            return {host.get("ip"): host for host in results_combined}

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_last_results_by_name(self, engine_table: str, scan_name: str = "") -> dict:
        """
        Load last results with some particular scan that can be
        passed via 'scan_name' variable. This function returns results
        only from one backend system (censys, shodan, masscan) at time,
        and only the latest _one_.
        If 'scan_name' is not setted, any last result from
        censys or shodan scan will be loaded.
        :param engine_table: shodan_results, censys_results, masscan_results, etc.
        :param scan_name: name of scanning - "servers", "sd-wans", etc.
        :return: dict with results
        """
        if scan_name:
            scan_name = f"AND scan_name = \"{scan_name}\""
        try:
            with self.connection as db_connection:
                sql_results = db_connection.execute(
                    """
                    SELECT json_extract(results, '$')
                    FROM {engine_table_fill}
                    WHERE scan_information_id = (
                        SELECT max(id) FROM scan_information
                        WHERE scan_total_results != 0
                        {scan_name_fill}
                    )
                    """.format(engine_table_fill=engine_table, scan_name_fill=scan_name or "")
                ).fetchall()
                if not sql_results:
                    return {}
                results_parsed = [json_loads(item[0]) for item in sql_results]
                results_combined = [
                    result for query_result in results_parsed for result in query_result
                ]
                return {host.get("ip"): host for host in results_combined}
        except sqlite3.OperationalError:
            return {}

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_all_results_by_name(self, engine_table: str, scan_name: str = "") -> dict:
        """
        Load collection of all results from one backend system (censys, shodan,
        masscan). For example, you can load all records from Shodan with
        'servers' scan, and this function will sort only unique hosts from
        all of the history of 'servers' scanning
        :param engine_table: shodan_results, censys_results, etc.
        :param scan_name: name of scanning - "servers", "sd-wans", etc.
        :return: dict with results
        """
        if scan_name:
            scan_name = f"AND scan_table.scan_name = \"{scan_name}\""
        with self.connection as db_connection:
            sql_results = db_connection.execute(
                """
                SELECT json_extract(results, '$')
                FROM {engine_table_fill} res_table
                JOIN scan_information scan_table
                WHERE scan_table.id = res_table.scan_information_id 
                {scan_name_fill}
                AND results != '[]'
                """.format(engine_table_fill=engine_table, scan_name_fill=scan_name or "")
            ).fetchall()
            if not sql_results:
                return {}
            results_parsed = [json_loads(item[0]) for item in sql_results]
            results_combined = [
                result for query_result in results_parsed for result in query_result
            ]
            final_results = {}
            for host in results_combined:
                if host.get("ip") in final_results.keys():
                    continue
                final_results.update({host.get("ip"): host})
            return final_results

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_multiple_last_results_by_name(self) -> dict:
        """
        Load last results with some 'scan_name' from multiple
        backend systems (shodan + censys + masscan at once). This function
        sort all of the host into one dictionary and returns
        unique results from last scan of some 'scan_name'
        :return: dictionary with all results, like "combined" results
        """
        shodan_results = self.load_last_results_by_name(engine_table="shodan_results", scan_name=self.scan_name)
        censys_results = self.load_last_results_by_name(engine_table="censys_results", scan_name=self.scan_name)
        masscan_results = self.load_last_results_by_name(engine_table="masscan_results", scan_name=self.scan_name)
        return {**shodan_results, **censys_results, **masscan_results}

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_last_shodan_results(self) -> dict:
        """
        Return latest results from shodan only
        :return: dict with shodan results
        """
        return self.load_last_results_by_name(engine_table="shodan_results")

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_last_censys_results(self) -> dict:
        """
        Return latest results from censys only
        :return: dict with censys results
        """
        return self.load_last_results_by_name(engine_table="censys_results")

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_last_masscan_results(self) -> dict:
        """
        Return latest results from masscan only
        :return: dict with masscan results
        """
        return self.load_last_results_by_name(engine_table="masscan_results")

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_last_shodan_results_by_scan_name(self) -> dict:
        """
        Return latest shodan results by some scan name (filename.json)
        :return: dict with results by name
        """
        return self.load_last_results_by_name(engine_table="shodan_results", scan_name=self.scan_name)

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_last_censys_results_by_scan_name(self) -> dict:
        """
        Return latest censys results by some scan name (filename.json)
        :return: dict with results by name
        """
        return self.load_last_results_by_name(engine_table="censys_results", scan_name=self.scan_name)

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_last_masscan_results_by_scan_name(self) -> dict:
        """
        Return latest masscan results by some scan name (filename.json)
        :return: dict with results by name
        """
        return self.load_last_results_by_name(engine_table="masscan_results", scan_name=self.scan_name)

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_all_shodan_results_by_scan_name(self) -> dict:
        """
        Return all combined shodan results by some scan name (filename.json)
        :return: dict with results by name
        """
        return self.load_all_results_by_name(engine_table="shodan_results", scan_name=self.scan_name)

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_all_censys_results_by_scan_name(self) -> dict:
        """
        Return all combined censys results by some scan name (filename.json)
        :return: dict with results by name
        """
        return self.load_all_results_by_name(engine_table="censys_results", scan_name=self.scan_name)

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_all_masscan_results_by_scan_name(self) -> dict:
        """
        Return all combined masscan results by some scan name (filename.json)
        :return: dict with results by name
        """
        return self.load_all_results_by_name(engine_table="masscan_results", scan_name=self.scan_name)

    @exception_handler(expected_exception=GrinderDatabaseCloseError)
    def close(self) -> None:
        """
        Close database forced
        :return: None
        """
        self.connection.close()

    def __del__(self):
        """
        Check if attribute is available and close db
        :return:
        """
        if hasattr(self, "connection"):
            self.connection.close()
