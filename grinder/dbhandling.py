#!/usr/bin/python3

import sqlite3
from datetime import datetime
from json import dumps as json_dumps
from json import loads as json_loads

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultDatabaseValues
from grinder.errors import GrinderDatabaseOpenError, GrinderDatabaseCreateError, GrinderDatabaseInitialScanError, \
    GrinderDatabaseAddScanDataError, GrinderDatabaseCloseError, GrinderDatabaseUpdateTimeError, \
    GrinderDatabaseLoadResultsError, GrinderDatabaseUpdateResultsCountError, GrinderDatabaseAddBasicScanDataError


class GrinderDatabase:
    @exception_handler(expected_exception=GrinderDatabaseOpenError)
    def __init__(self):
        self.connection = sqlite3.connect(DefaultDatabaseValues.DB_NAME)
        self.connection.execute('PRAGMA foreign_keys = ON')

        self.scan_date = None
        self.scan_start_time = None
        self.scan_end_time = None
        self.scan_duration = None

    @exception_handler(expected_exception=GrinderDatabaseCreateError)
    def create_db(self) -> None:
        with self.connection as db_connection:
            db_connection.execute(
                '''
                CREATE TABLE IF NOT EXISTS
                scan_information(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TEXT,
                    scan_start_time TEXT,
                    scan_end_time TEXT,
                    scan_duration TEXT,
                    scan_total_products INT,
                    scan_total_results INT
                )
                '''
            )
            db_connection.execute(
                '''
                CREATE TABLE IF NOT EXISTS
                scan_data(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_information_id INTEGER,
                    vendor TEXT,
                    product TEXT,
                    script TEXT,
                    confidence TEXT,

                    FOREIGN KEY (scan_information_id) REFERENCES scan_information(id)
                )
                '''
            )
            db_connection.execute(
                '''
                CREATE TABLE IF NOT EXISTS
                shodan_results(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_data_id INTEGER,
                    scan_information_id INTEGER,
                    query TEXT,
                    results_count INTEGER,
                    results TEXT,

                    FOREIGN KEY (scan_data_id) REFERENCES scan_data(id),
                    FOREIGN KEY (scan_information_id) REFERENCES scan_information(id)
                )
                '''
            )
            db_connection.execute(
                '''
                CREATE TABLE IF NOT EXISTS
                censys_results(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_data_id INTEGER,
                    scan_information_id INTEGER,
                    query TEXT,
                    results_count INTEGER,
                    results TEXT,

                    FOREIGN KEY (scan_data_id) REFERENCES scan_data(id),
                    FOREIGN KEY (scan_information_id) REFERENCES scan_information(id)
                )
                '''
            )

    @exception_handler(expected_exception=GrinderDatabaseInitialScanError)
    def initiate_scan(self) -> None:
        self.scan_date = datetime.today().strftime('%Y-%m-%d')
        self.scan_start_time = datetime.now()

        with self.connection as db_connection:
            db_connection.execute(
                '''
                INSERT OR REPLACE INTO
                scan_information(
                    scan_date,
                    scan_start_time
                ) VALUES (?, ?)
                ''', (
                    str(self.scan_date),
                    str(self.scan_start_time.time().strftime('%H:%M:%S'))
                )
            )

    @exception_handler(expected_exception=GrinderDatabaseUpdateTimeError)
    def update_end_time(self) -> None:
        self.scan_end_time = datetime.now()
        self.scan_duration = self.scan_end_time - self.scan_start_time
        with self.connection as db_connection:
            current_scan_id = db_connection.execute(
                '''
                SELECT max(id) FROM scan_information
                '''
            ).fetchone()[0]
            db_connection.execute(
                '''
                UPDATE scan_information
                    SET scan_end_time = ?,
                        scan_duration = ?
                    WHERE id = ?
                ''', (
                    str(self.scan_end_time.time().strftime('%H:%M:%S')),
                    str(self.scan_duration),
                    current_scan_id
                )
            )

    @exception_handler(expected_exception=GrinderDatabaseUpdateResultsCountError)
    def update_results_count(self, total_products: int, total_results: int) -> None:
        with self.connection as db_connection:
            current_scan_id = db_connection.execute(
                '''
                SELECT max(id) FROM scan_information
                '''
            ).fetchone()[0]
            db_connection.execute(
                '''
                UPDATE scan_information
                    SET scan_total_products = ?,
                        scan_total_results = ?
                    WHERE id = ?
                ''', (
                    total_products,
                    total_results,
                    current_scan_id
                )
            )

    @exception_handler(expected_exception=GrinderDatabaseAddBasicScanDataError)
    def add_basic_scan_data(self, vendor: str, product: str, script: str, confidence: str) -> None:
        with self.connection as db_connection:
            current_scan_id = db_connection.execute(
                '''
                SELECT max(id) FROM scan_information
                '''
            ).fetchone()[0]
            db_connection.execute(
                '''
                INSERT OR REPLACE INTO
                scan_data(
                    scan_information_id,
                    vendor,
                    product,
                    script,
                    confidence
                ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    current_scan_id,
                    vendor,
                    product,
                    script,
                    confidence
                )
            )

    @exception_handler(expected_exception=GrinderDatabaseAddScanDataError)
    def add_shodan_scan_data(self, query: str, results_count: int, results: dict) -> None:
        with self.connection as db_connection:
            current_scan_id = db_connection.execute(
                '''
                SELECT max(id) FROM scan_information
                '''
            ).fetchone()[0]
            current_scan_data_id = db_connection.execute(
                '''
                SELECT max(id) FROM scan_data
                '''
            ).fetchone()[0]
            db_connection.execute(
                '''
                INSERT OR REPLACE INTO
                shodan_results(
                    scan_data_id,
                    scan_information_id,
                    query,
                    results_count,
                    results
                ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    current_scan_data_id,
                    current_scan_id,
                    query,
                    results_count,
                    json_dumps(results)
                )
            )

    @exception_handler(expected_exception=GrinderDatabaseAddScanDataError)
    def add_censys_scan_data(self, query: str, results_count: int, results: dict) -> None:
        with self.connection as db_connection:
            current_scan_id = db_connection.execute(
                '''
                SELECT max(id) FROM scan_information
                '''
            ).fetchone()[0]
            current_scan_data_id = db_connection.execute(
                '''
                SELECT max(id) FROM scan_data
                '''
            ).fetchone()[0]
            db_connection.execute(
                '''
                INSERT OR REPLACE INTO
                censys_results(
                    scan_data_id,
                    scan_information_id,
                    query,
                    results_count,
                    results
                ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    current_scan_data_id,
                    current_scan_id,
                    query,
                    results_count,
                    json_dumps(results)
                )
            )

    @exception_handler(expected_exception=GrinderDatabaseLoadResultsError)
    def load_last_results(self):
        with self.connection as db_connection:
            sql_results = db_connection.execute(
                '''
                SELECT results FROM shodan_results
                WHERE scan_information_id = (
                    SELECT max(id) FROM scan_information
                    WHERE scan_total_results != 0
                    )
                AND results != '[]'
                UNION SELECT results FROM censys_results
                WHERE scan_information_id = (
                    SELECT max(id) FROM scan_information
                    WHERE scan_total_results != 0
                    )
                AND results != '[]'
                '''
            ).fetchall()
            results_parsed = [json_loads(item[0]) for item in sql_results]
            results_combined = [result for query_result in results_parsed for result in query_result]
            return results_combined

    @exception_handler(expected_exception=GrinderDatabaseCloseError)
    def close(self):
        self.connection.close()

    def __del__(self):
        self.close()
