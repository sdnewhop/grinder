#!/usr/bin/env python3


class DefaultValues:
    """
    Values that used almost everywhere,
    most basic default values class
    """

    SHODAN_API_KEY: str = "YOUR_DEFAULT_API_KEY"
    CENSYS_API_ID: str = "YOUR_CENSYS_API_ID"
    CENSYS_API_SECRET: str = "YOUR_CENSYS_API_SECRET"
    VULNERS_API_KEY: str = "YOUR_VULNERS_API_KEY_HERE"

    CENSYS_DEFAULT_RESULTS_QUANTITY: int = 100000
    CENSYS_FREE_PLAN_RESULTS_QUANTITY: int = 1000
    SHODAN_DEFAULT_RESULTS_QUANTITY: int = 100000

    SHODAN_MAX_VULNERABILITIES_REFERENCES: int = 3

    QUERIES_FILE: str = "queries_test.json"
    MARKERS_DIRECTORY: str = "map"

    RESULTS_DIRECTORY: str = "results"
    JSON_RESULTS_DIRECTORY: str = "json"
    JSON_RESULTS_FILE: str = "all_results.json"
    CSV_RESULTS_DIRECTORY: str = "csv"
    CSV_RESULTS_FILE: str = "all_results.csv"
    TXT_RESULTS_DIRECTORY: str = "txt"
    TXT_RESULTS_FILE: str = "all_results.txt"

    CUSTOM_SCRIPTS_DIRECTORY: str = "custom_scripts"
    PY_SCRIPTS_DIRECTORY: str = "py_scripts"
    NSE_SCRIPTS_DIRECTORY: str = "nse_scripts"

    JSON_CONTINENTS_FILE: str = "continents.json"
    CSV_CONTINENTS_FILE: str = "continents.csv"
    TXT_CONTINENTS_FILE: str = "continents.txt"

    PNG_RESULTS_DIRECTORY: str = "png"
    PNG_ALL_RESULTS_DIRECTORY: str = "all_results"
    PNG_LIMITED_RESULTS_DIRECTORY: str = "limited_results"
    PNG_VULNERS_RESULTS: str = "vulners_results"
    PNG_TLS_RESULTS: str = "tls_results"
    PNG_TLS_ATTACKS_BY_PRODUCTS: str = "tls_attacks_by_products"
    PNG_TLS_BUGS_BY_PRODUCTS: str = "tls_bugs_by_products"
    PNG_TLS_ATTACKS_BY_VENDORS: str = "tls_attacks_by_vendors"
    PNG_TLS_BUGS_BY_VENDORS: str = "tls_bugs_by_vendors"
    PNG_TLS_VENDORS_BY_ATTACKS: str = "tls_vendors_by_attacks"
    PNG_TLS_VENDORS_BY_BUGS: str = "tls_vendors_by_bugs"
    PNG_TLS_PRODUCTS_BY_ATTACKS: str = "tls_products_by_attacks"
    PNG_TLS_PRODUCTS_BY_BUGS: str = "tls_products_by_bugs"


class DefaultScriptCheckerValues:
    """
    Default values for script scanners
    """

    WORKERS = 50


class DefaultTlsParserValues:
    """
    Default values for TLS-Parser
    """

    PARSED_RESULTS_DIR = "tls_processed_data"

    FULL_RESULTS_JSON = "tls_scanner_results.json"
    UNIQUE_ATTACKS_JSON = "tls_scanner_attacks.json"
    UNIQUE_BUGS_JSON = "tls_scanner_bugs.json"
    UNIQUE_VULNERABILITIES_JSON = "tls_scanner_vulnerabilities.json"

    FULL_RESULTS_CSV = "tls_scanner_results.csv"
    UNIQUE_ATTACKS_CSV = "tls_scanner_attacks.csv"
    UNIQUE_BUGS_CSV = "tls_scanner_bugs.csv"
    UNIQUE_VULNERABILITIES_CSV = "tls_scanner_vulnerabilities.csv"

    UNIQUE_GROUPPED_PRODUCTS_RESULTS_CSV = "tls_scanner_groupped.csv"


class DefaultTlsScannerValues:
    """
    Default values for TLS-Scanner
    """

    PRODUCT_LIMIT = 50
    LENGTH_OF_HOSTS_SUBGROUPS = 100
    NMAP_PING_SCAN_ARGS = "-n -sP"
    TLS_DETECTION_HOST_TIMEOUT = 180
    TLS_NMAP_WORKERS = 10
    TLS_SCANNER_REPORT_DETAIL = "NORMAL"
    TLS_SCANNER_SCAN_DETAIL = "NORMAL"
    TLS_SCANNER_PATH = "./TLS-Scanner/apps/TLS-Scanner.jar"
    TLS_SCANNER_THREADS = 4
    TLS_SCANNER_RESULTS_DIR = "tls"
    TLS_SCANNER_TIMEOUT = 1200


class DefaultVulnersScanValues:
    """
    Default values for Nmap Vulners scan
    """

    SUDO = False
    PORTS = None
    TOP_PORTS = None
    WORKERS = 10
    HOST_TIMEOUT = 120
    VULNERS_SCRIPT_PATH = "/plugins/vulners.nse"


class DefaultMasscanScanValues:
    """
    Default values for Masscan scan itself
    """

    PORTS = "1-1024"
    TOP_PORTS = None
    RATE = 1000
    ARGUMENTS = ""
    SUDO = True


class DefaultNmapScanValues:
    """
    Default values for Nmap scan itself
    """

    PORTS = None
    TOP_PORTS = None
    SUDO = False
    HOST_TIMEOUT = 30
    ARGUMENTS = "-Pn -T4 -A --open"
    WORKERS = 10


class DefaultProcessManagerValues:
    """
    Default values for process manager
    """

    PORTS = None
    SUDO = False
    ARGUMENTS = "-Pn -A --open"
    WORKERS = 10


class DefaultPlotValues:
    """
    Default plot values
    """

    PLOT_DEFAULT_AUTOPCT = "%1.1f%%"
    PLOT_LABEL_FONT_SIZE = 6
    PLOT_SUPTITLE_FONT_SIZE = 10
    PLOT_LEGEND_SIZE = 8
    PLOT_DPI = 300


class DefaultDatabaseValues:
    """
    Default database values
    """

    DB_NAME = "database.db"
