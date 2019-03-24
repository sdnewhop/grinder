#!/usr/bin/env python3


class DefaultValues:
    SHODAN_API_KEY: str = 'YOUR_DEFAULT_API_KEY'
    CENSYS_API_ID: str = 'YOUR_CENSYS_API_ID'
    CENSYS_API_SECRET: str = 'YOUR_CENSYS_API_SECRET'
    CENSYS_DEFAULT_RESULTS: int = 1000

    QUERIES_FILE: str = 'queries_test.json'
    MARKERS_DIRECTORY: str = 'map'

    RESULTS_DIRECTORY: str = 'results'
    JSON_RESULTS_DIRECTORY: str = 'json'
    JSON_RESULTS_FILE: str = 'all_results.json'
    CSV_RESULTS_DIRECTORY: str = 'csv'
    CSV_RESULTS_FILE: str = 'all_results.csv'
    TXT_RESULTS_DIRECTORY: str = 'txt'
    TXT_RESULTS_FILE: str = 'all_results.txt'

    JSON_CONTINENTS_FILE: str = 'continents.json'
    CSV_CONTINENTS_FILE: str = 'continents.csv'
    TXT_CONTINENTS_FILE: str = 'continents.txt'

    PNG_RESULTS_DIRECTORY: str = 'png'


class DefaultPlotValues:
    PLOT_DEFAULT_AUTOPCT = "%1.1f%%"
    PLOT_LABEL_FONT_SIZE = 6
    PLOT_SUPTITLE_FONT_SIZE = 12
    PLOT_DPI = 200


class DefaultDatabaseValues:
    DB_NAME = 'database.db'
