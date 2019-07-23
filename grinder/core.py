#!/usr/bin/env python3
"""
Basic core module for grinder. All functions from
Other modules must be wrapped here for proper usage.
"""

from typing import NamedTuple, List
from termcolor import cprint
from re import findall
from time import sleep

# from enforce import runtime_validation

from grinder.censysconnector import CensysConnector
from grinder.continents import GrinderContinents
from grinder.dbhandling import GrinderDatabase
from grinder.decorators import exception_handler, timer
from grinder.defaultvalues import (
    DefaultValues,
    DefaultNmapScanValues,
    DefaultVulnersScanValues,
)
from grinder.errors import (
    GrinderCoreSearchError,
    GrinderCoreBatchSearchError,
    GrinderCoreProductQueriesError,
    GrinderCoreHostShodanResultsError,
    GrinderCoreUpdateMapMarkersError,
    GrinderCoreSaveResultsError,
    GrinderCoreCountUniqueProductsError,
    GrinderCoreConvertToContinentsError,
    GrinderCoreCreatePlotError,
    GrinderCoreIsHostExistedError,
    GrinderCoreLoadResultsFromFileError,
    GrinderCoreInitDatabaseCallError,
    GrinderCoreCloseDatabaseError,
    GrinderCoreUpdateEndTimeDatabaseError,
    GrinderCoreUpdateResultsCountDatabaseError,
    GrinderFileManagerOpenError,
    GrinderCoreLoadResultsFromDbError,
    GrinderDatabaseLoadResultsError,
    GrinderCoreLoadResultsError,
    GrinderCoreHostCensysResultsError,
    GrinderCoreSetCensysMaxResultsError,
    GrinderCoreSetShodanMaxResultsError,
    GrinderCoreAddProductDataToDatabaseError,
    GrinderCoreShodanSaveToDatabaseError,
    GrinderCoreCensysSaveToDatabaseError,
    GrinderCoreSaveResultsToDatabaseError,
    GrinderCoreNmapScanError,
    GrinderCoreFilterQueriesError,
    GrinderCoreVulnersScanError,
    GrinderCoreRunScriptsError,
    GrinderCoreTlsScanner,
)
from grinder.filemanager import GrinderFileManager
from grinder.mapmarkers import MapMarkers
from grinder.nmapprocessmanager import NmapProcessingManager
from grinder.plots import GrinderPlots
from grinder.shodanconnector import ShodanConnector
from grinder.utils import GrinderUtils
from grinder.pyscriptexecutor import PyScriptExecutor
from grinder.nmapscriptexecutor import NmapScriptExecutor
from grinder.tlsscanner import TlsScanner
from grinder.tlsparser import TlsParser


class HostInfo(NamedTuple):
    """
    This class is used to categorize all needed host fields.
    Here we are describing our scanning template for host.
    """

    product: str
    vendor: str
    query: str
    port: str
    proto: str
    ip: str
    lat: str
    lng: str
    country: str
    vulnerabilities: dict
    nmap_scan: dict
    scripts: dict


# @runtime_validation
class GrinderCore:
    """
    This is basic module class for all functional calls
    """

    def __init__(
        self,
        shodan_api_key: str = "",
        censys_api_id: str = "",
        censys_api_secret: str = "",
    ) -> None:
        self.shodan_processed_results: dict = {}
        self.censys_processed_results: dict = {}
        self.combined_results: dict = {}

        self.entities_count_all: list = []
        self.entities_count_limit: list = []
        self.queries_file: dict = {}

        self.censys_results_limit: int = DefaultValues.CENSYS_DEFAULT_RESULTS_QUANTITY
        self.shodan_results_limit: int = DefaultValues.SHODAN_DEFAULT_RESULTS_QUANTITY

        self.shodan_api_key = shodan_api_key or DefaultValues.SHODAN_API_KEY
        self.censys_api_id = censys_api_id or DefaultValues.CENSYS_API_ID
        self.censys_api_secret = censys_api_secret or DefaultValues.CENSYS_API_SECRET

        self.vendor_confidence: str = ""
        self.query_confidence: str = ""
        self.vendors: list = []
        self.max_entities: int = 6

        self.filemanager = GrinderFileManager()
        self.db = GrinderDatabase()

    @timer
    @exception_handler(expected_exception=GrinderCoreSearchError)
    def shodan_search(self, query: str, results_count=None) -> list:
        """
        Search in shodan database with ShodanConnector
        module.

        :param query (str): search query for shodan
        :return list: raw shodan results in list
        """

        # Skip default values
        if self.shodan_api_key == "YOUR_DEFAULT_API_KEY":
            print(f"│ Shodan key is not defined. Skip scan.")
            print(f"└ ", end="")
            return []

        if not results_count:
            results_count = (
                self.shodan_results_limit
                or DefaultValues.SHODAN_DEFAULT_RESULTS_QUANTITY
            )
        shodan = ShodanConnector(api_key=self.shodan_api_key)
        shodan.search(query, results_count)
        shodan_raw_results = shodan.get_results()
        print(f"│ Shodan results count: {shodan.get_shodan_count()}")
        print(f"│ Real results count: {shodan.get_real_count()}")
        print(f"└ ", end="")
        return shodan_raw_results

    @exception_handler(expected_exception=GrinderCoreSetCensysMaxResultsError)
    def set_censys_max_results(self, results_count: int) -> None:
        """
        Set maximum results quantity for Censys queries (1000 is maximum for free API plan)

        :param results_count (int): maximum results quantity
        :return None:
        """
        self.censys_results_limit = results_count

    @exception_handler(expected_exception=GrinderCoreSetShodanMaxResultsError)
    def set_shodan_max_results(self, results_count: int) -> None:
        """
        Set maximum results quantity for Shodan queries

        :param results_count (int): maximum results quantity
        :return None:
        """
        self.shodan_results_limit = results_count

    @timer
    @exception_handler(expected_exception=GrinderCoreSearchError)
    def censys_search(self, query: str, results_count=None) -> list:
        """
        Search in censys database with CensysConnector
        module.

        :param query (str): search query for censys
        :param results_count (int): maximum results quantity
        :return list: raw censys results in list
        """

        # Skip default values
        if (
            self.censys_api_id == "YOUR_CENSYS_API_ID"
            or self.censys_api_secret == "YOUR_CENSYS_API_SECRET"
        ):
            print(f"│ Censys key is not defined. Skip scan.")
            print(f"└ ", end="")
            return []

        if not results_count:
            results_count = (
                self.censys_results_limit
                or DefaultValues.CENSYS_DEFAULT_RESULTS_QUANTITY
            )

        censys = CensysConnector(
            api_id=self.censys_api_id, api_secret=self.censys_api_secret
        )
        censys.search(query, results_count)
        censys_raw_results = censys.get_results()
        print(f"│ Censys results count: {censys.get_results_count()}")
        print(f"└ ", end="")
        return censys_raw_results

    @exception_handler(expected_exception=GrinderCoreUpdateMapMarkersError)
    def update_map_markers(self, search_results=None) -> None:
        """
        Update map markers in JavaScript map

        :param search_results (dict): processed results in dict
        :return None:
        """
        cprint("Updating current map markers...", "blue", attrs=["bold"])
        if search_results is None:
            search_results = list(self.combined_results.values())
        MapMarkers().update_markers(search_results)

    def __get_proper_entity_name(self, entity_name):
        """
        Quick fix to convert entity names, 
        like vendor - vendors, port - ports etc.
        """
        if entity_name.lower() in ["continent", "port", "product", "vendor"]:
            return entity_name + "s"
        elif entity_name.lower() in ["country", "vulnerability"]:
            return entity_name[:-1] + "ies"
        elif entity_name.lower() == "proto":
            return entity_name + "cols"

    @exception_handler(expected_exception=GrinderCoreCreatePlotError)
    def create_plots(self) -> None:
        """
        Create graphics and plots

        :return None:
        """
        cprint("Create graphical plots...", "blue", attrs=["bold"])
        plots = GrinderPlots()
        limited_plots = GrinderPlots()
        # Save all results without limits
        for entity in self.entities_count_all:
            if not entity.get("results"):
                continue
            entity_proper_name = self.__get_proper_entity_name(entity.get("entity"))
            plots.create_pie_chart(
                results=entity.get("results"),
                suptitle=f"Percentage of nodes by {entity_proper_name}",
            )
            plots.save_pie_chart(
                relative_path=DefaultValues.PNG_ALL_RESULTS_DIRECTORY,
                filename=f'{entity.get("entity")}.png',
            )
        # Save results with maximum limit
        for limited_entity in self.entities_count_limit:
            if not limited_entity.get("results"):
                continue
            entity_proper_name = self.__get_proper_entity_name(
                limited_entity.get("entity")
            )
            limited_plots.create_pie_chart(
                results=limited_entity.get("results"),
                suptitle=f"Percentage of nodes by {entity_proper_name}",
            )
            limited_plots.save_pie_chart(
                relative_path=DefaultValues.PNG_LIMITED_RESULTS_DIRECTORY,
                filename=f'limited_{limited_entity.get("entity")}.png',
            )

    @exception_handler(expected_exception=GrinderCoreConvertToContinentsError)
    def count_continents(self) -> dict:
        """
        Count unique continents based on country. This method is custom
        because we need to convert our countries to continents before
        we put it in analysis.

        :return dict: dictionary {'country':Count of products in that country}
        """
        continents: dict = {}
        for entity in self.entities_count_all:
            if not entity.get("entity") == "country":
                continue
            continents = GrinderContinents.convert_continents(entity.get("results"))
        self.entities_count_all.append({"entity": "continent", "results": continents})
        return continents

    def count_vulnerabilities(self, max_vulnerabilities=10) -> List[str]:
        """
        Count unique vulnerabilities from Shodan and Vulners.com API scan

        :return dict: dictionary {'vulnerability': number of affected services}
        """
        full_cve_list: list = []
        for host in self.combined_results.values():
            shodan_cve_list: list = []
            vulners_cve_list: list = []
            host_vulnerabilities: list = []

            vulnerabilities = host.get("vulnerabilities")
            if not vulnerabilities:
                continue

            shodan_vulnerabilities = vulnerabilities.get("shodan_vulnerabilities")
            if shodan_vulnerabilities:
                shodan_cve_list = list(shodan_vulnerabilities.keys())

            vulners_vulnerabilities = vulnerabilities.get("vulners_vulnerabilities")
            if vulners_vulnerabilities:
                vulners_cve_list = list(vulners_vulnerabilities.keys())

            # If nothing was found from Shodan or Vulners for current host
            if not (shodan_cve_list or vulners_cve_list):
                continue

            host_vulnerabilities = list(set(shodan_cve_list + vulners_cve_list))
            if host_vulnerabilities:
                full_cve_list.extend(host_vulnerabilities)

        utils = GrinderUtils()
        utils.count_entities(full_cve_list, max_vulnerabilities)

        self.entities_count_all.append(
            {"entity": "vulnerability", "results": utils.get_all_count_results()}
        )
        self.entities_count_limit.append(
            {
                "entity": "vulnerability",
                "results": utils.get_limited_max_count_results(),
            }
        )
        return full_cve_list

    @exception_handler(expected_exception=GrinderCoreLoadResultsFromFileError)
    def load_results_from_file(
        self,
        load_dir=DefaultValues.RESULTS_DIRECTORY,
        load_file=DefaultValues.JSON_RESULTS_FILE,
        load_json_dir=DefaultValues.JSON_RESULTS_DIRECTORY,
    ) -> list:
        """
        Load saved results of latest previous scan from json file

        :param load_dir (str): base directory with results
        :param load_file (str): json results filename
        :param load_json_dir (str): directory with json results to load from
        :return list: processed search results
        """
        try:
            self.combined_results = self.filemanager.load_data_from_file(
                load_dir=load_dir, load_file=load_file, load_json_dir=load_json_dir
            )
            self.combined_results = {
                host.get("ip"): host for host in self.combined_results
            }
            print("Results of latest scan was successfully loaded from json file.")
            return self.combined_results
        except GrinderFileManagerOpenError:
            print(
                "Json file with results not found. Try to load results from database."
            )

    @exception_handler(expected_exception=GrinderCoreLoadResultsFromDbError)
    def load_results_from_db(self) -> list:
        """
        Load saved results of latest previous scan from database

        :return list: processed search results
        """
        try:
            self.combined_results = self.db.load_last_results()
            self.shodan_processed_results = self.db.load_last_shodan_results()
            self.censys_processed_results = self.db.load_last_censys_results()
            print("Results of latest scan was successfully loaded from database.")
            return self.combined_results
        except GrinderDatabaseLoadResultsError:
            print("Database empty or latest scan data was not found. Abort.")

    @exception_handler(expected_exception=GrinderCoreLoadResultsError)
    def load_results(self) -> list:
        """
        Load saved results from file or from database (any)

        :return list: processed search results
        """
        return self.load_results_from_file() or self.load_results_from_db()

    @exception_handler(expected_exception=GrinderCoreSaveResultsError)
    def save_results(self, dest_dir=DefaultValues.RESULTS_DIRECTORY) -> None:
        """
        Save all scan results to all formats

        :param dest_dir (str): directory to save results
        :return None:
        """
        cprint("Save all results...", "blue", attrs=["bold"])
        # Refresh combined results in any case
        self.combined_results = {
            **self.shodan_processed_results,
            **self.censys_processed_results,
        }

        # If all scan results were empty after refreshing
        if not self.combined_results:
            return

        if self.combined_results:
            self.filemanager.write_results_json(
                list(self.combined_results.values()),
                dest_dir=dest_dir,
                json_file=DefaultValues.JSON_RESULTS_FILE,
            )
            self.filemanager.write_results_csv(
                list(self.combined_results.values()),
                dest_dir=dest_dir,
                csv_file=DefaultValues.CSV_RESULTS_FILE,
            )
            self.filemanager.write_results_txt(
                list(self.combined_results.values()),
                dest_dir=dest_dir,
                txt_file=DefaultValues.TXT_RESULTS_FILE,
            )

        if self.entities_count_all:
            for entity in self.entities_count_all:
                self.filemanager.write_results_json(
                    entity.get("results"),
                    dest_dir=dest_dir,
                    json_file=f'{entity.get("entity")}.json',
                )
                self.filemanager.write_results_csv(
                    entity.get("results"),
                    dest_dir=dest_dir,
                    csv_file=f'{entity.get("entity")}.csv',
                )
                self.filemanager.write_results_txt(
                    entity.get("results"),
                    dest_dir=dest_dir,
                    txt_file=f'{entity.get("entity")}.txt',
                )

        if self.entities_count_limit:
            for entity in self.entities_count_limit:
                self.filemanager.write_results_json(
                    entity.get("results"),
                    dest_dir=dest_dir,
                    json_file=f'limited_{entity.get("entity")}.json',
                )
                self.filemanager.write_results_csv(
                    entity.get("results"),
                    dest_dir=dest_dir,
                    csv_file=f'limited_{entity.get("entity")}.csv',
                )
                self.filemanager.write_results_txt(
                    entity.get("results"),
                    dest_dir=dest_dir,
                    txt_file=f'limited_{entity.get("entity")}.txt',
                )

    @exception_handler(expected_exception=GrinderCoreIsHostExistedError)
    def __is_host_existed(self, ip: str) -> bool:
        """
        Check if current host is existed in current results. 

        :param ip (str): host ip
        :return bool: answer to question "Is current host already scanned?"
        """
        return self.shodan_processed_results.get(
            ip
        ) or self.censys_processed_results.get(ip)

    def set_unique_entities_quantity(self, max_entitities):
        """
        Set maximum limit of unique entities for count

        :param max_entities (int): number of entities
        :return Nones:
        """
        self.max_entities = max_entitities

    @exception_handler(expected_exception=GrinderCoreCountUniqueProductsError)
    def count_unique_entities(
        self, entity_name, search_results=None, max_entities=None
    ) -> None:
        """
        Count every unique entity (like country, protocol, port, etc.)

        :param entity_name (str): name of entity ('country', 'proto', etc.)
        :param search_results (dict): results to count from
        :param max_entities (int): max entities in count
        :return None:
        """
        cprint(f"Count unique {entity_name}...", "blue", attrs=["bold"])
        if not max_entities:
            max_entities = self.max_entities
        if entity_name == "vulnerability":
            self.count_vulnerabilities(max_entities)
            return
        if entity_name == "continent":
            self.count_continents()
            return
        if not search_results:
            search_results = list(self.combined_results.values())
        list_of_entities = [
            current_product.get(entity_name) for current_product in search_results
        ]
        utils = GrinderUtils()
        utils.count_entities(list_of_entities, max_entities)

        self.entities_count_all.append(
            {"entity": entity_name, "results": utils.get_all_count_results()}
        )
        self.entities_count_limit.append(
            {"entity": entity_name, "results": utils.get_limited_max_count_results()}
        )

    @exception_handler(expected_exception=GrinderCoreHostShodanResultsError)
    def __parse_current_host_shodan_results(
        self, current_host: dict, query: str, product_info: dict
    ) -> None:
        """
        Parse raw results from shodan. Results were received from
        ShodanConnector module.

        :param current_host (dict): current host information
        :param query (str): current active query on which we found this host
        :param product_info (dict): information about current product
        :return None:
        """
        if not (
            current_host.get("location").get("latitude")
            and current_host.get("location").get("longitude")
        ):
            return
        host_info = HostInfo(
            product=product_info["product"],
            vendor=product_info["vendor"],
            query=query,
            port=current_host.get("port"),
            proto=current_host.get("_shodan").get("module"),
            ip=current_host.get("ip_str"),
            lat=current_host.get("location").get("latitude"),
            lng=current_host.get("location").get("longitude"),
            country=current_host.get("location").get("country_name"),
            vulnerabilities=dict(
                shodan_vulnerabilities=current_host.get("vulns") or {},
                vulners_vulnerabilities={},
            ),
            nmap_scan={},
            scripts=dict(py_script=None, nse_script=None),
        )
        shodan_result_as_dict = dict(host_info._asdict())
        if not self.__is_host_existed(shodan_result_as_dict.get("ip")):
            self.shodan_processed_results.update(
                {shodan_result_as_dict.get("ip"): shodan_result_as_dict}
            )

    @exception_handler(expected_exception=GrinderCoreHostCensysResultsError)
    def __parse_current_host_censys_results(
        self, current_host: dict, query: str, product_info: dict
    ) -> None:
        """
        Parse raw results from censys. Results were received from
        CensysConnector module.

        :param current_host (dict): current host information
        :param query (str): current active query on which we found this host
        :param product_info (dict): information about current product
        :return None:
        """
        if not (current_host.get("lat") and current_host.get("lng")):
            return
        host_info = HostInfo(
            product=product_info["product"],
            vendor=product_info["vendor"],
            query=query,
            port=current_host.get("port"),
            proto=current_host.get("proto"),
            ip=current_host.get("ip"),
            lat=current_host.get("lat"),
            lng=current_host.get("lng"),
            country=current_host.get("country"),
            vulnerabilities=dict(shodan_vulnerabilities={}, vulners_vulnerabilities={}),
            nmap_scan={},
            scripts=dict(py_script=None, nse_script=None),
        )
        censys_result_as_dict = dict(host_info._asdict())
        if not self.__is_host_existed(censys_result_as_dict.get("ip")):
            self.censys_processed_results.update(
                {censys_result_as_dict.get("ip"): censys_result_as_dict}
            )

    @exception_handler(expected_exception=GrinderCoreInitDatabaseCallError)
    def __init_database(self) -> None:
        """
        Initialize database in case of first-time using. Here we are create
        database and put basic structures in it.

        :return None:
        """
        self.db.create_db()
        self.db.initiate_scan()

    @exception_handler(expected_exception=GrinderCoreCloseDatabaseError)
    def __close_database(self) -> None:
        """
        Close current database after use

        :return None:
        """
        self.db.close()

    @exception_handler(expected_exception=GrinderCoreUpdateEndTimeDatabaseError)
    def __update_end_time_database(self) -> None:
        """
        Update time when we finish scan

        :return None:
        """
        self.db.update_end_time()

    @exception_handler(expected_exception=GrinderCoreUpdateResultsCountDatabaseError)
    def __update_results_count(self, total_products: int, total_results: int) -> None:
        """
        Update all results counters when we finish scan

        :param total_products (int): quantity of all products
        :param total_results (int): quantity of all results
        :return None:
        """
        self.db.update_results_count(total_products, total_results)

    @exception_handler(expected_exception=GrinderCoreAddProductDataToDatabaseError)
    def __add_product_data_to_database(self, product_info) -> None:
        """
        Add basic information from json file with queries into database.

        :return None:
        """
        self.db.add_basic_scan_data(
            vendor=product_info.get("vendor"),
            product=product_info.get("product"),
            script=product_info.get("script"),
            vendor_confidence=product_info.get("vendor_confidence"),
        )

    @exception_handler(expected_exception=GrinderCoreShodanSaveToDatabaseError)
    def __shodan_save_to_database(self, query: dict) -> None:
        """
        Save current query-based results to database

        :param query (str): current search query
        :return None:
        """
        results_by_query = list(
            filter(
                lambda host: host.get("query") == query.get("query"),
                self.shodan_processed_results.values(),
            )
        )
        results_count = len(results_by_query) if results_by_query else None
        self.db.add_shodan_scan_data(
            query=query, results_count=results_count, results=results_by_query
        )

    @exception_handler(expected_exception=GrinderCoreCensysSaveToDatabaseError)
    def __censys_save_to_database(self, query: dict) -> None:
        """
        Save current query-based results to database

        :param query (str): current search query
        :return None:
        """
        results_by_query = list(
            filter(
                lambda host: host.get("query") == query.get("query"),
                self.censys_processed_results.values(),
            )
        )
        results_count = len(results_by_query) if results_by_query else None
        self.db.add_censys_scan_data(
            query=query, results_count=results_count, results=results_by_query
        )

    @exception_handler(expected_exception=GrinderCoreSaveResultsToDatabaseError)
    def save_results_to_database(self):
        """
        Save all results to database

        :return None:
        """
        cprint("Save all results to database...", "blue", attrs=["bold"])
        for product_info in self.queries_file:
            for query in product_info.get("shodan_queries"):
                self.__shodan_save_to_database(query)
            for query in product_info.get("censys_queries"):
                self.__censys_save_to_database(query)

        self.__update_end_time_database()
        self.__update_results_count(
            total_products=len(self.queries_file),
            total_results=len(self.combined_results),
        )
        self.__close_database()

    def __is_query_confidence_valid(self, query_confidence: str) -> bool:
        """
        Check if current query confidence is valid

        :param query_confidence (str): query confidence to check
        :return None:
        """
        # If current query confidence level is not set - every query is ok
        if not self.query_confidence:
            return True
        # If current query confidence is not valid by definition
        if not self.query_confidence.lower() in ["firm", "certain", "tentative"]:
            print("Confidence level for current query is not valid")
            return False

        """
        Lower confidence must include higher confidence:
        certain = certain
        firm = firm + certain
        tentative = tentative + firm + certain
        """
        if self.query_confidence.lower() == "certain":
            required_confidences = ["certain"]
        elif self.query_confidence.lower() == "firm":
            required_confidences = ["certain", "firm"]
        elif self.query_confidence.lower() == "tentative":
            required_confidences = ["certain", "firm", "tentative"]
        else:
            required_confidences = []

        if query_confidence.lower() in required_confidences:
            return True
        return False

    @exception_handler(expected_exception=GrinderCoreProductQueriesError)
    def __process_current_product_queries(self, product_info: dict) -> None:
        """
        Process current product information from input json file with
        queries and other information. This is the basic wrapper for all
        searches in different backend systems - in this function we
        adds information about product in database, search hosts
        with queries and parse them after that.

        :param product_info (dict): all information about current product 
            including queries, vendor, confidence etc.
        :return None:
        """
        self.__add_product_data_to_database(product_info)

        # Shodan queries processor
        for query_info in product_info.get("shodan_queries"):
            if not self.__is_query_confidence_valid(query_info.get("query_confidence")):
                continue
            query = query_info.get("query")
            cprint(f"Current Shodan query is: {query}", "blue", attrs=["bold"])
            shodan_raw_results = self.shodan_search(query)
            for current_host in shodan_raw_results:
                self.__parse_current_host_shodan_results(
                    current_host, query, product_info
                )

        # Censys queries processor
        for query_info in product_info.get("censys_queries"):
            if not self.__is_query_confidence_valid(query_info.get("query_confidence")):
                continue
            query = query_info.get("query")
            cprint(f"Current Censys query is: {query}", "blue", attrs=["bold"])
            censys_raw_results = self.censys_search(query)
            for current_host in censys_raw_results:
                self.__parse_current_host_censys_results(
                    current_host, query, product_info
                )

        # Merge all search results into one dictionary
        # This dictionary looks like:
        # {
        #     ip: {
        #         product,
        #         vendor,
        #         query
        #         ...
        #         },
        #     ...
        # }
        self.combined_results = {
            **self.shodan_processed_results,
            **self.censys_processed_results,
        }

    @exception_handler(expected_exception=GrinderCoreTlsScanner)
    def tls_scan(self, scanner_path):
        cprint("Start TLS scanning", "blue", attrs=["bold"])
        if not self.shodan_processed_results:
            self.shodan_processed_results = self.db.load_last_shodan_results()
        if not self.censys_processed_results:
            self.censys_processed_results = self.db.load_last_censys_results()
        self.combined_results = {
            **self.shodan_processed_results,
            **self.censys_processed_results,
        }
        tls_scanner = TlsScanner(self.combined_results)
        tls_parser = TlsParser(self.combined_results)
        try:
            cprint(
                "Checking for currently online and alive hosts", "blue", attrs=["bold"]
            )
            tls_scanner.sort_alive_hosts()
        except Exception as sort_alive_hosts_err:
            print(
                f"Error at TLS scanner sort alive hosts method: {sort_alive_hosts_err}"
            )
            return
        try:
            cprint(
                "Detect SSL/TLS ports, certificates and services",
                "blue",
                attrs=["bold"],
            )
            tls_scanner.detect_tls_ports()
        except Exception as detect_tls_ports_err:
            print(f"Error at detecting of TLS ports method: {detect_tls_ports_err}")
            return
        try:
            cprint(
                "Link compatible ports and services with hosts", "blue", attrs=["bold"]
            )
            tls_scanner.link_alive_hosts_with_tls_ports()
        except Exception as link_alive_hosts_with_tls_ports_err:
            print(
                f"Error at linking hosts with ports in TLS method: {link_alive_hosts_with_tls_ports_err}"
            )
            return
        try:
            cprint("Run TLS-Scanner", "blue", attrs=["bold"])
            if scanner_path:
                tls_scanner.start_tls_scan(scanner_path=scanner_path)
            else:
                tls_scanner.start_tls_scan()
        except Exception as tls_scan_err:
            print(f"Error at TLS scanning: {tls_scan_err}")
            return
        try:
            cprint("Parse and process TLS-Scanner results", "blue", attrs=["bold"])
            tls_parser.load_tls_scan_results()
        except Exception as parse_tls_results_err:
            print(f"Error at TLS results parsing: {parse_tls_results_err}")
            return

    @exception_handler(expected_exception=GrinderCoreNmapScanError)
    def nmap_scan(
        self,
        ports: str = DefaultNmapScanValues.PORTS,
        top_ports: int = DefaultNmapScanValues.TOP_PORTS,
        sudo: bool = DefaultNmapScanValues.SUDO,
        host_timeout: int = DefaultNmapScanValues.HOST_TIMEOUT,
        arguments: str = DefaultNmapScanValues.ARGUMENTS,
        workers: int = DefaultNmapScanValues.WORKERS,
    ):
        """
        Initiate Nmap scan on hosts

        :param ports (str): ports to scan
        :param top_ports (int): quantity of top-ports to scan
        :param sudo (bool): sudo if needed
        :param arguments (str): Nmap arguments
        :param workers (int): number of Nmap workers
        :return None:
        """
        cprint("Start Nmap scanning", "blue", attrs=["bold"])
        cprint(f"Number of workers: {workers}", "blue", attrs=["bold"])

        # Check for top-ports if defined
        if top_ports:
            arguments = f"{arguments} --top-ports {str(top_ports)}"
        if host_timeout:
            arguments = f"{arguments} --host-timeout {str(host_timeout)}s"

        if not self.shodan_processed_results:
            self.shodan_processed_results = self.db.load_last_shodan_results()
        if not self.censys_processed_results:
            self.censys_processed_results = self.db.load_last_censys_results()

        # Make ip:port list of all results
        all_hosts = {**self.shodan_processed_results, **self.censys_processed_results}
        all_hosts = [
            {"ip": host.get("ip"), "port": host.get("port")}
            for host in all_hosts.values()
        ]

        cprint(
            f'Nmap scan arguments: {arguments}, custom ports: "{str(ports)}", top-ports: "{str(top_ports)}"',
            "blue",
            attrs=["bold"],
        )
        nmap_scan = NmapProcessingManager(
            hosts=all_hosts,
            ports=ports,
            sudo=sudo,
            arguments=arguments,
            workers=workers,
        )
        nmap_scan.start()
        nmap_results = nmap_scan.get_results()

        for host in self.shodan_processed_results.keys():
            self.shodan_processed_results[host]["nmap_scan"] = nmap_results.get(host)
        for host in self.censys_processed_results.keys():
            self.censys_processed_results[host]["nmap_scan"] = nmap_results.get(host)

    @exception_handler(expected_exception=GrinderCoreVulnersScanError)
    def vulners_scan(
        self,
        sudo: bool = DefaultVulnersScanValues.SUDO,
        ports: str = DefaultVulnersScanValues.PORTS,
        top_ports: int = DefaultVulnersScanValues.TOP_PORTS,
        workers: int = DefaultVulnersScanValues.WORKERS,
        host_timeout: int = DefaultVulnersScanValues.HOST_TIMEOUT,
        vulners_path: str = DefaultVulnersScanValues.VULNERS_SCRIPT_PATH,
    ):
        cprint("Start Vulners API scanning", "blue", attrs=["bold"])
        cprint(f"Number of workers: {workers}", "blue", attrs=["bold"])
        if not self.shodan_processed_results:
            self.shodan_processed_results = self.db.load_last_shodan_results()
        if not self.censys_processed_results:
            self.censys_processed_results = self.db.load_last_censys_results()

        # Make ip:port list of all results
        all_hosts = {**self.shodan_processed_results, **self.censys_processed_results}
        all_hosts = [
            {"ip": host.get("ip"), "port": host.get("port")}
            for host in all_hosts.values()
        ]

        # Check for top-ports if defined
        arguments = (
            f"-Pn -sV --script=.{vulners_path} --host-timeout {str(host_timeout)}s"
        )
        if top_ports:
            arguments = f"{arguments} --top-ports {str(top_ports)}"

        cprint(
            f'Vulners scan arguments: {arguments}, custom ports: "{str(ports)}", top-ports: "{str(top_ports)}"',
            "blue",
            attrs=["bold"],
        )
        vulners_scan = NmapProcessingManager(
            hosts=all_hosts,
            ports=ports,
            sudo=sudo,
            arguments=arguments,
            workers=workers,
        )
        vulners_scan.start()

        # Get all host vulns in one pack
        hosts_vulners: dict = {}
        results = vulners_scan.get_results()
        for host in results:
            host_vulners: list = []
            tcp_protocol = results[host].get("tcp")
            if not tcp_protocol:
                continue
            for port in tcp_protocol:
                script_output = tcp_protocol[port].get("script")
                if not script_output:
                    continue
                host_vulners.append(script_output.get("vulners"))
            vulns = list(set(findall(r"CVE-\d+-\d+", str(host_vulners))))
            vulns_with_urls = {
                vuln: f"https://vulners.com/cve/{vuln}" for vuln in vulns
            }
            hosts_vulners.update({host: vulns_with_urls})

        for host in self.shodan_processed_results.keys():
            self.shodan_processed_results[host]["vulnerabilities"].update(
                {"vulners_vulnerabilities": hosts_vulners.get(host)}
            )
        for host in self.censys_processed_results.keys():
            self.censys_processed_results[host]["vulnerabilities"].update(
                {"vulners_vulnerabilities": hosts_vulners.get(host)}
            )

    def set_vendor_confidence(self, confidence: str) -> None:
        """
        Set vendor confidence level for search

        :param confidence (str): confidence level
        :return None:
        """
        self.vendor_confidence = confidence

    def set_query_confidence(self, confidence: str) -> None:
        """
        Set query confidence level for search

        :param confidence (str): confidence level
        :return None:
        """
        self.query_confidence = confidence

    def set_vendors(self, vendors: List[str]) -> None:
        """
        Set list of vendors to search for

        :param vendors (list): list of vendors
        :return None:
        """
        self.vendors = vendors

    @exception_handler(expected_exception=GrinderCoreFilterQueriesError)
    def __filter_queries_by_vendor_confidence(self) -> None:
        """
        Filter queries by vendor confidence (not the same as query confidence)

        :return None:
        """
        if not self.vendor_confidence:
            return
        if not self.vendor_confidence.lower() in ["firm", "certain", "tentative"]:
            print("Confidence level for vendors is not valid")
            return
        """
        Lower confidence must include higher confidence:
        certain = certain
        firm = firm + certain
        tentative = tentative + firm + certain
        """
        if self.vendor_confidence.lower() == "certain":
            required_confidences = ["certain"]
        elif self.vendor_confidence.lower() == "firm":
            required_confidences = ["certain", "firm"]
        elif self.vendor_confidence.lower() == "tentative":
            required_confidences = ["certain", "firm", "tentative"]
        else:
            required_confidences = []

        self.queries_file = list(
            filter(
                lambda product: product.get("vendor_confidence").lower()
                in required_confidences,
                self.queries_file,
            )
        )
        if not self.queries_file:
            print("Vendors with equal confidence level not found")
            return

    @exception_handler(expected_exception=GrinderCoreFilterQueriesError)
    def __filter_queries_by_vendors(self) -> None:
        """
        Filter queries by vendors

        :return None:
        """
        # Make list of all existed products
        if not self.vendors:
            return
        vendors_from_queries = list(
            map(lambda product: product.get("vendor"), self.queries_file)
        )

        # Search vendors from CLI in list of all existed products
        founded_vendors = [
            existed_vendor
            for existed_vendor in vendors_from_queries
            for needed_vendor in self.vendors
            if needed_vendor.lower() in existed_vendor.lower()
        ]
        if not founded_vendors:
            print("Vendors not found in queries file")
            self.queries_file = []
            return

        self.vendors = founded_vendors

        # Choose right products
        self.queries_file = list(
            filter(
                lambda product: product.get("vendor").lower()
                in map(str.lower, founded_vendors),
                self.queries_file,
            )
        )

    @exception_handler(expected_exception=GrinderCoreRunScriptsError)
    def run_scripts(self, queries_filename):
        """
        Initiate script execution

        :param queries_filename (str): name of json file with input data
            such as queries (shodan_queries, censys_queries)
        :return None
        """
        cprint("Start Custom Scripts scanning", "blue", attrs=["bold"])
        if not self.queries_file:
            try:
                self.queries_file = self.filemanager.get_queries(
                    queries_file=queries_filename
                )
            except GrinderFileManagerOpenError:
                print(
                    "Oops! File with queries was not found. Create it or set name properly."
                )
                return

        # Search for compatible script
        for ip, host_info in self.combined_results.items():
            scripts = None
            for product in self.queries_file:
                if (product.get("vendor"), product.get("product")) == (
                    host_info.get("vendor"),
                    host_info.get("product"),
                ):
                    scripts = product.get("scripts")
                    break
            if not scripts:
                continue

            py_script = scripts.get("py_script")
            if py_script:
                py_script_res = PyScriptExecutor.run_script(host_info, py_script)
                if not py_script_res:
                    print(f"[PyExecutor: Empty]\tScript {py_script} done for {ip}")
                else:
                    print(f"[PyExecutor: Successful]\tScript {py_script} done for {ip}")
                    if py_script_res:
                        self.combined_results[ip]["scripts"][
                            "py_script"
                        ] = py_script_res

            nse_script = scripts.get("nse_script")
            if nse_script:
                nse_script_res = NmapScriptExecutor.run_script(host_info, nse_script)
                if not nse_script_res:
                    print(f"[NseExecutor: Empty]\tScript {nse_script} done for {ip}")
                else:
                    print(
                        f"[NseExecutor: Successful]\tScript {nse_script} done for {ip}"
                    )
                    if nse_script_res:
                        self.combined_results[ip]["scripts"][
                            "nse_script"
                        ] = nse_script_res

    @timer
    @exception_handler(expected_exception=GrinderCoreBatchSearchError)
    def batch_search(self, queries_filename: str) -> dict:
        """
        Run batch search for all products from input JSON product list file.
        Here we are try to load JSON file with queries for different search
        systems, also we initialize our database (if it was not initialized
        earlier), and we process every product in queries file (parsing, 
        processing, etc.). Basically it is the main search method in module.

        :param queries_filename (str): name of json file with input data
            such as queries (shodan_queries, censys_queries)
        :return dict: all processed results from searches in format like
            {
                host_ip: {
                    host_information
                    ...
                    } 
                ...
            }
        """
        queries_filename = queries_filename or DefaultValues.QUERIES_FILE
        print(f"File with queries: {queries_filename}")

        try:
            self.queries_file = self.filemanager.get_queries(
                queries_file=queries_filename
            )
        except GrinderFileManagerOpenError:
            print(
                "Oops! File with queries was not found. Create it or set name properly."
            )
            return self.combined_results

        self.__filter_queries_by_vendor_confidence()
        self.__filter_queries_by_vendors()
        if not self.queries_file:
            print("Filter method is not valid.")
            return self.combined_results
        self.__init_database()

        for product_info in self.queries_file:
            self.__process_current_product_queries(product_info)

        return self.combined_results
