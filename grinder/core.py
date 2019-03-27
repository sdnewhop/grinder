#!/usr/bin/env python3
"""
Basic core module for grinder. All functions from
Other modules must be wrapped here for proper usage.
"""

from typing import NamedTuple

# from enforce import runtime_validation
from termcolor import cprint

from grinder.censysconnector import CensysConnector
from grinder.continents import GrinderContinents
from grinder.dbhandling import GrinderDatabase
from grinder.decorators import exception_handler, timer
from grinder.defaultvalues import DefaultValues
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
    GrinderCoreAddProductDataToDatabaseError,
    GrinderCoreShodanSaveToDatabaseError,
    GrinderCoreCensysSaveToDatabaseError,
    GrinderCoreSaveResultsToDatabaseError,
    GrinderCoreNmapScanError,
)
from grinder.filemanager import GrinderFileManager
from grinder.mapmarkers import MapMarkers
from grinder.nmapprocessmanager import NmapProcessingManager
from grinder.plots import GrinderPlots
from grinder.shodanconnector import ShodanConnector
from grinder.utils import GrinderUtils


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
    nmap_scan: dict


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
        self.censys_results_limit: int = DefaultValues.CENSYS_DEFAULT_RESULTS

        self.shodan_api_key = shodan_api_key or DefaultValues.SHODAN_API_KEY
        self.censys_api_id = censys_api_id or DefaultValues.CENSYS_API_ID
        self.censys_api_secret = censys_api_secret or DefaultValues.CENSYS_API_SECRET

        self.confidence = None

        self.filemanager = GrinderFileManager()
        self.db = GrinderDatabase()

    @timer
    @exception_handler(expected_exception=GrinderCoreSearchError)
    def shodan_search(self, query: str) -> list:
        """
        Search in shodan database with ShodanConnector
        module.

        :param query (str): search query for shodan
        :return list: raw shodan results in list
        """
        shodan = ShodanConnector(api_key=self.shodan_api_key)
        shodan.search(query)
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
        if not results_count:
            results_count = (
                self.censys_results_limit or DefaultValues.CENSYS_DEFAULT_RESULTS
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

    @exception_handler(expected_exception=GrinderCoreCreatePlotError)
    def create_plots(self) -> None:
        """
        Create graphics and plots

        :return None:
        """
        cprint("Create graphical plots...", "blue", attrs=["bold"])
        plots = GrinderPlots()
        for entity in self.entities_count_all:
            plots.create_pie_chart(entity.get("results"), entity.get("entity"))
            plots.save_pie_chart(f'{entity.get("entity")}.png')
        for fixed_entity in self.entities_count_limit:
            plots.create_pie_chart(
                fixed_entity.get("results"), fixed_entity.get("entity")
            )
            plots.save_pie_chart(f'fixed_{fixed_entity.get("entity")}.png')

    @exception_handler(expected_exception=GrinderCoreConvertToContinentsError)
    def count_continents(self) -> dict:
        """
        Count unique continents based on country. This method is custom
        because we need to convert our countries to continents before
        we put it in analysis.

        :return dict: dictionary {'country':Count of products in that country}
        """
        cprint("Count unique continents...", "blue", attrs=["bold"])
        continents: dict = {}
        for entity in self.entities_count_all:
            if not entity.get("entity") == "country":
                continue
            continents = GrinderContinents.convert_continents(entity.get("results"))
        self.entities_count_all.append({"entity": "continents", "results": continents})
        return continents

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
        # Update combined results if we use nmap scan or something
        self.combined_results = {
            **self.shodan_processed_results,
            **self.censys_processed_results,
        }
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
                    json_file=f'fixed_{entity.get("entity")}.json',
                )
                self.filemanager.write_results_csv(
                    entity.get("results"),
                    dest_dir=dest_dir,
                    csv_file=f'fixed_{entity.get("entity")}.csv',
                )
                self.filemanager.write_results_txt(
                    entity.get("results"),
                    dest_dir=dest_dir,
                    txt_file=f'fixed_{entity.get("entity")}.txt',
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

    @exception_handler(expected_exception=GrinderCoreCountUniqueProductsError)
    def count_unique_entities(
        self, entity_name, search_results=None, max_entities=5
    ) -> None:
        """
        Count every unique entity (like country, protocol, port, etc.)

        :param entity_name (str): name of entity ('country', 'proto', etc.)
        :param search_results (dict): results to count from
        :param max_entities (int): max entities in count
        :return None:
        """
        cprint(f"Count unique {entity_name}...", "blue", attrs=["bold"])
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
            {"entity": entity_name, "results": utils.get_fixed_max_count_results()}
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
            and current_host.get("location").get("latitude")
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
            nmap_scan=None,
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
            nmap_scan=None,
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
            confidence=product_info.get("confidence"),
        )

    @exception_handler(expected_exception=GrinderCoreShodanSaveToDatabaseError)
    def __shodan_save_to_database(self, query: str) -> None:
        """
        Save current query-based results to database

        :param query (str): current search query
        :return None:
        """
        results_by_query = list(
            filter(
                lambda host: host.get("query") == query,
                self.shodan_processed_results.values(),
            )
        )
        results_count = len(results_by_query) if results_by_query else None
        self.db.add_shodan_scan_data(
            query=query, results_count=results_count, results=results_by_query
        )

    @exception_handler(expected_exception=GrinderCoreCensysSaveToDatabaseError)
    def __censys_save_to_database(self, query: str) -> None:
        """
        Save current query-based results to database

        :param query (str): current search query
        :return None:
        """
        results_by_query = list(
            filter(
                lambda host: host.get("query") == query,
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
        for query in product_info.get("shodan_queries"):
            cprint(f"Current Shodan query is: {query}", "blue", attrs=["bold"])
            shodan_raw_results = self.shodan_search(query)
            for current_host in shodan_raw_results:
                self.__parse_current_host_shodan_results(
                    current_host, query, product_info
                )

        # Censys queries processor
        for query in product_info.get("censys_queries"):
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

    @exception_handler(expected_exception=GrinderCoreNmapScanError)
    def nmap_scan(self, ports="80,443", sudo=False, arguments="-Pn -A", workers=10):
        """
        Initiate Nmap scan on hosts

        :param ports (str): ports to scan
        :param sudo (bool): sudo if needed
        :param arguments (str): Nmap arguments
        :param workers (int): number of Nmap workers
        """
        cprint("Start Nmap scanning", "blue", attrs=["bold"])
        if not self.shodan_processed_results:
            self.shodan_processed_results = self.db.load_last_shodan_results()
        if not self.censys_processed_results:
            self.censys_processed_results = self.db.load_last_censys_results()
        all_hosts = list(
            {**self.shodan_processed_results, **self.censys_processed_results}.keys()
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

    def set_confidence(self, confidence) -> None:
        self.confidence = confidence
    
    def __filter_queries_by_confidence(self) -> None:
        if not self.confidence:
            return
        if not self.confidence.lower() in ['firm', 'certain', 'tentative']:
            print('Confidence level is not valid')
            return
        self.queries_file = list(filter(lambda product: product.get('confidence').lower() == self.confidence.lower(), self.queries_file))
        if not self.queries_file:
            print('Queries with equal confidence level not found')
            return

    @timer
    #@exception_handler(expected_exception=GrinderCoreBatchSearchError)
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
        
        self.__filter_queries_by_confidence()
        self.__init_database()

        for product_info in self.queries_file:
            self.__process_current_product_queries(product_info)

        return self.combined_results
