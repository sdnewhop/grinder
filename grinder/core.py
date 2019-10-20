#!/usr/bin/env python3
"""
Basic core module for grinder. All functions from
Other modules must be wrapped here for proper usage.
"""

from typing import NamedTuple, List, Dict
from termcolor import cprint
from re import findall
from ntpath import basename

# from enforce import runtime_validation

from grinder.vulnersconnector import VulnersConnector
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
    GrinderFileManagerJsonDecoderError,
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
    GrinderCoreVulnersReportError,
    GrinderCoreSaveVulnersResultsError,
    GrinderCoreSaveVulnersPlotsError,
    GrinderCoreForceUpdateCombinedResults,
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
        vulners_api_key: str = ""
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
        self.vulners_api_key = vulners_api_key or DefaultValues.VULNERS_API_KEY

        self.vendor_confidence: str = ""
        self.query_confidence: str = ""
        self.vendors: list = []
        self.max_entities: int = 6

        self.filemanager = GrinderFileManager()
        self.db = GrinderDatabase()

    @timer
    @exception_handler(expected_exception=GrinderCoreSearchError)
    def shodan_search(self, query: str, results_count: int = None) -> List[dict]:
        """
        Search in shodan database with ShodanConnector
        module.

        :param results_count: quantity of results to scan for
        :param query: search query for shodan
        :return: raw shodan results in list
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

        :param results_count: maximum results quantity
        :return: None
        """
        self.censys_results_limit = results_count

    @exception_handler(expected_exception=GrinderCoreSetShodanMaxResultsError)
    def set_shodan_max_results(self, results_count: int) -> None:
        """
        Set maximum results quantity for Shodan queries

        :param results_count: maximum results quantity
        :return: None
        """
        self.shodan_results_limit = results_count

    @timer
    @exception_handler(expected_exception=GrinderCoreSearchError)
    def censys_search(self, query: str, results_count: int = None) -> List[dict]:
        """
        Search in censys database with CensysConnector
        module.

        :param query: search query for censys
        :param results_count: maximum results quantity
        :return: raw censys results in list
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
    def update_map_markers(self, search_results: dict = None) -> None:
        """
        Update map markers in JavaScript map

        :param search_results: processed results in dict
        :return: None
        """
        cprint("Updating current map markers...", "blue", attrs=["bold"])
        if search_results is None:
            search_results = list(self.combined_results.values())
        MapMarkers().update_markers(search_results)

    @staticmethod
    def __get_proper_entity_name(entity_name: str) -> str:
        """
        Quick fix to convert entity names,
        like vendor - vendors, port - ports etc.

        :param entity_name: name of entity
        :return: modified entity name
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

        :return: None
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
    def count_continents(self) -> Dict[str, int]:
        """
        Count unique continents based on country. This method is custom
        because we need to convert our countries to continents before
        we put it in analysis.

        :return: dictionary {'country': number of products in that country}
        """
        continents: dict = {}
        for entity in self.entities_count_all:
            if not entity.get("entity") == "country":
                continue
            continents = GrinderContinents.convert_continents(entity.get("results"))
        self.entities_count_all.append({"entity": "continent", "results": continents})
        return continents

    def count_vulnerabilities(self, max_vulnerabilities: int = 10) -> List[str]:
        """
        Count unique vulnerabilities from Shodan and Vulners.com API scan

        :param max_vulnerabilities: maximum quantity of vulnerabilities
        :return: full CVE list with entities in format {'vulnerability': number of affected services}
        """
        full_cve_list: list = []
        for host in self.combined_results.values():
            shodan_cve_list: list = []
            vulners_cve_list: list = []

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
        load_dir: str = DefaultValues.RESULTS_DIRECTORY,
        load_file: str = DefaultValues.JSON_RESULTS_FILE,
        load_json_dir: str = DefaultValues.JSON_RESULTS_DIRECTORY,
    ) -> dict:
        """
        Load saved results of latest previous scan from json file

        :param load_dir: base directory with results
        :param load_file: json results filename
        :param load_json_dir: directory with json results to load from
        :return: processed search results
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
                "JSON file with results not found. Try to load results from database."
            )
        except GrinderFileManagerJsonDecoderError:
            print(
                "JSON file with results corrupted. Try to load results from database."
            )

    @exception_handler(expected_exception=GrinderCoreForceUpdateCombinedResults)
    def __force_update_combined_results(self) -> None:
        """
        If somehow combined_results is need to be updated,
        this function can update it.
        :return: None
        """
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

    @exception_handler(expected_exception=GrinderCoreLoadResultsFromDbError)
    def load_results_from_db(self) -> list or dict:
        """
        Load saved results of latest previous scan from database

        :return: processed search results
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

        :return: processed search results
        """
        return self.load_results_from_file() or self.load_results_from_db()

    @exception_handler(expected_exception=GrinderCoreSaveVulnersResultsError)
    def save_vulners_results(self,
                             results: dict,
                             name: str,
                             dest_dir=DefaultValues.RESULTS_DIRECTORY,
                             hosts_results=None) -> None:
        """
        Save results from vulners separately from another results
        :param results: results to save
        :param name: name of file
        :param dest_dir: directory to save
        :param hosts_results: results with all hosts
        :return: None
        """
        cprint(f"Save Vulners reports for {name}...", "blue", attrs=["bold"])
        self.filemanager.write_results_json(
            results,
            dest_dir=dest_dir,
            json_file=f"{name.replace(' ', '_')}.json",
        )
        bypass_list = ["vulners exploits by vulnerabilities",
                       "vulners by cvss groups",
                       "hosts groupped by vulnerabilities"]
        self.filemanager.write_results_csv(
            results.values() if name not in bypass_list else results,
            dest_dir=dest_dir,
            csv_file=f"{name.replace(' ', '_')}.csv",
        )
        if name == "vulners exploits by vulnerabilities":
            self.filemanager.write_results_csv_exploits_to_cve(
                results,
                dest_dir=dest_dir,
                csv_file=f"{name.replace(' ', '_')}.csv",
                hosts_results=hosts_results
            )

    @exception_handler(expected_exception=GrinderCoreSaveVulnersPlotsError)
    def save_vulners_plots(self, results: dict or list, name: str, suptitle: str) -> None:
        """
        Create plots with vulners results
        :param results: results to save
        :param name: name of file and suptitle
        :param suptitle: name of plot
        :return: None
        """
        cprint(f"Create Vulners graphical plots for {name}...", "blue", attrs=["bold"])
        plots = GrinderPlots()
        plots.create_pie_chart(
            results=results,
            suptitle=f"{suptitle}",
        )
        plots.save_pie_chart(
            relative_path=DefaultValues.PNG_VULNERS_RESULTS,
            filename=f"{name.replace(' ', '_')}.png",
        )

    @exception_handler(expected_exception=GrinderCoreVulnersReportError)
    def vulners_report(self) -> None:
        """
        Report information from Vulners API
        :return: None
        """
        # If counter of entities is empty - skip vulners report
        if not self.entities_count_all or not self.combined_results:
            return

        # Collect only vulnerabilities from entities counter
        vulnerabilities = {}
        for entity in self.entities_count_all:
            if not entity.get("entity") == "vulnerability":
                continue
            if entity.get("results"):
                vulnerabilities = entity.get("results")
                break

        # Initialize reporter for different kind of vulnerabilities and exploits
        vulners = VulnersConnector(api_key=self.vulners_api_key)
        vulners.vulnerabilities = vulnerabilities
        vulners.hosts = self.combined_results

        # Search for critical vulnerabilities
        vulners_vulnerabilities = vulners.get_vulnerabilities_report()
        vulners_critical_vulnerabilities = vulners.get_critical_vulnerabilities_report(
            vulnerabilities_report=vulners_vulnerabilities
        )
        vulners_critical_vulnerabilities_hosts = vulners.get_critical_vulnerabilities_hosts_report(
            critical_vulnerabilities_report=vulners_critical_vulnerabilities
        )

        # Group hosts and vulnerabilities into CVSS groups of vulns
        vulners_by_cvss_groups = vulners.sort_by_cvss_rating(
            vulnerabilities_report=vulners_vulnerabilities
        )
        vulners_by_cvss_groups_hosts = vulners.sort_by_cvss_rating_hosts(
            cvss_groupped_vulnerabilties_report=vulners_by_cvss_groups
        )

        # Search for exploits for vulnerabilities and software
        vulners_exploits_by_cve = vulners.get_exploits_for_vulnerabilities()
        vulners_exploits_by_cpe = vulners.get_exploits_for_software()

        # Pair of results with names to save
        named_results_to_save = [
            (vulners_vulnerabilities, "vulners vulnerabilities"),
            (vulners_critical_vulnerabilities, "vulners critical vulnerabilities"),
            (vulners_exploits_by_cve, "vulners exploits by vulnerabilities"),
            (vulners_exploits_by_cpe, "vulners exploits by software"),
            (vulners_by_cvss_groups, "vulners by cvss groups"),
            (vulners_critical_vulnerabilities_hosts, "hosts with critical vulnerabilities"),
            (vulners_by_cvss_groups_hosts, "hosts groupped by vulnerabilities")
        ]
        # Saver
        for results, name in named_results_to_save:
            if not results:
                continue
            self.save_vulners_results(
                results,
                name=name,
                hosts_results=self.combined_results,
            )

        # Count length
        length_vulnerabilities = len(vulnerabilities.keys())
        length_critical_vulnerabilities = len(vulners_critical_vulnerabilities.keys())
        length_references_vulnerabilities = len(vulners_exploits_by_cve.keys())
        length_exploitable_hosts = len(vulners_exploits_by_cpe.keys())
        length_hosts_with_critical_vulnerabilities = len(vulners_critical_vulnerabilities_hosts.keys())
        length_all_hosts = len(self.combined_results)

        # Set labels and definitions for plots
        hosts_with_critical_vulnerabilities_comparison = {
            "Other": length_all_hosts - length_hosts_with_critical_vulnerabilities,
            "With Critical Vulnerabilities": length_hosts_with_critical_vulnerabilities
        }
        critical_vulnerabilities_comparison = {
            "Other": length_vulnerabilities - length_critical_vulnerabilities,
            "Critical": length_critical_vulnerabilities
        }
        vulnerabilities_with_exploits_comparison = {
            "Other": length_vulnerabilities - length_references_vulnerabilities,
            "Referenced in Exploits": length_references_vulnerabilities
        }
        cpes_with_exploits_comparison = {
            "Other": length_all_hosts - length_exploitable_hosts,
            "With Exploits": length_exploitable_hosts
        }
        vulners_cvss_comparison = {
            key: len(value) for key, value in vulners_by_cvss_groups.items()
        }
        vulners_cvss_hosts_comparison = {
            key: len(value) for key, value in vulners_by_cvss_groups_hosts.items()
        }

        plots_information_to_save = [
            {
                "results": hosts_with_critical_vulnerabilities_comparison,
                "name": "hosts with critical vulnerabilities",
                "suptitle": "Percentage of nodes with critical vulnerabilities",
            },
            {
                "results": critical_vulnerabilities_comparison,
                "name": "critical vulnerabilities",
                "suptitle": "Percentage of critical vulnerabilities",
            },
            {
                "results": vulnerabilities_with_exploits_comparison,
                "name": "vulnerabilities referenced in exploits",
                "suptitle": "Percentage of vulnerabilities referenced in exploits documents",
            },
            {
                "results": cpes_with_exploits_comparison,
                "name": "hosts with exploitable software",
                "suptitle": "Percentage of nodes with exploitable software",
            },
            {
                "results": vulners_cvss_comparison,
                "name": "CVSS vulnerabilities",
                "suptitle": "Percentage of vulnerabilities by CVSS v3.0 rating",
            },
            {
                "results": vulners_cvss_hosts_comparison,
                "name": "hosts groupped by cvss rating",
                "suptitle": "Percentage of nodes divided into groups of CVSS rating vulnerabilities"
            }
        ]
        for entity_to_save in plots_information_to_save:
            self.save_vulners_plots(entity_to_save.get("results"),
                                    name=entity_to_save.get("name"),
                                    suptitle=entity_to_save.get("suptitle"))

    @exception_handler(expected_exception=GrinderCoreSaveResultsError)
    def save_results(self, dest_dir: str = DefaultValues.RESULTS_DIRECTORY) -> None:
        """
        Save all scan results to all formats

        :param dest_dir: directory to save results
        :return: None
        """
        cprint("Save all results...", "blue", attrs=["bold"])

        # If all scan results were empty
        if not self.combined_results and not self.shodan_processed_results and not self.censys_processed_results:
            return
        # If some results are exists, but combined results are empty - refresh it
        elif not self.combined_results:
            self.__force_update_combined_results()

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

    @exception_handler(expected_exception=GrinderCoreIsHostExistedError)
    def __is_host_existed(self, ip: str) -> bool:
        """
        Check if current host is existed in current results. 

        :param ip: host ip
        :return: answer to question "Is current host already scanned?"
        """
        return self.shodan_processed_results.get(
            ip
        ) or self.censys_processed_results.get(ip)

    def set_unique_entities_quantity(self, max_entities: int) -> None:
        """
        Set maximum limit of unique entities for count

        :param max_entities: number of entities
        :return: None
        """
        self.max_entities = max_entities

    @exception_handler(expected_exception=GrinderCoreCountUniqueProductsError)
    def count_unique_entities(
        self, entity_name: str, search_results: dict = None, max_entities: int = None
    ) -> None:
        """
        Count every unique entity (like country, protocol, port, etc.)

        :param entity_name: name of entity ('country', 'proto', etc.)
        :param search_results: results to count from
        :param max_entities: max entities in count
        :return: None
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

        :param current_host: current host information
        :param query: current active query on which we found this host
        :param product_info: information about current product
        :return: None
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

        :param current_host: current host information
        :param query: current active query on which we found this host
        :param product_info: information about current product
        :return: None
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
    def __init_database(self, queries_filename: str) -> None:
        """
        Initialize database in case of first-time using. Here we are create
        database and put basic structures in it.

        :return: None
        """
        self.db.create_db()
        self.db.initiate_scan(queries_filename)

    @exception_handler(expected_exception=GrinderCoreLoadResultsFromDbError)
    def __increment_prev_scan_results(self):
        """
        Load already scanned before results (for this query file)
        :return: None
        """
        self.shodan_processed_results = self.db.load_all_shodan_results_by_scan_name()
        self.censys_processed_results = self.db.load_all_censys_results_by_scan_name()
        self.__force_update_combined_results()
        if self.combined_results:
            print(f"Results from previous scans were loaded: {len(self.combined_results)} hosts")

    @exception_handler(expected_exception=GrinderCoreCloseDatabaseError)
    def __close_database(self) -> None:
        """
        Close current database after use

        :return: None
        """
        self.db.close()

    @exception_handler(expected_exception=GrinderCoreUpdateEndTimeDatabaseError)
    def __update_end_time_database(self) -> None:
        """
        Update time when we finish scan

        :return: None
        """
        self.db.update_end_time()

    @exception_handler(expected_exception=GrinderCoreUpdateResultsCountDatabaseError)
    def __update_results_count(self, total_products: int, total_results: int) -> None:
        """
        Update all results counters when we finish scan

        :param total_products: quantity of all products
        :param total_results: quantity of all results
        :return: None
        """
        self.db.update_results_count(total_products, total_results)

    @exception_handler(expected_exception=GrinderCoreAddProductDataToDatabaseError)
    def __add_product_data_to_database(self, product_info) -> None:
        """
        Add basic information from json file with queries into database.

        :return: None
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

        :param query: current search query
        :return: None
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

        :param query: current search query
        :return: None
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

        :return: None
        """
        cprint("Save all results to database...", "blue", attrs=["bold"])
        for product_info in self.queries_file:
            for query in product_info.get("shodan_queries", []) or []:
                self.__shodan_save_to_database(query)
            for query in product_info.get("censys_queries", []) or []:
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

        :param query_confidence: query confidence to check
        :return: bool answer to question "Is current query confidence level is valid?"
        """
        # If current query confidence level is not set - every query is ok
        if not self.query_confidence:
            return True
        # If current query confidence is not valid by definition
        if not self.query_confidence.lower() in ["firm", "certain", "tentative"]:
            print("Confidence level for current query is not valid")
            return False
        if not query_confidence:
            print("Query confidence level of current product is not valid: empty field")
            return False
        if not isinstance(query_confidence, str):
            print("Query confidence level of current product is not valid: wrong type")
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
        len_of_shodan_queries = len(product_info.get("shodan_queries") or [])
        for query_index, query_info in enumerate(product_info.get("shodan_queries") or []):
            if not self.__is_query_confidence_valid(query_info.get("query_confidence", "") or ""):
                continue
            query = query_info.get("query")
            cprint(f"{query_index} / {len_of_shodan_queries} :: "
                   f"Current Shodan query is: {query or 'Empty query field'}", "blue", attrs=["bold"])
            if not query:
                print("Query field is empty, skip this search")
                continue
            shodan_raw_results = self.shodan_search(query)
            for current_host in shodan_raw_results:
                self.__parse_current_host_shodan_results(
                    current_host, query, product_info
                )

        # Censys queries processor
        len_of_censys_queries = len(product_info.get("censys_queries") or [])
        for query_index, query_info in enumerate(product_info.get("censys_queries") or []):
            if not self.__is_query_confidence_valid(query_info.get("query_confidence", "") or ""):
                continue
            query = query_info.get("query")
            cprint(f"{query_index} / {len_of_censys_queries} :: "
                   f"Current Censys query is: {query or 'Empty query field'}", "blue", attrs=["bold"])
            if not query:
                print("Query field is empty, skip this search")
                continue
            censys_raw_results = self.censys_search(query)
            for current_host in censys_raw_results:
                self.__parse_current_host_censys_results(
                    current_host, query, product_info
                )

    @exception_handler(expected_exception=GrinderCoreTlsScanner)
    def tls_scan(self, scanner_path: str) -> None:
        """
        Initiate TLS configuration scanning
        :param scanner_path: path to scanner itself
        :return: None
        """
        cprint("Start TLS scanning", "blue", attrs=["bold"])
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
    ) -> None:
        """
        Initiate Nmap scan on hosts

        :param ports: ports to scan
        :param top_ports: quantity of top-ports to scan
        :param sudo: sudo if needed
        :param host_timeout: timeout for host in case of very long scanning
        :param arguments: Nmap arguments
        :param workers: number of Nmap workers
        :return: None
        """
        cprint("Start Nmap scanning", "blue", attrs=["bold"])
        cprint(f"Number of workers: {workers}", "blue", attrs=["bold"])

        # Check for top-ports if defined
        if top_ports:
            arguments = f"{arguments} --top-ports {str(top_ports)}"
        if host_timeout:
            arguments = f"{arguments} --host-timeout {str(host_timeout)}s"

        # Make ip:port list of all results
        all_hosts = [
            {"ip": host.get("ip"), "port": host.get("port")}
            for host in self.combined_results.values()
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
    ) -> None:
        """
        Almost the same as Nmap scan but with slightly different features
        :param sudo:
        :param ports:
        :param top_ports:
        :param workers:
        :param host_timeout:
        :param vulners_path:
        :return:
        """
        cprint("Start Vulners API scanning", "blue", attrs=["bold"])
        cprint(f"Number of workers: {workers}", "blue", attrs=["bold"])

        # Make ip:port list of all results
        all_hosts = [
            {"ip": host.get("ip"), "port": host.get("port")}
            for host in self.combined_results.values()
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

        :param confidence: confidence level
        :return: None
        """
        self.vendor_confidence = confidence

    def set_query_confidence(self, confidence: str) -> None:
        """
        Set query confidence level for search

        :param confidence: confidence level
        :return: None
        """
        self.query_confidence = confidence

    def set_vendors(self, vendors: List[str]) -> None:
        """
        Set list of vendors to search for

        :param vendors: list of vendors
        :return: None
        """
        self.vendors = vendors

    @exception_handler(expected_exception=GrinderCoreFilterQueriesError)
    def __filter_queries_by_vendor_confidence(self) -> None:
        """
        Filter queries by vendor confidence (not the same as query confidence)

        :return: None
        """
        if not self.vendor_confidence:
            return
        if not isinstance(self.vendor_confidence, str):
            print("Confidence level for vendors is not valid: wrong type of confidence level")
            self.queries_file = []
            return
        if not self.vendor_confidence.lower() in ["firm", "certain", "tentative"]:
            print("Confidence level for vendors is not valid")
            self.queries_file = []
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
                lambda product: str(product.get("vendor_confidence", "")).lower()
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

        :return: None
        """
        # Make list of all existed products
        if not self.vendors:
            return
        vendors_from_queries = list(
            map(lambda product: product.get("vendor", ""), self.queries_file)
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
    def run_scripts(self, queries_filename: str):
        """
        Initiate script execution

        :param queries_filename: name of json file with input data
            such as queries (shodan_queries, censys_queries, etc.)
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
        results_len = len(self.combined_results.keys())
        for index, (ip, host_info) in enumerate(self.combined_results.items()):
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

            cur_position = f"{index}/{results_len}"
            py_script = scripts.get("py_script")
            if py_script:
                py_script_res = PyScriptExecutor.run_script(host_info, py_script)
                if not py_script_res:
                    print(f"[{cur_position}] [PyExecutor: Empty output] Script {py_script} done for {ip}")
                else:
                    print(f"[{cur_position}] [PyExecutor: Successful] Script {py_script} done for {ip}")
                    if py_script_res:
                        self.combined_results[ip]["scripts"][
                            "py_script"
                        ] = py_script_res

            nse_script = scripts.get("nse_script")
            if nse_script:
                nse_script_res = NmapScriptExecutor.run_script(host_info, nse_script)
                if not nse_script_res:
                    print(f"[{cur_position}] [NseExecutor: Empty output] Script {nse_script} done for {ip}")
                else:
                    print(
                        f"[{cur_position}] [NseExecutor: Successful] Script {nse_script} done for {ip}"
                    )
                    if nse_script_res:
                        self.combined_results[ip]["scripts"][
                            "nse_script"
                        ] = nse_script_res

    @staticmethod
    def __separate_filename_wo_extension(original_filepath: str) -> str:
        """
        This function separates filename from path and extension.
        For example, queries/servers.json -> servers
        :param original_filepath: original filepath
        :return: only name
        """
        full_filename = basename(original_filepath)
        if not full_filename:
            return original_filepath
        splitted_name = full_filename.split(".")
        if not splitted_name:
            return original_filepath
        return str(splitted_name[0])

    @timer
    @exception_handler(expected_exception=GrinderCoreBatchSearchError)
    def batch_search(self, queries_filename: str, not_incremental: bool = False) -> dict:
        """
        Run batch search for all products from input JSON product list file.
        Here we are try to load JSON file with queries for different search
        systems, also we initialize our database (if it was not initialized
        earlier), and we process every product in queries file (parsing, 
        processing, etc.). Basically it is the main search method in module.

        :param queries_filename: name of json file with input data
            such as queries (shodan_queries, censys_queries)
        :param not_incremental: turn off incremental scan
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
        except GrinderFileManagerJsonDecoderError as json_err:
            print(
                "Oops! Looks like you got error in your JSON file syntax. Please, check it out and run Grinder again."
            )
            print(f"Error message: {json_err.error_args}")
            return self.combined_results
        except GrinderFileManagerOpenError as open_err:
            print(
                "Oops! File with queries was not found. Create it or set name properly."
            )
            print(f"Error message: {open_err.error_args}")
            return self.combined_results

        self.__filter_queries_by_vendor_confidence()
        self.__filter_queries_by_vendors()
        if not self.queries_file:
            print("Filter method is not valid.")
            return self.combined_results
        self.__init_database(self.__separate_filename_wo_extension(queries_filename))
        if not_incremental is False:
            self.__increment_prev_scan_results()

        len_of_products = len(self.queries_file)
        for product_index, product_info in enumerate(self.queries_file):
            cprint(f"{product_index} / {len_of_products} :: Current product: {product_info.get('product')}", "blue", attrs=["bold"])
            self.__process_current_product_queries(product_info)

        # Force create combined results container
        self.__force_update_combined_results()
        return self.combined_results
