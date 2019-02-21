#!/usr/bin/env python3

from typing import NamedTuple
from enforce import runtime_validation

from grinder.continents import GrinderContinents
from grinder.decorators import exception_handler, timer
from grinder.defaultvalues import DefaultValues
from grinder.errors import GrinderCoreSearchError, GrinderCoreBatchSearchError, \
    GrinderCoreProductQueriesError, GrinderCoreHostShodanResultsError, GrinderCoreUpdateMapMarkersError, \
    GrinderCoreSaveResultsError, GrinderCoreCountUniqueProductsError, GrinderCoreConvertToContinentsError, \
    GrinderCoreCreatePlotError, GrinderCoreIsHostExistedError
from grinder.filemanager import GrinderFileManager
from grinder.mapmarkers import MapMarkers
from grinder.plots import GrinderPlots
from grinder.shodanconnector import ShodanConnector
from grinder.utils import GrinderUtils
from grinder.dbhandling import GrinderDatabase


class HostInfo(NamedTuple):
    product: str
    vendor: str
    query: str
    port: str
    proto: str
    ip: str
    lat: str
    lng: str
    country: str

#@runtime_validation
class GrinderCore:
    shodan_results: list = []
    shodan_processed_results: list = []

    def __init__(self, api_key: str) -> None:
        self.product_info: dict = {}
        self.all_entities_count: list = []
        self.fixed_entities_count: list = []
        self.continents: dict = {}

        self.db = None

        self.api_key = api_key or DefaultValues.API_KEY
        print(f'Shodan API key: {self.api_key}')

    @timer
    @exception_handler(expected_exception=GrinderCoreSearchError)
    def shodan_search(self, query: str) -> list:
        shodan = ShodanConnector(self.api_key)
        shodan.search(query)
        self.shodan_results = shodan.get_results()
        print(f'│ Shodan results count: {shodan.get_shodan_count()}')
        print(f'│ Real results count: {shodan.get_real_count()}')
        print(f'└ ', end='')
        return self.shodan_results

    @exception_handler(expected_exception=GrinderCoreUpdateMapMarkersError)
    def update_map_markers(self, search_results=None, enabled=True) -> None:
        if search_results is None:
            search_results = self.shodan_processed_results
        MapMarkers().update_markers(search_results, enabled)
    
    @exception_handler(expected_exception=GrinderCoreCreatePlotError)
    def create_plots(self) -> None:
        plots = GrinderPlots()
        for entity in self.all_entities_count:
            plots.create_pie_chart(entity.get('results'), entity.get('entity'))
            plots.save_pie_chart(f'{entity.get("entity")}.png')
        for fixed_entity in self.fixed_entities_count:
            plots.create_pie_chart(fixed_entity.get('results'), fixed_entity.get('entity'))
            plots.save_pie_chart(f'fixed_{fixed_entity.get("entity")}.png')

    @exception_handler(expected_exception=GrinderCoreConvertToContinentsError)
    def count_continents(self) -> dict:
        continents: dict = {}
        for entity in self.all_entities_count:
            if not entity.get('entity') == 'country':
                continue
            continents = GrinderContinents.convert_continents(entity.get('results'))
        self.continents = continents
        return self.continents

    @exception_handler(expected_exception=GrinderCoreSaveResultsError)
    def save_results(self, dest_dir=DefaultValues.RESULTS_DIRECTORY) -> None:
        if not self.shodan_processed_results:
            return
        if self.shodan_processed_results:
            GrinderFileManager.write_results_json(self, self.shodan_processed_results, 
                dest_dir=dest_dir, json_file=DefaultValues.JSON_RESULTS_FILE)
            GrinderFileManager.write_results_csv(self, self.shodan_processed_results,  
                dest_dir=dest_dir, csv_file=DefaultValues.CSV_RESULTS_FILE)
            GrinderFileManager.write_results_txt(self, self.shodan_processed_results,  
                dest_dir=dest_dir, txt_file=DefaultValues.TXT_RESULTS_FILE)

        if self.continents:
            GrinderFileManager.write_results_json(self, self.continents, 
                dest_dir=dest_dir, json_file=DefaultValues.JSON_CONTINENTS_FILE)
            GrinderFileManager.write_results_csv(self, self.continents,  
                dest_dir=dest_dir, csv_file=DefaultValues.CSV_CONTINENTS_FILE)
            GrinderFileManager.write_results_txt(self, self.continents,  
                dest_dir=dest_dir, txt_file=DefaultValues.TXT_CONTINENTS_FILE)

        for entity in self.all_entities_count:
            GrinderFileManager.write_results_json(self, entity.get('results'), 
                dest_dir=dest_dir, json_file=f'{entity.get("entity")}.json')
            GrinderFileManager.write_results_csv(self, entity.get('results'), 
                dest_dir=dest_dir, csv_file=f'{entity.get("entity")}.csv')
            GrinderFileManager.write_results_txt(self, entity.get('results'), 
                dest_dir=dest_dir, txt_file=f'{entity.get("entity")}.txt')

        for entity in self.fixed_entities_count:
            GrinderFileManager.write_results_json(self, entity.get('results'), 
                dest_dir=dest_dir, json_file=f'fixed_{entity.get("entity")}.json')
            GrinderFileManager.write_results_csv(self, entity.get('results'), 
                dest_dir=dest_dir, csv_file=f'fixed_{entity.get("entity")}.csv')
            GrinderFileManager.write_results_txt(self, entity.get('results'), 
                dest_dir=dest_dir, txt_file=f'fixed_{entity.get("entity")}.txt')

    @exception_handler(expected_exception=GrinderCoreIsHostExistedError)
    def __is_host_existed(self, ip: str) -> bool or None:
        existed_ip_list = [exist_host.get('ip') for exist_host in self.shodan_processed_results]
        if ip in existed_ip_list:
            return True

    @exception_handler(expected_exception=GrinderCoreCountUniqueProductsError)
    def count_unique_entities(self, entity_name, search_results=None, max_entities=5) -> None:
        if not search_results:
            search_results = self.shodan_processed_results
        list_of_products = [current_product.get(entity_name) for current_product in search_results]
        utils = GrinderUtils()
        utils.count_entities(list_of_products, max_entities, entity_name)

        self.all_entities_count.append({'entity': entity_name, 'results': utils.get_all_count_results()})
        self.fixed_entities_count.append({'entity': entity_name, 'results': utils.get_fixed_max_count_results()})

    @exception_handler(expected_exception=GrinderCoreHostShodanResultsError)
    def parse_current_host_shodan_results(self, current_host: dict, query: str) -> None:
        if not (current_host.get('location').get('latitude') and current_host.get('location').get('latitude')):
            return
        host_info = HostInfo(
            product=self.product_info['product'],
            vendor=self.product_info['vendor'],
            query=query,
            port=current_host.get('port'),
            proto=current_host.get('_shodan').get('module'),
            ip=current_host.get('ip_str'),
            lat=current_host.get('location').get('latitude'),
            lng=current_host.get('location').get('longitude'),
            country=current_host.get('location').get('country_name'),
        )
        shodan_result_as_dict = dict(host_info._asdict())
        if not self.__is_host_existed(shodan_result_as_dict.get('ip_str ')):
            self.shodan_processed_results.append(shodan_result_as_dict)

    def __init_database(self):
        self.db = GrinderDatabase()
        self.db.create_db()
        self.db.initiate_scan()
    
    def __close_database(self):
        self.db.close()
    
    def __update_end_time_database(self):
        self.db.update_end_time()

    def __save_to_database(self, query: str):
        results_by_query = list(filter(lambda host: host.get('query') == query, self.shodan_processed_results))
        results_count = len(results_by_query) if results_by_query else None
        self.db.add_scan_data(vendor=self.product_info.get('vendor'),
                              product=self.product_info.get('product'),
                              query=query,
                              script=self.product_info.get('script'),
                              confidence=self.product_info.get('confidence'),
                              results_count=results_count,
                              results=results_by_query)

    @exception_handler(expected_exception=GrinderCoreProductQueriesError)
    def process_current_product_queries(self, product_info: dict) -> None:
        self.product_info = product_info
        for query in product_info.get('queries'):
            print(f'Current query is: {query}')
            shodan_hostlist_results = self.shodan_search(query)
            for current_host in shodan_hostlist_results:
                self.parse_current_host_shodan_results(current_host, query)
            self.__save_to_database(query)

    @timer
    @exception_handler(expected_exception=GrinderCoreBatchSearchError)
    def batch_search(self, queries_file: str) -> list:
        queries_file = queries_file or DefaultValues.QUERIES_FILE
        print(f'File with queries: {queries_file}')
        queries = GrinderFileManager().get_queries(queries_file=queries_file)
        self.__init_database()
        for product_info in queries:
            self.process_current_product_queries(product_info)
        self.__update_end_time_database()
        self.__close_database()
        return self.shodan_processed_results
