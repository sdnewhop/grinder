#!/usr/bin/python3

from censys.ipv4 import CensysIPv4

class CensysConnector:
    def __init__(self,
                 api_id="",
                 api_secret=""):
        self.api = CensysIPv4(api_id=api_id, api_secret=api_secret)
        self.results: list = []
        self.censys_results_count: int = 0
        self.search_fields = ['ip',
               'location.country',
               'location.latitude',
               'location.longitude',
               'ports',
               'protocols']
        self.convert_dict = {
            'ip': 'ip',
            'location.country': 'country',
            'location.latitude': 'lat',
            'location.longitude': 'lng',
            'ports': 'port',
            'protocols': 'proto'
        }

    def search(self, query: str, max_records=1000) -> None:
        self.results = list(self.api.search(query, fields=self.search_fields, max_records=max_records))
        self.censys_results_count = len(self.results)

    def get_raw_results(self) -> list:
        return self.results

    def get_results(self) -> list:
        formated_result: list = []
        for result in self.results:
            formated_result.append(dict((self.convert_dict[key], value) for (key, value) in result.items()))
        return formated_result

    def get_results_count(self) -> int:
        return self.censys_results_count

if __name__ == '__main__':
    searcher = CensysConnector()
    searcher.search('apache', 1)
    print(searcher.get_results())