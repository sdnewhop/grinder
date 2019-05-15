#!/usr/bin/env python3

from shodan import Shodan
from shodan.exception import APIError, APITimeout

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultValues
from grinder.errors import ShodanConnectorInitError, ShodanConnectorSearchError


class ShodanConnector:
    @exception_handler(expected_exception=ShodanConnectorInitError)
    def __init__(self, api_key=DefaultValues.SHODAN_API_KEY):
        self.api = Shodan(api_key)
        self.results: list = []
        self.shodan_results_count: int = 0
        self.real_results_count: int = 0

    @exception_handler(expected_exception=ShodanConnectorSearchError)
    def search(
        self, query: str, max_records=DefaultValues.SHODAN_DEFAULT_RESULTS_QUANTITY
    ) -> None:
        try:
            self.results = list(self.api.search_cursor(query))[:max_records]
            self.shodan_results_count = self.api.count(query).get("total")
        except (APIError, APITimeout) as api_error:
            print(f"Shodan API error: {api_error}")
        self.real_results_count = len(list(self.results))

    def get_results(self) -> list:
        return self.results

    def get_shodan_count(self) -> int:
        return self.shodan_results_count

    def get_real_count(self) -> int:
        return self.real_results_count

    def get_vulnerabilities(self) -> dict:
        return {
            host["ip_str"]: host["vulns"] for host in self.results if host.get("vulns")
        }
