#!/usr/bin/env python3

from shodan import Shodan
from shodan.exception import APIError, APITimeout
from itertools import islice

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultValues
from grinder.errors import ShodanConnectorInitError, ShodanConnectorSearchError


class ShodanConnector:
    @exception_handler(expected_exception=ShodanConnectorInitError)
    def __init__(self, api_key=DefaultValues.SHODAN_API_KEY):
        self.api = Shodan(api_key)
        self.results: list = []
        self.one_host_result = {}
        self.shodan_results_count: int = 0
        self.real_results_count: int = 0

    def _remove_unused_fields_in_vulns(
            self, max_references: int = DefaultValues.SHODAN_MAX_VULNERABILITIES_REFERENCES
    ) -> None:
        """
        Remove fields that not useful from vulnerabilities.
        :param max_references: decrease quantity of reference to this number
        :return: None
        """
        for host in self.results:
            if not host.get("vulns"):
                continue
            for cve, cve_information in host.get("vulns", {}).items():
                if cve_information.get("references"):
                    cve_information["references"] = cve_information["references"][
                                                    :max_references
                                                    ]
                if "verified" in cve_information.keys():
                    cve_information.pop("verified")

    @exception_handler(expected_exception=ShodanConnectorSearchError)
    def search(
            self, query: str, max_records=DefaultValues.SHODAN_DEFAULT_RESULTS_QUANTITY
    ) -> None:
        """
        Search for defined query in Shodan database
        :param query: query to search for
        :param max_records: quantity of max records to search
        :return: None
        """
        try:
            results_generator = self.api.search_cursor(query, minify=True)
            self.results = list(islice(results_generator, max_records))
            self._remove_unused_fields_in_vulns()
            self.shodan_results_count = self.api.count(query).get("total")
        except (APIError, APITimeout) as api_error:
            print(f"Shodan API error: {api_error}")
        self.real_results_count = len(list(self.results))

    def get_results(self) -> list:
        """
        Return Shodan results
        :return: list of results
        """
        return self.results

    def get_shodan_count(self) -> int:
        """
        Return quantity of results from Shodan database
        :return: quantity of results
        """
        return self.shodan_results_count

    def get_real_count(self) -> int:
        """
        Return real quantity of results that
        was successfully gained from Shodan
        :return: quantity of real results that we get
        """
        return self.real_results_count

    def get_vulnerabilities(self) -> dict:
        """
        Return dictionary with vulnerabilities,
        {host: vulnerabilities}
        :return: dictionary with vulnerabilities
        """
        return {
            host["ip_str"]: host["vulns"] for host in self.results if host.get("vulns")
        }

    def get_one_host_result(self) -> dict:
        """
        Return results in dict
        :return: host info
        """
        return self.one_host_result

    def get_host_info(self, host_address: str):
        try:
            self.shodan_host_info = self.api.host(host_address, history=False)
            self.one_host_result = self.shodan_host_info
        except (APIError, APITimeout) as api_error:
            print(f"Shodan API error: {api_error}")
