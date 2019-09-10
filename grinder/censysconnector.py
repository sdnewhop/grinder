#!/usr/bin/env python3

from censys.base import (
    CensysRateLimitExceededException,
    CensysJSONDecodeException,
    CensysNotFoundException,
    CensysUnauthorizedException,
    CensysException,
)
from censys.ipv4 import CensysIPv4

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultValues
from grinder.errors import (
    CensysConnectorGetResultsError,
    CensysConnectorInitError,
    CensysConnectorSearchError,
)


class CensysConnector:
    @exception_handler(expected_exception=CensysConnectorInitError)
    def __init__(
        self,
        api_id=DefaultValues.CENSYS_API_ID,
        api_secret=DefaultValues.CENSYS_API_SECRET,
    ):
        try:
            self.api = CensysIPv4(api_id=api_id, api_secret=api_secret)
        except CensysUnauthorizedException as invalid_api_err:
            print(f"Censys invalid API keys error: {invalid_api_err}")
        except CensysException as api_err:
            print(f"Censys API error: {api_err}")
        self.results: list = []
        self.censys_results_count: int = 0
        self.search_fields = [
            "ip",
            "location.country",
            "location.latitude",
            "location.longitude",
            "ports",
            "protocols",
        ]
        self.convert_dict = {
            "ip": "ip",
            "location.country": "country",
            "location.latitude": "lat",
            "location.longitude": "lng",
            "ports": "port",
            "protocols": "proto",
        }

    @exception_handler(expected_exception=CensysConnectorSearchError)
    def search(
        self, query: str, max_records=DefaultValues.CENSYS_DEFAULT_RESULTS_QUANTITY
    ) -> None:
        try:
            self.results = list(
                self.api.search(
                    query, fields=self.search_fields, max_records=max_records
                )
            )
        except (
            CensysRateLimitExceededException,
            CensysJSONDecodeException,
            CensysNotFoundException,
            CensysUnauthorizedException,
        ) as api_error:
            print(f"Censys API error: {api_error}")
        except AttributeError as api_not_defined:
            print(f"Censys API was not initialized: {api_not_defined}")
        except CensysException as too_much_results_required:
            if "Only the first 1,000 search results are available" in str(
                too_much_results_required
            ):
                print(
                    "Only the first 1,000 search results are available. Retry search with 1,000 results limit."
                )
                self.search(
                    query, max_records=DefaultValues.CENSYS_FREE_PLAN_RESULTS_QUANTITY
                )
            else:
                print(f"Censys API core exception: {too_much_results_required}")
        self.censys_results_count = len(self.results)

    def get_raw_results(self) -> list:
        return self.results

    @exception_handler(expected_exception=CensysConnectorGetResultsError)
    def get_results(self) -> list:
        formated_result: list = []
        for result in self.results:
            formated_result.append(
                dict((self.convert_dict[key], value) for (key, value) in result.items())
            )
        for host in formated_result:
            if isinstance(host["port"], list):
                host["port"] = host["port"][0]
            if isinstance(host["proto"], list):
                host["proto"] = host["proto"][0]
        return formated_result

    def get_results_count(self) -> int:
        return self.censys_results_count
