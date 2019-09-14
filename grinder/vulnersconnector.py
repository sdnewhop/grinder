#!/usr/bin/env python3

from copy import deepcopy
from re import compile

from termcolor import cprint
from vulners import Vulners

from grinder.decorators import exception_handler
from grinder.errors import (
    VulnersConnectorInitError,
    VulnersConnectorGetVulnerabiltiesReportError,
    VulnersConnectorGetCriticalVulnerabiltiesReportError,
    VulnersConnectorGetCriticalVulnerabiltiesHostsReportError,
    VulnersConnectorSortByCVSSRatingError,
    VulnersConnectorSortByCVSSRatingHostsError,
    VulnersConnectorExploitsByVulnerabilitiesError,
    VulnersConnectorParseCpesError,
    VulnersConnectorCountUniqueCpesError,
    VulnersConnectorSearchCpeExploitsError,
    VulnersConnectorGetExploitsForSoftwareError,
)


class VulnersConnector:
    @exception_handler(expected_exception=VulnersConnectorInitError)
    def __init__(self, api_key: str, vulnerabilities: dict = None, hosts: dict = None):
        self.api_key = api_key
        self._vulnerabilities = vulnerabilities or {}
        self._hosts = hosts or {}

    @property
    def vulnerabilities(self):
        return self._vulnerabilities

    @vulnerabilities.setter
    def vulnerabilities(self, vulnerabilities: dict):
        if not vulnerabilities:
            return
        self._vulnerabilities = vulnerabilities

    @property
    def hosts(self):
        return self._hosts

    @hosts.setter
    def hosts(self, hosts: dict):
        if not hosts:
            return
        self._hosts = hosts

    @exception_handler(expected_exception=VulnersConnectorGetVulnerabiltiesReportError)
    def get_vulnerabilities_report(self) -> dict:
        """
        Collect all reports and bulletins connected with list of vulnerabilities
        :return: dictionary with reports
        """
        cprint(
            "Vulners: Collect all documents related to vulnerabilities...",
            "blue",
            attrs=["bold"],
        )
        try:
            vulners_api = Vulners(api_key=self.api_key)
        except ValueError as wrong_key:
            print("Error:", wrong_key)
            return {}
        vulnerabilities_list = list(self._vulnerabilities.keys())
        if not vulnerabilities_list:
            return {}
        vulnerabilities_report = vulners_api.documentList(vulnerabilities_list)
        return vulnerabilities_report

    @exception_handler(
        expected_exception=VulnersConnectorGetCriticalVulnerabiltiesReportError
    )
    def get_critical_vulnerabilities_report(
        self, vulnerabilities_report: dict = None, critical_cvss: int = 9.0
    ) -> dict:
        """
        Count critical vulnerabilities from all vulnerabilities
        :param vulnerabilities_report: previously received vulnerabilities report (if exists)
        :param critical_cvss: lower boundary of critical level - 9.0 by CVSS 3.0 rating (default)
        :return: dictionary with critical vulnerabilities
        """
        cprint("Vulners: Separate critical vulnerabilities...", "blue", attrs=["bold"])
        if not vulnerabilities_report:
            vulnerabilities_report = self.get_vulnerabilities_report()
        if not vulnerabilities_report:
            return {}
        critical_cve_data = {}
        for cve, cve_information in vulnerabilities_report.items():
            if not cve_information.get("cvss"):
                continue
            if not cve_information["cvss"].get("score"):
                continue
            if not float(cve_information["cvss"]["score"]) >= critical_cvss:
                continue
            critical_cve_data.update({cve: cve_information})
        return critical_cve_data

    @exception_handler(
        expected_exception=VulnersConnectorGetCriticalVulnerabiltiesHostsReportError
    )
    def get_critical_vulnerabilities_hosts_report(
        self, critical_vulnerabilities_report: dict = None, hosts: dict = None
    ) -> dict:
        """
        Count hosts with critical vulnerabilities
        :param critical_vulnerabilities_report: previously received critical vulnerabilities
        :param hosts: already scanned hosts with info
        :return: dictionary with ips of hosts
        """
        cprint(
            "Vulners: Separate hosts with critical vulnerabilities...",
            "blue",
            attrs=["bold"],
        )
        if not critical_vulnerabilities_report:
            critical_vulnerabilities_report = self.get_critical_vulnerabilities_report()
        if not critical_vulnerabilities_report:
            return {}
        if not hosts and self._hosts:
            hosts = self._hosts
        if not hosts and not self._hosts:
            return {}
        critical_cves = list(critical_vulnerabilities_report.keys())
        if not critical_cves:
            return {}

        critical_cve_hosts = {}
        for ip, host_info in hosts.items():
            vulnerabilities = host_info.get("vulnerabilities")
            if not vulnerabilities:
                continue
            all_host_vulnerabilities = []
            if vulnerabilities.get("shodan_vulnerabilities"):
                shodan_host_vulnerabilities = list(
                    vulnerabilities.get("shodan_vulnerabilities").keys()
                )
                all_host_vulnerabilities.extend(shodan_host_vulnerabilities)
            if vulnerabilities.get("vulners_vulnerabilities"):
                vulners_host_vulnerabilities = list(
                    vulnerabilities.get("vulners_vulnerabilities").keys()
                )
                all_host_vulnerabilities.extend(vulners_host_vulnerabilities)
            if not all_host_vulnerabilities:
                continue
            all_unique_host_vulnerabilities = list(set(all_host_vulnerabilities))
            check_if_any_critical = any(
                vulnerability in all_unique_host_vulnerabilities
                for vulnerability in critical_cves
            )
            if check_if_any_critical:
                critical_cve_hosts.update({ip: host_info})

        return critical_cve_hosts

    @exception_handler(expected_exception=VulnersConnectorSortByCVSSRatingError)
    def sort_by_cvss_rating(self, vulnerabilities_report: dict = None) -> dict:
        """
        Sort vulnerabilities by cvss rating
        :param cve_data: previously received vulnerabilities report
        :return: dictionary with cve by levels
        """
        cprint(
            "Vulners: Sort vulnerabilities by CVSS levels...", "blue", attrs=["bold"]
        )
        if not vulnerabilities_report:
            vulnerabilities_report = self.get_vulnerabilities_report()
        if not vulnerabilities_report:
            return {}

        # CVSS v3.0 Ratings
        # Severity	Base Score Range
        # None	    0.0
        # Low	    0.1-3.9
        # Medium	4.0-6.9
        # High	    7.0-8.9
        # Critical	9.0-10.0
        groupped_cve = {}
        for cve, cve_information in vulnerabilities_report.items():
            if not cve_information.get("cvss"):
                continue
            if not cve_information["cvss"].get("score"):
                continue
            score = float(cve_information["cvss"]["score"])
            level = ""
            if score == 0.0:
                level = "None"
            elif 0.1 <= score <= 3.9:
                level = "Low"
            elif 4.0 <= score <= 6.9:
                level = "Medium"
            elif 7.0 <= score <= 8.9:
                level = "High"
            elif 9.0 <= score <= 10.0:
                level = "Critical"
            if level == "":
                continue
            if not groupped_cve.get(level):
                groupped_cve[level] = [cve]
            else:
                groupped_cve[level].append(cve)
        return groupped_cve

    @exception_handler(expected_exception=VulnersConnectorSortByCVSSRatingHostsError)
    def sort_by_cvss_rating_hosts(
        self, cvss_groupped_vulnerabilties_report: dict = None, hosts: dict = None
    ) -> dict:
        """
        Sort hosts by CVSS rating
        :param cvss_groupped_vulnerabilties_report: already groupped vulnerabilities by CVSS rating
        :param hosts: already scanned hosts with info
        :return: dictionary with hosts groupped by cvss level
        """
        cprint("Vulners: Sort nodes by CVSS levels...", "blue", attrs=["bold"])
        if not cvss_groupped_vulnerabilties_report:
            cvss_groupped_vulnerabilties_report = self.sort_by_cvss_rating()
        if not cvss_groupped_vulnerabilties_report:
            return {}
        if not hosts and self._hosts:
            hosts = self._hosts
        if not hosts and not self._hosts:
            return {}

        groupped_cve_hosts = {}
        for ip, host_info in hosts.items():
            vulnerabilities = host_info.get("vulnerabilities")
            if not vulnerabilities:
                continue
            all_host_vulnerabilities = []
            if vulnerabilities.get("shodan_vulnerabilities"):
                shodan_host_vulnerabilities = list(
                    vulnerabilities.get("shodan_vulnerabilities").keys()
                )
                all_host_vulnerabilities.extend(shodan_host_vulnerabilities)
            if vulnerabilities.get("vulners_vulnerabilities"):
                vulners_host_vulnerabilities = list(
                    vulnerabilities.get("vulners_vulnerabilities").keys()
                )
                all_host_vulnerabilities.extend(vulners_host_vulnerabilities)
            if not all_host_vulnerabilities:
                continue
            all_unique_host_vulnerabilities = list(set(all_host_vulnerabilities))
            for (
                group,
                groupped_vulnerabilities,
            ) in cvss_groupped_vulnerabilties_report.items():
                check_if_group_match = any(
                    vulnerability in all_unique_host_vulnerabilities
                    for vulnerability in groupped_vulnerabilities
                )
                if not check_if_group_match:
                    continue
                if not groupped_cve_hosts.get(group):
                    groupped_cve_hosts[group] = [host_info]
                else:
                    groupped_cve_hosts[group].append(host_info)

        return groupped_cve_hosts

    @exception_handler(
        expected_exception=VulnersConnectorExploitsByVulnerabilitiesError
    )
    def get_exploits_for_vulnerabilities(self) -> dict:
        """
        Find exploits for current vulnerabilities
        :return: dictionary with exploits by cve
        """
        cprint(
            "Vulners: Collect all exploits references for collected vulnerabilities...",
            "blue",
            attrs=["bold"],
        )
        try:
            vulners_api = Vulners(api_key=self.api_key)
        except ValueError as wrong_key:
            print("Error:", wrong_key)
            return {}

        right_filter = [
            f"cvelist:{vulnerability}" for vulnerability in self.vulnerabilities.keys()
        ]
        exploits = {}
        length_of_right_filters = len(right_filter)
        for index, cve in enumerate(right_filter):
            cve_without_filter = cve.replace("cvelist:", "")
            try:
                cve_references = vulners_api.searchExploit(cve)
            except:
                continue
            print(
                f" - Found {len(cve_references)} exploits for {cve_without_filter} "
                f"({index}/{length_of_right_filters}, total CVEs: {len(exploits.keys())})"
            )
            if not cve_references:
                continue
            cve_exploits = []
            for possible_exploit in cve_references:
                if possible_exploit.get("bulletinFamily") != "exploit":
                    continue
                cve_exploits.append(possible_exploit)
            if cve_exploits:
                exploits.update({cve_without_filter: cve_exploits})
        return exploits

    @exception_handler(expected_exception=VulnersConnectorParseCpesError)
    def _parse_cpes(self, hosts: dict = None):
        """
        Parse compatible with Vulners API CPEs from hosts
        see: https://nmap.org/book/output-formats-cpe.html
        see: https://cpe.mitre.org/specification/
        :param hosts: hosts to check CPE
        :return: dictionary with CPEs
        """
        if not hosts and self._hosts:
            hosts = self._hosts
        if not hosts and not self._hosts:
            return {}

        host_to_cpe = {}
        # This regexp helps to find at least software with major version
        # from CPE
        valid_cpe = compile(r"cpe:\/\S:\w+:\w+:.+")

        for host_ip, host_information in hosts.items():
            if not host_information.get("nmap_scan"):
                continue
            if not host_information["nmap_scan"].get("tcp"):
                continue
            for port_number, port_information in host_information["nmap_scan"][
                "tcp"
            ].items():
                if not port_information.get("cpe"):
                    continue
                cpe_search = valid_cpe.findall(port_information.get("cpe"))
                if not cpe_search:
                    continue
                if not host_to_cpe.get(host_ip):
                    host_to_cpe.update(
                        {
                            host_ip: {
                                port_number: {
                                    "cpe_id": port_information.get("cpe"),
                                    "cpe_info": [],
                                }
                            }
                        }
                    )
                else:
                    host_to_cpe[host_ip].update(
                        {
                            port_number: {
                                "cpe_id": port_information.get("cpe"),
                                "cpe_info": [],
                            }
                        }
                    )
        return host_to_cpe

    @exception_handler(expected_exception=VulnersConnectorCountUniqueCpesError)
    def _count_unique_cpes(self, host_to_cpe) -> list:
        """
        Count all unique CPEs without repeating
        (to reduce quantity of queries to API)
        :param host_to_cpe: dictionary with hosts connected with CPEs
        :return: list of unique CPEs
        """
        unique_cpes = []
        for ip, port_cpe in host_to_cpe.items():
            if not port_cpe:
                continue
            for cpe in port_cpe.values():
                if cpe.get("cpe_id") not in unique_cpes:
                    unique_cpes.append(cpe.get("cpe_id"))
        return unique_cpes

    @exception_handler(expected_exception=VulnersConnectorSearchCpeExploitsError)
    def _search_cpe_exploits(
        self, unique_cpe: list, database_name: str = "exploit"
    ) -> dict:
        """
        Search for exploits that connected with particular software
        by CPE fingerprint
        :param unique_cpe: list of unique CPEs
        :param database_name: name of required database/bulletin to search
        :return: dictionary with CPEs and found exploits
        """
        try:
            vulners_api = Vulners(api_key=self.api_key)
        except ValueError as wrong_key:
            print("Error:", wrong_key)
            return {}

        cpe_with_exploits = {}
        for cpe in unique_cpe:
            cpe_results = vulners_api.cpeVulnerabilities(cpe)
            print(
                f" - Software: {cpe}, available databases: {list(cpe_results.keys())}"
            )
            if not cpe_results:
                continue
            cpe_exploit_list = cpe_results.get(database_name)
            if not cpe_exploit_list:
                continue
            cpe_with_exploits.update({cpe: cpe_exploit_list})
        return cpe_with_exploits

    @exception_handler(expected_exception=VulnersConnectorGetExploitsForSoftwareError)
    def get_exploits_for_software(self, hosts: dict = None):
        """
        Parse CPEs and search exploits for them with Vulners
        :param hosts: already scanned hosts with info
        :return: dictionary with software exploits
        """
        if not hosts and self._hosts:
            hosts = self._hosts
        if not hosts and not self._hosts:
            return {}

        cprint("Vulners: Collect all software exploits...", "blue", attrs=["bold"])
        host_to_cpe = self._parse_cpes()
        if not host_to_cpe:
            return {}
        unique_cpe = self._count_unique_cpes(host_to_cpe)
        if not unique_cpe:
            return {}
        cpe_with_exploits = self._search_cpe_exploits(unique_cpe)
        if not cpe_with_exploits:
            return {}

        copy_host_to_cpe = deepcopy(host_to_cpe)
        for ip, port_cpe in copy_host_to_cpe.items():
            for port, cpe in port_cpe.items():
                if not cpe.get("cpe_id") in cpe_with_exploits.keys():
                    host_to_cpe[ip].pop(port)
                    continue
                host_to_cpe[ip][port]["cpe_info"] = cpe_with_exploits[cpe.get("cpe_id")]
            if not host_to_cpe.get(ip):
                host_to_cpe.pop(ip)

        return host_to_cpe
