#!/usr/bin/env python3

from vulners import Vulners
from re import compile
from pprint import pprint
from copy import deepcopy
from termcolor import cprint

class VulnersReport:
    def __init__(self, vulnerabilities, api_key):
        self.api_key = api_key

        self.vulnerabilities = vulnerabilities

    def get_vulnerabilities_report(self) -> dict:
        cprint("Vulners: Collect all documents related to vulnerabilities...", "blue", attrs=["bold"])
        try:
            vulners_api = Vulners(api_key=self.api_key)
        except ValueError as wrong_key:
            print("Error:", wrong_key)
            return {}
        cve_data = vulners_api.documentList(list(self.vulnerabilities.keys()))
        return cve_data

    def get_critical_vulnerabilities_report(self, cve_data: dict = None, critical_cvss: int = 9.0):
        cprint("Vulners: Separate critical vulnerabilities...", "blue", attrs=["bold"])
        if not cve_data:
            cve_data = self.get_vulnerabilities_report()
        critical_cve_data = {}
        for cve, cve_information in cve_data.items():
            if not cve_information.get("cvss"):
                continue
            if not cve_information["cvss"].get("score"):
                continue
            if not float(cve_information["cvss"]["score"]) >= critical_cvss:
                continue
            critical_cve_data.update({cve: cve_information})
        return critical_cve_data

    def get_critical_vulnerabilities_hosts_report(self, cve_data: dict = None, hosts: dict = None):
        cprint("Vulners: Separate hosts with critical vulnerabilities...", "blue", attrs=["bold"])
        if not cve_data:
            cve_data = self.get_critical_vulnerabilities_report()
        critical_cves = list(cve_data.keys())
        critical_cve_hosts = {}
        for ip, host_info in hosts.items():
            vulnerabilities = host_info.get("vulnerabilities")
            if not vulnerabilities:
                continue
            all_vulnerabilities = []
            if vulnerabilities.get("shodan_vulnerabilities"):
                all_vulnerabilities.extend(list(vulnerabilities.get("shodan_vulnerabilities").keys()))
            if vulnerabilities.get("vulners_vulnerabilities"):
                all_vulnerabilities.extend(list(vulnerabilities.get("vulners_vulnerabilities").keys()))
            all_unique_vulnerabilities = list(set(all_vulnerabilities))
            check_if_got_critical = any(vulnerability in all_unique_vulnerabilities for vulnerability in critical_cves)
            if check_if_got_critical:
                critical_cve_hosts.update({ip: host_info})
        return critical_cve_hosts

    def sort_by_cvss_rating(self, cve_data: dict = None):
        cprint("Vulners: Sort vulnerabilities by CVSS levels...", "blue", attrs=["bold"])
        if not cve_data:
            cve_data = self.get_vulnerabilities_report()
        groupped_cve = {}
        # CVSS v3.0 Ratings
        # Severity	Base Score Range
        # None	    0.0
        # Low	    0.1-3.9
        # Medium	4.0-6.9
        # High	    7.0-8.9
        # Critical	9.0-10.0
        for cve, cve_information in cve_data.items():
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

    def sort_by_cvss_rating_hosts(self, cve_data: dict = None, hosts: dict = None):
        cprint("Vulners: Sort nodes by CVSS levels...", "blue", attrs=["bold"])
        if not cve_data:
            cve_data = self.sort_by_cvss_rating()
        groupped_cve_hosts = {}
        for ip, host_info in hosts.items():
            vulnerabilities = host_info.get("vulnerabilities")
            if not vulnerabilities:
                continue
            all_vulnerabilities = []
            if vulnerabilities.get("shodan_vulnerabilities"):
                all_vulnerabilities.extend(list(vulnerabilities.get("shodan_vulnerabilities").keys()))
            if vulnerabilities.get("vulners_vulnerabilities"):
                all_vulnerabilities.extend(list(vulnerabilities.get("vulners_vulnerabilities").keys()))
            all_unique_vulnerabilities = list(set(all_vulnerabilities))
            for group, groupped_vulnerabilities in cve_data.items():
                check_if_group_match = any(vulnerability in all_unique_vulnerabilities
                                           for vulnerability in groupped_vulnerabilities)
                if not check_if_group_match:
                    continue
                if not groupped_cve_hosts.get(group):
                    groupped_cve_hosts[group] = [host_info]
                else:
                    groupped_cve_hosts[group].append(host_info)
        return groupped_cve_hosts

    def get_exploits_for_vulnerabilities(self):
        cprint("Vulners: Collect all exploits references for collected vulnerabilities...", "blue", attrs=["bold"])
        try:
            vulners_api = Vulners(api_key=self.api_key)
        except ValueError as wrong_key:
            print("Error:", wrong_key)
            return {}
        references = vulners_api.referencesList(list(self.vulnerabilities.keys()))
        exploits = {}

        for cve, cve_references in references.items():
            for id, reference in cve_references.items():
                for entity in reference:
                    bulletin = entity.get("bulletinFamily")
                    if not bulletin:
                        continue
                    if bulletin.lower() == "exploit":
                        if exploits.get(cve):
                            exploits[cve].append(entity)
                        else:
                            exploits.update({cve: [entity]})
        return exploits

    def _parse_cpes(self, hosts: dict):
        # https://nmap.org/book/output-formats-cpe.html
        # https://cpe.mitre.org/specification/
        host_to_cpe = {}
        valid_cpe = compile(r"cpe:\/\S:\w+:\w+:.+")

        for host_ip, host_information in hosts.items():
            if not host_information.get("nmap_scan"):
                continue
            if not host_information["nmap_scan"].get("tcp"):
                continue
            for port_number, port_information in host_information["nmap_scan"]["tcp"].items():
                if not port_information.get("cpe"):
                    continue
                cpe_search = valid_cpe.findall(port_information.get("cpe"))
                if not cpe_search:
                    continue
                if not host_to_cpe.get(host_ip):
                    host_to_cpe.update({host_ip: {
                        port_number: {
                            "cpe_id": port_information.get("cpe"),
                            "cpe_info": []
                        }
                    }})
                else:
                    host_to_cpe[host_ip].update({
                        port_number: {
                            "cpe_id": port_information.get("cpe"),
                            "cpe_info": []
                        }
                    })
        return host_to_cpe

    def _count_unique_cpes(self, host_to_cpe):
        unique_cpes = []
        for ip, port_cpe in host_to_cpe.items():
            for cpe in port_cpe.values():
                if cpe.get("cpe_id") not in unique_cpes:
                    unique_cpes.append(cpe.get("cpe_id"))
        return unique_cpes

    def _search_cpe_exploits(self, unique_cpe, database_name="exploit"):
        try:
            vulners_api = Vulners(api_key=self.api_key)
        except ValueError as wrong_key:
            print("Error:", wrong_key)
            return {}
        cpe_with_exploits = {}
        for cpe in unique_cpe:
            cpe_results = vulners_api.cpeVulnerabilities(cpe)
            print(f"Software: {cpe}, available databases: {list(cpe_results.keys())}")
            if not cpe_results:
                continue
            cpe_exploit_list = cpe_results.get(database_name)
            if not cpe_exploit_list:
                continue
            cpe_with_exploits.update({cpe: cpe_exploit_list})
        return cpe_with_exploits

    def get_exploits_for_software(self, hosts: dict):
        cprint("Vulners: Collect all software exploits...", "blue", attrs=["bold"])
        host_to_cpe = self._parse_cpes(hosts)
        unique_cpe = self._count_unique_cpes(host_to_cpe)
        cpe_with_exploits = self._search_cpe_exploits(unique_cpe)

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