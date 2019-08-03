#!/usr/bin/env python3
from os import listdir
from re import findall
from json import dump
from pprint import pprint
from pathlib import Path
from grinder.defaultvalues import (
    DefaultValues,
    DefaultTlsScannerValues,
    DefaultTlsParserValues,
)
from csv import DictWriter
from collections import Counter, OrderedDict

LIST_OF_ATTACKS = [
    "Padding Oracle",
    "Bleichenbacher",
    "CRIME",
    "Breach",
    "Invalid Curve",
    "Invalid Curve Ephemerals",
    "SSL Poodle",
    "TLS Poodle",
    "CVE-20162107",
    "Logjam",
    "Sweet 32",
    "DROWN",
    "Heartbleed",
    "EarlyCcs",
]

LIST_OF_BUGS = [
    "Version Intolerant",
    "Ciphersuite Intolerant",
    "Extension Intolerant",
    "CS Length Intolerant \(>512 Byte\)",
    "Compression Intolerant",
    "ALPN Intolerant",
    "CH Length Intolerant",
    "NamedGroup Intolerant",
    "Empty last Extension Intolerant",
    "SigHashAlgo Intolerant",
    "Big ClientHello Intolerant",
    "2nd Ciphersuite Byte Bug",
    "Ignores offered Ciphersuites",
    "Reflects offered Ciphersuites",
    "Ignores offered NamedGroups",
    "Ignores offered SigHashAlgos",
]


class TlsParser:
    def __init__(self, hosts: dict):
        self.hosts: dict = hosts

    def _parse_attacks(self, results: str) -> (dict, dict):
        if "Cannot reach the Server" in results:
            return "error", "error"
        if "Server does not seem to support SSL" in results:
            return "error", "error"
        attacks = {}
        for attack in LIST_OF_ATTACKS:
            attack_res = findall(r"{attack}\s+: (\w+)".format(attack=attack), results)
            if not attack_res:
                continue
            if attack_res[0] == "true":
                attacks.update({attack: True})

        bugs = {}
        for bug in LIST_OF_BUGS:
            bug_res = findall(r"{bug}\s+: (\w+)".format(bug=bug), results)
            if not bug_res:
                continue
            if bug_res[0] == "true":
                bugs.update({bug: True})

        return attacks, bugs

    def _search_vulnerabilities(self, host_ip):
        if not self.hosts.get(host_ip):
            return []
        if not self.hosts[host_ip].get("vulnerabilities"):
            return []
        vulns = self.hosts[host_ip].get("vulnerabilities")
        shodan_vulns = vulns.get("shodan_vulnerabilities") or []
        vulners_vulns = vulns.get("vulners_vulnerabilities") or []
        if shodan_vulns:
            shodan_vulns = list(shodan_vulns.keys())
        if vulners_vulns:
            vulners_vulns = list(vulners_vulns.keys())
        return list(set(list(shodan_vulns + vulners_vulns)))

    def load_tls_scan_results(
        self,
        dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
        tls_dir: str = DefaultTlsScannerValues.TLS_SCANNER_RESULTS_DIR,
    ) -> None:
        all_results = {}
        full_path = Path(".").joinpath(dest_dir).joinpath(tls_dir)

        for file in listdir(full_path):
            with open(full_path.joinpath(file), mode="r") as host_tls_results:
                results = host_tls_results.read()

                attacks, bugs = self._parse_attacks(results)
                if attacks == "error" and bugs == "error":
                    continue

                search_pattern = findall(
                    r"(\d+.\d+.\d+.\d+)-(\d+)-(\w+)-(.+).txt", file
                )
                if not search_pattern:
                    continue
                ip, port, vendor, product = search_pattern[0]
                vendor = vendor.replace("_", " ")
                product = product.replace("_", " ")
                vulnerabilities = self._search_vulnerabilities(host_ip=ip)

                if not all_results.get(ip):
                    all_results.update(
                        {
                            ip: dict(
                                vendor=vendor,
                                product=product,
                                port=port,
                                attacks=attacks,
                                bugs=bugs,
                                vulnerabilities=vulnerabilities,
                            )
                        }
                    )

                if self.hosts.get(ip):
                    if attacks:
                        self.hosts[ip].update(dict(attacks=attacks))
                    if bugs:
                        self.hosts[ip].update(dict(bugs=bugs))

        unique_attacks = self.count_unique_entities(all_results, ent_type="attacks")
        unique_bugs = self.count_unique_entities(all_results, ent_type="bugs")
        unique_vulnerabilities = self.count_unique_entities(all_results, ent_type="vulnerabilities")

        self.save_results_json(all_results)
        self.save_results_json(unique_attacks, filename="tls_scanner_attacks.json")
        self.save_results_json(unique_bugs, filename="tls_scanner_bugs.json")
        self.save_results_json(unique_vulnerabilities, filename="tls_scanner_vulnerabilities.json")

        self.save_results_csv(all_results)
        self.save_unique_results_csv(unique_attacks, filename="tls_scanner_attacks.csv")
        self.save_unique_results_csv(unique_bugs, filename="tls_scanner_bugs.csv")
        self.save_unique_results_csv(unique_vulnerabilities, filename="tls_scanner_vulnerabilities.csv")

        self.save_unique_groupped_results_csv(all_results, filename="tls_scanner_groupped.csv")


    def count_unique_entities(self, results, ent_type="attacks"):
        all_attacks = [host.get(ent_type) for host in results.values()]
        flat_list = [item for sublist in all_attacks for item in sublist]
        counter = Counter(flat_list)
        entities_sorted_by_value = dict(
            sorted(counter.items(), key=lambda x: x[1], reverse=True)
        )
        return entities_sorted_by_value

    def save_results_json(
        self,
        results,
        dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
        sub_dir: str = DefaultTlsParserValues.PARSED_RESULTS_DIR,
        filename: str = DefaultTlsParserValues.ATTACKS_JSON,
    ):
        full_path = Path(".").joinpath(dest_dir).joinpath(sub_dir)
        full_path.mkdir(parents=True, exist_ok=True)
        full_path = full_path.joinpath(filename)
        with open(full_path, "w") as alive_hosts:
            try:
                dump(results, alive_hosts, indent=4)
            except:
                raise Exception("Can not save hosts to json file")

    def save_results_csv(
            self,
            results,
            dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
            sub_dir: str = DefaultTlsParserValues.PARSED_RESULTS_DIR,
            filename: str = DefaultTlsParserValues.ATTACKS_CSV,
        ):
            full_path = Path(".").joinpath(dest_dir).joinpath(sub_dir)
            full_path.mkdir(parents=True, exist_ok=True)
            full_path = full_path.joinpath(filename)
            csv_columns = ["ip", "vendor", "product", "port", "attacks", "bugs", "vulnerabilities"]

            with open(full_path, "w") as csv_file:
                writer = DictWriter(csv_file, fieldnames=csv_columns)
                writer.writeheader()

                sorted_by_vendor = sorted(results.items(), key=lambda item: item[1].get("product"))
                results = OrderedDict(sorted_by_vendor)

                for ip, data in results.items():
                    data.update({"ip": ip})
                    data.update({"attacks": list(data["attacks"].keys())})
                    data.update({"bugs": list(data["bugs"].keys())})
                    writer.writerow(data) 

    def save_unique_results_csv(
            self,
            results,
            dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
            sub_dir: str = DefaultTlsParserValues.PARSED_RESULTS_DIR,
            filename: str = DefaultTlsParserValues.ATTACKS_CSV,
        ):
            full_path = Path(".").joinpath(dest_dir).joinpath(sub_dir)
            full_path.mkdir(parents=True, exist_ok=True)
            full_path = full_path.joinpath(filename)
            csv_columns = ["name", "quantity"]

            with open(full_path, "w") as csv_file:
                writer = DictWriter(csv_file, fieldnames=csv_columns)
                writer.writeheader()
                for name, quantity in results.items():
                    writer.writerow({"name": name, "quantity": quantity})
    
    def save_unique_groupped_results_csv(
        self,
        results,
        dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
        sub_dir: str = DefaultTlsParserValues.PARSED_RESULTS_DIR,
        filename: str = DefaultTlsParserValues.ATTACKS_CSV,
    ):
        full_path = Path(".").joinpath(dest_dir).joinpath(sub_dir)
        full_path.mkdir(parents=True, exist_ok=True)
        full_path = full_path.joinpath(filename)

        all_attacks = [host.get("attacks") for host in results.values()]
        flat_list = [item for sublist in all_attacks for item in sublist]
        counter = Counter(flat_list)
        entities_sorted_by_value = dict(
            sorted(counter.items(), key=lambda x: x[1], reverse=True)
        )
        
        groupped_results = {}
        for attack, quantity in entities_sorted_by_value.items():
            products_with_this_attack = [
                {
                    "vendor": host.get("vendor"),
                    "product": host.get("product"),
                    "ip": host.get("ip"),
                    "port": host.get("port"),
                } for host in results.values() if attack in host.get("attacks")]
            groupped_results.update({attack: {}})
            attack_vendors = list(set([host.get("vendor") for host in products_with_this_attack]))
            for vendor in attack_vendors:
                groupped_results[attack].update({vendor: {}})
                attack_products = list(set([host.get("product") for host in products_with_this_attack if host.get("vendor") == vendor]))
                for product in attack_products: 
                    ips = [host.get("ip") + ":" + host.get("port") for host in products_with_this_attack if host.get("vendor") == vendor and host.get("product") == product]
                    quantity = len(ips)
                    
                    sorted_ips = {
                        product: {
                            "ips": ips, 
                            "quantity": quantity
                        }
                    }
                    sorted_ips_by_quantity = sorted(sorted_ips.items(), key=lambda item: item[1].get("quantity"), reverse=True)
                    res_sorted_dict = OrderedDict(sorted_ips_by_quantity)
                    groupped_results[attack][vendor].update(res_sorted_dict)

        csv_columns = ["attack", "vendor", "product", "versions", "ips", "quantity"]
        with open(full_path, "w") as csv_file:
            writer = DictWriter(csv_file, fieldnames=csv_columns)
            writer.writeheader()
            for attack, vendor in groupped_results.items():
                for vendor, product in vendor.items():
                    all_ips = [info.get("ips") for info in product.values()]
                    vendor_row = {
                        "attack": attack,
                        "vendor": vendor + " " + "(total)",
                        "product": "",
                        "versions": None,
                        "ips": [item for sublist in all_ips for item in sublist],
                        "quantity": sum([info.get("quantity") for info in product.values()])
                    }
                    writer.writerow(vendor_row)
                    for product, info in product.items():
                        row = {
                            "attack": attack, 
                            "vendor": vendor, 
                            "product": product, 
                            "versions": None,
                            "ips": info.get("ips"), 
                            "quantity": info.get("quantity"),
                        }
                        writer.writerow(row)
