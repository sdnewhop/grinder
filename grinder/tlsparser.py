#!/usr/bin/env python3
from collections import Counter, OrderedDict
from csv import DictWriter
from json import dump
from os import listdir
from pathlib import Path
from re import findall

from grinder.plots import GrinderPlots
from grinder.defaultvalues import (
    DefaultValues,
    DefaultTlsScannerValues,
    DefaultTlsParserValues,
)

# Possible list of attacks from TLS-Scanner
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

# Possible list of bugs from TLS-Scanner
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
    def __init__(self, hosts: dict) -> None:
        self.hosts: dict = hosts

    @staticmethod
    def _parse_attacks(results: str) -> (dict, dict) or (str, str):
        """
        Parse file with host results
        :param results: results for some host
        :return: dictionaries with attacks and bugs
        """

        # Return tuple with errors in case when
        # Some error was happened during TLS-Scanning
        if "Cannot reach the Server" in results:
            return "error", "error"
        if "Server does not seem to support SSL" in results:
            return "error", "error"

        # Parse attacks from results
        attacks = {}
        for attack in LIST_OF_ATTACKS:
            attack_res = findall(r"{attack}\s+: (\w+)".format(attack=attack), results)
            if not attack_res:
                continue
            if attack_res[0] == "true":
                attacks.update({attack: True})

        # Parse bugs from results
        bugs = {}
        for bug in LIST_OF_BUGS:
            bug_res = findall(r"{bug}\s+: (\w+)".format(bug=bug), results)
            if not bug_res:
                continue
            if bug == "CS Length Intolerant \(>512 Byte\)":
                bug = bug.replace("\\", "")
            if bug_res[0] == "true":
                bugs.update({bug: True})

        return attacks, bugs

    def _search_vulnerabilities(self, host_ip: str) -> list:
        """
        Parse vulnerabilities from basic results (Shodan/Vulners)
        :param host_ip: host to search vulnerabilities for
        :return: list of vulnerabilities
        """
        if not self.hosts.get(host_ip):
            return []
        if not self.hosts[host_ip].get("vulnerabilities"):
            return []
        vulns = self.hosts[host_ip].get("vulnerabilities")
        shodan_vulns = vulns.get("shodan_vulnerabilities") or []
        vulners_vulns = vulns.get("vulners_vulnerabilities") or []
        if shodan_vulns and isinstance(shodan_vulns, dict):
            shodan_vulns = list(shodan_vulns.keys())
        if vulners_vulns and isinstance(vulners_vulns, dict):
            vulners_vulns = list(vulners_vulns.keys())
        return list(set(list(shodan_vulns + vulners_vulns)))

    @staticmethod
    def save_plots(
        results: dict,
        suptitle: str,
        filename: str,
        directory: str = DefaultValues.PNG_TLS_RESULTS,
    ) -> None:
        """
        Save graphic plots for parsed TLS attacks and bugs
        :param results: results to build pie charts for
        :param suptitle: title of plot
        :param filename: filename to save
        :param directory: directory to save
        :return: None
        """
        plots = GrinderPlots()
        plots.create_pie_chart(results, suptitle)
        plots.save_pie_chart(relative_path=directory, filename=filename)

    def save_plots_per_product(self, all_results: dict) -> None:
        """
        Create all possible plots and charts for
        attacks and bugs, products and vendors
        :param all_results: all results that need to be processed
        :return: None
        """
        unique_products = list(
            set([info.get("product") for info in all_results.values()])
        )
        unique_vendors = list(
            set([info.get("vendor") for info in all_results.values()])
        )
        for product in unique_products:
            product_hosts = {}
            for ip, info in all_results.items():
                if info.get("product") != product:
                    continue
                product_hosts.update({ip: info})
            unique_attacks = self.count_unique_entities(
                product_hosts, ent_type="attacks"
            )
            unique_bugs = self.count_unique_entities(product_hosts, ent_type="bugs")
            product_to_name = product.replace(" ", "_")
            self.save_plots(
                unique_attacks,
                f"Quantity of unique attacks for {product}",
                f"tls_attacks_{product_to_name}.png",
                DefaultValues.PNG_TLS_ATTACKS_BY_PRODUCTS,
            )
            self.save_plots(
                unique_bugs,
                f"Quantity of unique bugs for {product}",
                f"tls_bugs_{product_to_name}.png",
                DefaultValues.PNG_TLS_BUGS_BY_PRODUCTS,
            )
        for vendor in unique_vendors:
            vendor_hosts = {}
            for ip, info in all_results.items():
                if info.get("vendor") != vendor:
                    continue
                vendor_hosts.update({ip: info})
            unique_attacks = self.count_unique_entities(
                vendor_hosts, ent_type="attacks"
            )
            unique_bugs = self.count_unique_entities(vendor_hosts, ent_type="bugs")
            vendor_to_name = vendor.replace(" ", "_")
            self.save_plots(
                unique_attacks,
                f"Quantity of unique attacks for {vendor}",
                f"tls_attacks_{vendor_to_name}.png",
                DefaultValues.PNG_TLS_ATTACKS_BY_VENDORS,
            )
            self.save_plots(
                unique_bugs,
                f"Quantity of unique bugs for {vendor}",
                f"tls_bugs_{vendor_to_name}.png",
                DefaultValues.PNG_TLS_BUGS_BY_VENDORS,
            )
        for attack in LIST_OF_ATTACKS:
            attack_hosts = {}
            for ip, info in all_results.items():
                if attack not in info.get("attacks").keys():
                    continue
                attack_hosts.update({ip: info})
            unique_vendors = self.count_unique_entities(
                attack_hosts, ent_type="vendor", flat_list_flag=False
            )
            unique_products = self.count_unique_entities(
                attack_hosts, ent_type="product", flat_list_flag=False
            )
            attack_to_name = attack.replace(" ", "_")
            self.save_plots(
                unique_vendors,
                f"Quantity of unique vendors for {attack}",
                f"tls_attacks_{attack_to_name}.png",
                DefaultValues.PNG_TLS_VENDORS_BY_ATTACKS,
            )
            self.save_plots(
                unique_products,
                f"Quantity of unique products for {attack}",
                f"tls_attacks_{attack_to_name}.png",
                DefaultValues.PNG_TLS_PRODUCTS_BY_ATTACKS,
            )
        for bug in LIST_OF_BUGS:
            bug_hosts = {}
            for ip, info in all_results.items():
                if bug == "CS Length Intolerant \(>512 Byte\)":
                    bug = bug.replace("\\", "")
                if bug not in info.get("bugs").keys():
                    continue
                bug_hosts.update({ip: info})
            unique_vendors = self.count_unique_entities(
                bug_hosts, ent_type="vendor", flat_list_flag=False
            )
            unique_products = self.count_unique_entities(
                bug_hosts, ent_type="product", flat_list_flag=False
            )
            bug_to_name = bug.replace(" ", "_")
            self.save_plots(
                unique_vendors,
                f"Quantity of unique vendors for {bug}",
                f"tls_bugs_{bug_to_name}.png",
                DefaultValues.PNG_TLS_VENDORS_BY_BUGS,
            )
            self.save_plots(
                unique_products,
                f"Quantity of unique products for {bug}",
                f"tls_bugs_{bug_to_name}.png",
                DefaultValues.PNG_TLS_PRODUCTS_BY_BUGS,
            )

    def load_tls_scan_results(
        self,
        dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
        tls_dir: str = DefaultTlsScannerValues.TLS_SCANNER_RESULTS_DIR,
    ) -> None:
        """
        Load all results from TLS scanning
        :param dest_dir: directory with basic results
        :param tls_dir: subdirectory with TLS results
        :return: None
        """
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
        unique_vulnerabilities = self.count_unique_entities(
            all_results, ent_type="vulnerabilities"
        )

        self.save_plots_per_product(all_results)
        self.save_plots(unique_attacks, "Quantity of unique attacks", "tls_attacks.png")
        self.save_plots(unique_bugs, "Quantity of unique bugs", "tls_bugs.png")

        self.save_results_json(
            all_results, filename=DefaultTlsParserValues.FULL_RESULTS_JSON
        )
        self.save_results_json(
            unique_attacks, filename=DefaultTlsParserValues.UNIQUE_ATTACKS_JSON
        )
        self.save_results_json(
            unique_bugs, filename=DefaultTlsParserValues.UNIQUE_BUGS_JSON
        )
        self.save_results_json(
            unique_vulnerabilities,
            filename=DefaultTlsParserValues.UNIQUE_VULNERABILITIES_JSON,
        )

        self.save_results_csv(
            all_results, filename=DefaultTlsParserValues.FULL_RESULTS_CSV
        )
        self.save_unique_results_csv(
            unique_attacks, filename=DefaultTlsParserValues.UNIQUE_ATTACKS_CSV
        )
        self.save_unique_results_csv(
            unique_bugs, filename=DefaultTlsParserValues.UNIQUE_BUGS_CSV
        )
        self.save_unique_results_csv(
            unique_vulnerabilities,
            filename=DefaultTlsParserValues.UNIQUE_VULNERABILITIES_CSV,
        )

        self.save_unique_groupped_results_csv(
            all_results,
            filename=DefaultTlsParserValues.UNIQUE_GROUPPED_PRODUCTS_RESULTS_CSV,
        )

    @staticmethod
    def count_unique_entities(
        results: dict, ent_type: str, flat_list_flag: bool = True
    ) -> dict:
        """
        Count unique entities (attacks, bugs, vulnerabilities, etc.)
        :param results: dictionary with results to count in
        :param ent_type: type of entity to count
        :param flat_list: is list need to be flattened
        :return: sorted entities in dictionary
        """
        all_attacks = [host.get(ent_type) for host in results.values()]
        if flat_list_flag:
            flat_list = [item for sublist in all_attacks for item in sublist]
        else:
            flat_list = all_attacks
        counter = Counter(flat_list)
        entities_sorted_by_value = dict(
            sorted(counter.items(), key=lambda x: x[1], reverse=True)
        )
        return entities_sorted_by_value

    @staticmethod
    def save_results_json(
        results: dict or list,
        filename: str,
        dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
        sub_dir: str = DefaultTlsParserValues.PARSED_RESULTS_DIR,
    ) -> None:
        """
        Save some results to json file
        :param results: results to save in file
        :param filename: name of file
        :param dest_dir: basic results dir
        :param sub_dir: subdirectory in destination directory to save
        :return: None
        """
        full_path = Path(".").joinpath(dest_dir).joinpath(sub_dir)
        full_path.mkdir(parents=True, exist_ok=True)
        full_path = full_path.joinpath(filename)
        with open(full_path, "w") as alive_hosts:
            try:
                dump(results, alive_hosts, indent=4)
            except:
                raise Exception("Can not save hosts to json file")

    @staticmethod
    def save_results_csv(
        results: dict,
        filename: str,
        dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
        sub_dir: str = DefaultTlsParserValues.PARSED_RESULTS_DIR,
    ) -> None:
        """
        Save results to CSV file
        :param results: results to save in file
        :param filename: name of file
        :param dest_dir: basic results dir
        :param sub_dir: subdirectory in destination directory to save
        :return: None
        """
        full_path = Path(".").joinpath(dest_dir).joinpath(sub_dir)
        full_path.mkdir(parents=True, exist_ok=True)
        full_path = full_path.joinpath(filename)
        csv_columns = [
            "ip",
            "vendor",
            "product",
            "port",
            "attacks",
            "bugs",
            "vulnerabilities",
        ]

        with open(full_path, "w") as csv_file:
            writer = DictWriter(csv_file, fieldnames=csv_columns)
            writer.writeheader()

            sorted_by_vendor = sorted(
                results.items(), key=lambda item: item[1].get("product")
            )
            results = OrderedDict(sorted_by_vendor)

            for ip, data in results.items():
                data.update({"ip": ip})
                data.update({"attacks": list(data["attacks"].keys())})
                data.update({"bugs": list(data["bugs"].keys())})
                writer.writerow(data)

    @staticmethod
    def save_unique_results_csv(
        results: dict,
        filename: str,
        dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
        sub_dir: str = DefaultTlsParserValues.PARSED_RESULTS_DIR,
    ) -> None:
        """
        Save unique results to CSV file
        :param results: results to save in file
        :param filename: name of file
        :param dest_dir: basic results dir
        :param sub_dir: subdirectory in destination directory to save
        :return: None
        """
        full_path = Path(".").joinpath(dest_dir).joinpath(sub_dir)
        full_path.mkdir(parents=True, exist_ok=True)
        full_path = full_path.joinpath(filename)
        csv_columns = ["name", "quantity"]

        with open(full_path, "w") as csv_file:
            writer = DictWriter(csv_file, fieldnames=csv_columns)
            writer.writeheader()
            for name, quantity in results.items():
                writer.writerow({"name": name, "quantity": quantity})

    @staticmethod
    def save_unique_groupped_results_csv(
        results: dict,
        filename: str,
        dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
        sub_dir: str = DefaultTlsParserValues.PARSED_RESULTS_DIR,
    ) -> None:
        """
        Save groupped results with unique attacks and bugs
        for every vendor in total and for every product
        :param results: results to save in file
        :param filename: name of file
        :param dest_dir: basic results dir
        :param sub_dir: subdirectory in destination directory to save
        :return: None
        """
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
                }
                for host in results.values()
                if attack in host.get("attacks")
            ]
            groupped_results.update({attack: {}})
            attack_vendors = list(
                set([host.get("vendor") for host in products_with_this_attack])
            )
            for vendor in attack_vendors:
                groupped_results[attack].update({vendor: {}})
                attack_products = list(
                    set(
                        [
                            host.get("product")
                            for host in products_with_this_attack
                            if host.get("vendor") == vendor
                        ]
                    )
                )
                for product in attack_products:
                    ips = [
                        host.get("ip") + ":" + host.get("port")
                        for host in products_with_this_attack
                        if host.get("vendor") == vendor
                        and host.get("product") == product
                    ]
                    quantity = len(ips)

                    sorted_ips = {product: {"ips": ips, "quantity": quantity}}
                    sorted_ips_by_quantity = sorted(
                        sorted_ips.items(),
                        key=lambda item: item[1].get("quantity"),
                        reverse=True,
                    )
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
                        "quantity": sum(
                            [info.get("quantity") for info in product.values()]
                        ),
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
