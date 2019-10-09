#!/usr/bin/env python3
from copy import deepcopy
from itertools import zip_longest
from os import listdir
from pathlib import Path
from random import choice
from re import compile
from subprocess import check_output, DEVNULL, TimeoutExpired
from typing import Iterator, Iterable

from nmap import PortScanner
from termcolor import cprint

from grinder.decorators import timer, exception_handler
from grinder.defaultvalues import DefaultTlsScannerValues, DefaultValues
from grinder.errors import GrinderCoreTlsScanner
from grinder.nmapprocessmanager import NmapProcessingManager


class TlsScanner:
    def __init__(
        self, hosts: dict, n: int = DefaultTlsScannerValues.LENGTH_OF_HOSTS_SUBGROUPS
    ) -> None:
        self.hosts: dict = hosts
        self.alive_hosts: list = []
        self.tls_ports: dict = {}
        self.all_ports: dict = {}
        self.alive_hosts_with_ports: dict = {}
        self.n: int = n
        self._prepare_results_directory()

    @staticmethod
    def _grouper(n: int, iterable: Iterable, padding=None) -> Iterator:
        """
        Make groups of n hosts
        :param n: quantity of hosts in group
        :param iterable: some iterable object to divide
        :param padding: is padding required if group is not full
        :return: return list of groups
        """
        return zip_longest(*[iter(iterable)] * n, fillvalue=padding)

    def _set_ping_status(self) -> None:
        """
        Add status of ping to result file
        :return: None
        """
        for ip, host_info in self.hosts.items():
            if ip in self.alive_hosts:
                host_info.update({"tls_status": "online"})
            else:
                host_info.update({"tls_status": "offline"})

    @staticmethod
    def sort_hosts_by_product(
        hosts: dict, product_limit: int = DefaultTlsScannerValues.PRODUCT_LIMIT
    ) -> dict:
        """
        Sort hosts by unique products in limited quantity
        (because scan can take too long to finish, it's
        better to divide it into parts)
        :param hosts: dictionary with hosts
        :param product_limit: limit of products for separating
        :return: hosts in limited quantity that was set in product_limit
        """
        if not product_limit:
            return hosts

        # Take all unique products and print it
        unique_products = list(set([host.get("product") for host in hosts.values()]))
        print("Unique products:", str(unique_products))

        # Add hosts until product limit
        fixed_hosts = {}
        for product in unique_products:
            current_product_quantity = 0
            for ip, host in hosts.items():
                if (
                    host.get("product") == product
                    and current_product_quantity < product_limit
                ):
                    fixed_hosts.update({ip: host})
                    current_product_quantity += 1
        return fixed_hosts

    def _remove_already_scanned_hosts(self, hosts: dict) -> dict:
        """
        Check if some hosts was already scanned and we
        got *.txt results for them in "tls" folder
        :param hosts: dictionary with hosts
        :return: hosts
        """
        online_hosts = deepcopy(hosts)

        for ip, info in hosts.items():
            vendor = info.get("vendor")
            product = info.get("product")
            port = info.get("port")
            # In some cases we got special ports, so we need to check it
            for possible_port in [443, 8443, port]:
                name_of_file = "{host}-{port}-{vendor}-{product}".format(
                    host=ip, port=str(possible_port), vendor=vendor, product=product
                ).replace(" ", "_")
                if self._is_host_already_scanned(name_of_file):
                    online_hosts.pop(ip)
                    break
        difference = len(list(hosts.keys())) - len(list(online_hosts.keys()))
        # Return number of already scanned hosts
        print(f"Remove already scanned hosts: {str(difference)}")
        return online_hosts

    def sort_alive_hosts(self) -> None:
        """
        Make fast pingscan for all hosts to check
        if it needed to be scanned with TLS-Scanner
        (reject all offline hosts)
        :return: None
        """
        nm = PortScanner()
        online_hosts = self._remove_already_scanned_hosts(self.hosts)
        online_hosts = self.sort_hosts_by_product(online_hosts)
        hosts_ip = list(online_hosts.keys())
        groups = self._grouper(self.n, hosts_ip)
        groups = [list(group) for group in groups]
        groups_len = len(groups)

        for index, group in enumerate(groups):
            print(f"│ Do pingscan for {self.n} hosts ({index}/{groups_len})")
            group_ips = [ip for ip in group if ip]
            hosts_in_nmap_format = " ".join(group_ips)
            nm.scan(
                hosts=hosts_in_nmap_format,
                arguments=DefaultTlsScannerValues.NMAP_PING_SCAN_ARGS,
            )
            results = nm.all_hosts()
            alive_hosts_group = [
                ip for ip in results if nm[ip]["status"]["state"] == "up"
            ]
            groups[index] = alive_hosts_group

        print(f"└ Done pingscan for {len(hosts_ip)} hosts")
        groups_flat = [host for group in groups for host in group]
        self.alive_hosts = groups_flat
        self._set_ping_status()

    def detect_tls_ports(
        self,
        host_timeout: int = DefaultTlsScannerValues.TLS_DETECTION_HOST_TIMEOUT,
        tls_workers: int = DefaultTlsScannerValues.TLS_NMAP_WORKERS,
    ) -> None:
        """
        This function tries to detect all SSL/TLS ports
        with Nmap - basically, we start Nmap scanning with all
        of the default scripts, and use "ssl-cert" for example to
        define if current service/port got SSL cert or something
        like this. If we got this information, we can assume
        that this is TLS/SSL port/service.
        :param host_timeout: host timeout for scanning
        :param tls_workers: quantity of TLS/Nmap workers
        :return:
        """
        hosts_in_nmap_format = [{"ip": ip, "port": ""} for ip in self.alive_hosts]
        ssl_scan = NmapProcessingManager(
            hosts=hosts_in_nmap_format,
            arguments=f"-Pn -T4 -A -sT --top-ports 50 --host-timeout={host_timeout}s",
            workers=tls_workers,
        )
        ssl_scan.start()
        scan_results = ssl_scan.get_results()
        for host, results in scan_results.items():
            tcp = results.get("tcp")
            if not tcp:
                continue
            self.all_ports[host] = list(tcp.keys())
            for port, service in tcp.items():
                scripts = service.get("script")
                if not scripts:
                    continue
                ssl_cert = scripts.get("ssl-cert")
                if not ssl_cert:
                    continue
                if self.tls_ports.get(host):
                    self.tls_ports[host].append(port)
                else:
                    self.tls_ports[host] = [port]
                self.hosts[host].update({"ssl_cert": ssl_cert})

            if self.tls_ports.get(host):
                self.hosts[host].update({"tls_ports": self.tls_ports[host]})

    def link_alive_hosts_with_tls_ports(self) -> None:
        """
        Predict compatible port for scanning
        :return: None
        """
        for host in self.alive_hosts:
            if self.tls_ports.get(host):
                if 443 in self.tls_ports[host]:
                    self.alive_hosts_with_ports[host] = 443
                elif 8443 in self.tls_ports[host]:
                    self.alive_hosts_with_ports[host] = 8443
                else:
                    self.alive_hosts_with_ports[host] = choice(self.tls_ports[host])
            elif self.all_ports.get(host):
                if 443 in self.all_ports[host]:
                    self.alive_hosts_with_ports[host] = 443
                elif 8443 in self.all_ports[host]:
                    self.alive_hosts_with_ports[host] = 8443
                else:
                    self.alive_hosts_with_ports[host] = 443
            else:
                self.alive_hosts_with_ports[host] = 443

    @timer
    @exception_handler(expected_exception=GrinderCoreTlsScanner)
    def _run_tls_on_host(
        self,
        scanner_path: Path or str,
        host: str,
        port: int or str,
        report_detail: str,
        scan_detail: str,
        threads: int or str,
    ) -> str or None:
        """
        Call TLS-Scanner module to scan TLS configuration, attacks and bugs
        :param scanner_path: path to TLS-Scanner jar file
        :param host: host URL or ip
        :param port: port to scan (443, 8443, etc.)
        :param report_detail: details of reports ("NORMAL" by default)
        :param scan_detail: details of scanning ("NORMAL" by default)
        :param threads: quantity of scanning threads (overallThreads, parallelProbes - 4/4 by default)
        :return: results of tls scanning or nothing in case of fail/error
        """
        command = [
            "java",
            "-jar",
            scanner_path,
            "-connect",
            str(host) + ":" + str(port),
            "-noColor",
            "-implementation",
            "-reportDetail",
            report_detail,
            "-scanDetail",
            scan_detail,
            "-overallThreads",
            str(threads),
            "-parallelProbes",
            str(threads),
        ]
        try:
            tls_scanner_res = check_output(
                command,
                universal_newlines=True,
                timeout=DefaultTlsScannerValues.TLS_SCANNER_TIMEOUT,
                stderr=DEVNULL,
            )
        except TimeoutExpired:
            print(f"└ Timeout expired: ", end="")
            return

        # Some kind of dirty hack to remove all the stupid ANSI console symbols
        ansi_escape = compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
        tls_scanner_res = ansi_escape.sub("", tls_scanner_res)
        print(f"└ ", end="")
        return tls_scanner_res

    @staticmethod
    def _is_host_already_scanned(name_of_file) -> bool:
        """
        Check if host was already scanned and results are in "TLS" directory
        :param name_of_file: name of file to check, without extension
        :return: answer to question "Is current host was already scanned?"
        """
        results_dir = (
            Path(".")
            .joinpath(DefaultValues.RESULTS_DIRECTORY)
            .joinpath(DefaultTlsScannerValues.TLS_SCANNER_RESULTS_DIR)
        )
        if f"{name_of_file}.txt" not in listdir(results_dir):
            return False
        else:
            with open(
                results_dir.joinpath(f"{name_of_file}.txt"), mode="r"
            ) as res_file:
                file_contains = res_file.read()
                if (
                    "Cannot reach the Server. Is it online?" in file_contains
                    and "online error caught" not in file_contains
                ):
                    print(f"Host {name_of_file} was offline. Try to rescan.")
                    return False
            print(f"Host was already scanned: {name_of_file}")
            return True

    @staticmethod
    def _prepare_results_directory() -> None:
        """
        Prepare directory for results
        :return: None
        """
        prepare_results_dir = (
            Path(".")
            .joinpath(DefaultValues.RESULTS_DIRECTORY)
            .joinpath(DefaultTlsScannerValues.TLS_SCANNER_RESULTS_DIR)
        )
        prepare_results_dir.mkdir(parents=True, exist_ok=True)

    @timer
    def start_tls_scan(
        self,
        report_detail: str = DefaultTlsScannerValues.TLS_SCANNER_REPORT_DETAIL,
        scan_detail: str = DefaultTlsScannerValues.TLS_SCANNER_SCAN_DETAIL,
        scanner_path: str = DefaultTlsScannerValues.TLS_SCANNER_PATH,
        threads: int = DefaultTlsScannerValues.TLS_SCANNER_THREADS,
    ) -> None:
        """
        Basic TLS-Scanner wrapper-runner to run scan on all hosts
        :param report_detail: details of report ("NORMAL" by default)
        :param scan_detail: details of scan ("NORMAL" by default)
        :param scanner_path: path to jar of TLS-Scanner
        :param threads: quantity of threads, 4/4 by default
        :return: None
        """
        alive_hosts_quantity = len(self.alive_hosts_with_ports.items())
        for index, host_port in enumerate(self.alive_hosts_with_ports.items()):
            host, port = host_port
            cprint(
                f"Start TLS scan for {index} from {alive_hosts_quantity} hosts",
                "blue",
                attrs=["bold"],
            )
            vendor = self.hosts[host].get("vendor")
            product = self.hosts[host].get("product")
            name_of_file = "{host}-{port}-{vendor}-{product}".format(
                host=host, port=str(port), vendor=vendor, product=product
            ).replace(" ", "_")
            print(f"│ Vendor: {vendor}")
            print(f"│ Product: {product}")
            print(f"│ Host: {host}")
            print(f"│ Port: {port}")
            print(f"│ File to save: {name_of_file}.txt")

            # Check if file already exists
            if self._is_host_already_scanned(name_of_file):
                continue

            try:
                tls_scanner_res = self._run_tls_on_host(
                    scanner_path=scanner_path,
                    host=host,
                    port=port,
                    report_detail=report_detail,
                    scan_detail=scan_detail,
                    threads=threads,
                )
            except Exception as unexp_err:
                print(f"└ TLS Scanning error ({str(unexp_err)})")
                continue
            if not tls_scanner_res:
                continue
            self.save_tls_results(
                dest_dir=DefaultValues.RESULTS_DIRECTORY,
                sub_dir=DefaultTlsScannerValues.TLS_SCANNER_RESULTS_DIR,
                filename=name_of_file,
                result=tls_scanner_res,
            )
        print(f"TLS scan for {alive_hosts_quantity} hosts: ", end="")

    @staticmethod
    def save_tls_results(dest_dir: str, sub_dir: str, filename: str, result) -> None:
        """
        Save results of TLS-Scanner scanning in *.txt file
        :param dest_dir: destination directory with results ("results" by default)
        :param sub_dir: destination subdirectory for TLS ("tls" by default)
        :param filename: name of file to write
        :param result: result to save in file
        :return: None
        """
        path_to_txt_file = Path(".").joinpath(dest_dir).joinpath(sub_dir).joinpath(f"{filename}.txt")
        with open(path_to_txt_file, mode="w") as result_file:
            result_file.write(result)
