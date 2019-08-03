#!/usr/bin/env python3
from grinder.nmapprocessmanager import NmapProcessingManager
from grinder.decorators import create_results_directory, create_subdirectory, timer, exception_handler
from grinder.defaultvalues import DefaultTlsScannerValues, DefaultValues
from grinder.errors import GrinderCoreTlsScanner

from nmap import PortScanner
from pprint import pprint
from itertools import zip_longest
from random import choice
from subprocess import check_output, DEVNULL, TimeoutExpired
from re import compile
from termcolor import cprint
from pathlib import Path
from os import listdir
from copy import deepcopy


class TlsScanner:
    def __init__(
        self, hosts: dict, n: int = DefaultTlsScannerValues.LENGTH_OF_HOSTS_SUBGROUPS
    ):
        self.hosts: dict = hosts
        self.alive_hosts: list = []
        self.tls_ports: dict = {}
        self.all_ports: dict = {}
        self.alive_hosts_with_ports: dict = {}
        self.n: int = n

    def _grouper(self, n, iterable, padding=None):
        return zip_longest(*[iter(iterable)] * n, fillvalue=padding)

    def _set_ping_status(self):
        for ip, host_info in self.hosts.items():
            if ip in self.alive_hosts:
                host_info.update({"tls_status": "online"})
            else:
                host_info.update({"tls_status": "offline"})

    def sort_hosts_by_product(self, hosts: dict, product_limit: int = DefaultTlsScannerValues.PRODUCT_LIMIT):
        if not product_limit:
            return hosts
        unique_products = list(set([host.get("product") for host in hosts.values()]))
        print("Unique products:", str(unique_products))
        fixed_hosts = {}
        for product in unique_products:
            current_product_quantity = 0
            for ip, host in hosts.items():
                if host.get("product") == product and current_product_quantity < product_limit:
                    fixed_hosts.update({ip: host})
                    current_product_quantity += 1
        return fixed_hosts
    
    def _remove_already_scanned_hosts(self, hosts: dict):
        copy_hosts = deepcopy(hosts)
        for ip, info in copy_hosts.items():
            vendor = info.get("vendor")
            product = info.get("product")
            port = info.get("port")
            for possible_port in [443, 8443, port]:
                name_of_file = "{host}-{port}-{vendor}-{product}".format(
                    host=ip, port=str(possible_port), vendor=vendor, product=product
                ).replace(" ", "_")
                if self._is_host_already_scanned(name_of_file):
                    hosts.pop(ip)
                    break
        difference = len(list(copy_hosts.keys())) - len(list(hosts.keys()))
        print(f"Remove already scanned hosts: {str(difference)}")
        return hosts


    def sort_alive_hosts(self):
        nm = PortScanner()
        self.hosts = self._remove_already_scanned_hosts(self.hosts)
        self.hosts = self.sort_hosts_by_product(self.hosts)
        hosts_ip = list(self.hosts.keys())
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
    ):
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

    def link_alive_hosts_with_tls_ports(self):
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
        self, scanner_path, host, port, report_detail, scan_detail, threads
    ):
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

        ansi_escape = compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
        tls_scanner_res = ansi_escape.sub("", tls_scanner_res)
        print(f"└ ", end="")
        return tls_scanner_res

    def _is_host_already_scanned(self, name_of_file):
        if f"{name_of_file}.txt" in listdir(
            Path(".")
            .joinpath(DefaultValues.RESULTS_DIRECTORY)
            .joinpath(DefaultTlsScannerValues.TLS_SCANNER_RESULTS_DIR)):
            print(f"Host was already scanned: {name_of_file}")
            return True
        else:
            return False

    @timer
    def start_tls_scan(
        self,
        report_detail: str = DefaultTlsScannerValues.TLS_SCANNER_REPORT_DETAIL,
        scan_detail: str = DefaultTlsScannerValues.TLS_SCANNER_SCAN_DETAIL,
        scanner_path: str = DefaultTlsScannerValues.TLS_SCANNER_PATH,
        threads: int = DefaultTlsScannerValues.TLS_SCANNER_THREADS,
    ):
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

    @create_results_directory()
    @create_subdirectory(subdirectory=DefaultTlsScannerValues.TLS_SCANNER_RESULTS_DIR)
    def save_tls_results(self, dest_dir: str, sub_dir: str, filename: str, result):
        with open(
            Path(".")
            .joinpath(dest_dir)
            .joinpath(sub_dir).joinpath(f"{filename}.txt"), mode="w") as result_file:
            result_file.write(result)
