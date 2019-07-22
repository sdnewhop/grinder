#!/usr/bin/env python3
from grinder.nmapprocessmanager import NmapProcessingManager
from grinder.decorators import create_results_directory, create_subdirectory
from grinder.defaultvalues import DefaultTlsScannerValues, DefaultValues

from nmap import PortScanner
from pprint import pprint
from itertools import zip_longest
from random import choice
from subprocess import check_output, DEVNULL
from re import compile


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

    def sort_alive_hosts(self):
        nm = PortScanner()
        hosts_ip = list(self.hosts.keys())
        groups = self._grouper(self.n, hosts_ip)
        groups = [list(group) for group in groups]
        groups_len = len(groups)
        for index, group in enumerate(groups):
            print(f"Pingscan for {self.n} hosts from group {index}/{groups_len}")
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
        groups_flat = [host for group in groups for host in group]
        self.alive_hosts = groups_flat
        self._set_ping_status()

    def detect_tls_ports(
        self,
        ssl_script_path: str = DefaultTlsScannerValues.SSL_NMAP_SCRIPT_PATH,
        host_timeout: int = DefaultTlsScannerValues.TLS_DETECTION_HOST_TIMEOUT,
    ):
        hosts_in_nmap_format = [{"ip": ip, "port": ""} for ip in self.alive_hosts]
        ssl_scan = NmapProcessingManager(
            hosts=hosts_in_nmap_format,
            arguments=f"-T4 -F -sC -sV --script=.{ssl_script_path} --version-intensity 1 --open --host-timeout={host_timeout}s",
            workers=10,
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
                if "Subject" in ssl_cert or "Issuer" in ssl_cert:
                    if self.tls_ports.get(host):
                        self.tls_ports[host].append(port)
                    else:
                        self.tls_ports[host] = [port]
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

    def start_tls_scan(
        self,
        report_detail: str = DefaultTlsScannerValues.TLS_SCANNER_REPORT_DETAIL,
        scan_detail: str = DefaultTlsScannerValues.TLS_SCANNER_SCAN_DETAIL,
        scanner_path: str = DefaultTlsScannerValues.TLS_SCANNER_PATH,
        threads: int = DefaultTlsScannerValues.TLS_SCANNER_THREADS,
    ):
        for host, port in self.alive_hosts_with_ports.items():
            print(f"Start tls scan for {host}")
            try:
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
                tls_scanner_res = check_output(
                    command,
                    universal_newlines=True,
                    timeout=DefaultTlsScannerValues.TLS_SCANNER_TIMEOUT,
                    stderr=DEVNULL,
                )
                ansi_escape = compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
                tls_scanner_res = ansi_escape.sub("", tls_scanner_res)
            except:
                continue
            vendor = self.hosts[host].get("vendor")
            product = self.hosts[host].get("product")
            name_of_file = "{host}-{port}-{vendor}-{product}".format(
                host=host, port=str(port), vendor=vendor, product=product
            ).replace(" ", "_")
            self.save_tls_results(
                dest_dir=DefaultValues.RESULTS_DIRECTORY,
                sub_dir=DefaultTlsScannerValues.TLS_SCANNER_RESULTS_DIR,
                filename=name_of_file,
                result=tls_scanner_res,
            )

    @create_results_directory()
    @create_subdirectory(subdirectory=DefaultTlsScannerValues.TLS_SCANNER_RESULTS_DIR)
    def save_tls_results(self, dest_dir: str, sub_dir: str, filename: str, result):
        with open(f"./{dest_dir}/{sub_dir}/{filename}.txt", mode="w") as result_file:
            result_file.write(result)
