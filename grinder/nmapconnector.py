#!/usr/bin/python3

import nmap
import time

class NmapConnector:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results: dict = {}

    def scan(self, hosts: list, arguments='-A') -> None:
        hosts = ' '.join(hosts)
        self.nm.scan(hosts=hosts, arguments=arguments)
        self.results = {host: self.nm[host] for host in self.nm.all_hosts()}

    def get_results(self) -> dict:
        return self.results

    def get_results_count(self) -> int:
        return len(self.results)
