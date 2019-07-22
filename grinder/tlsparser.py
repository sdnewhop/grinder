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
        attacks = {}
        for attack in LIST_OF_ATTACKS:
            attack_res = findall(r"{attack}\s+: (\w+)".format(attack=attack), results)
            if not attack_res:
                continue
            if attack_res[0] == "true":
                attacks.update({attack: True})
            elif attack_res[0] == "false":
                attacks.update({attack: False})

        bugs = {}
        for bug in LIST_OF_BUGS:
            bug_res = findall(r"{bug}\s+: (\w+)".format(bug=bug), results)
            if not bug_res:
                continue
            if bug_res[0] == "true":
                bugs.update({bug: True})
            elif bug_res[0] == "false":
                bugs.update({attack: False})

        return attacks, bugs

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
                search_pattern = findall(
                    r"(\d+.\d+.\d+.\d+)-(\d+)-(\w+)-(.+).txt", file
                )
                if not search_pattern:
                    continue
                ip, port, vendor, product = search_pattern[0]
                vendor = vendor.replace("_", " ")
                product = product.replace("_", " ")

                if not all_results.get(ip):
                    all_results.update(
                        {
                            ip: dict(
                                vendor=vendor,
                                product=product,
                                port=port,
                                attacks=attacks,
                                bugs=bugs,
                            )
                        }
                    )

                if self.hosts.get(ip):
                    if attacks:
                        self.hosts[ip].update(dict(attacks=attacks))
                    if bugs:
                        self.hosts[ip].update(dict(bugs=bugs))

        self.save_results(all_results)

    def save_results(
        self,
        results,
        dest_dir: str = DefaultValues.RESULTS_DIRECTORY,
        filename: str = DefaultTlsParserValues.ATTACKS_JSON,
    ):
        full_path = Path(".").joinpath(dest_dir).joinpath(filename)
        with open(full_path, "w") as alive_hosts:
            try:
                dump(results, alive_hosts, indent=4)
            except:
                raise Exception("Can not save hosts to json file")
