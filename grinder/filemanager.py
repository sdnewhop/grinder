#!/usr/bin/env python3

from csv import DictWriter, QUOTE_ALL
from csv import writer as csv_writer
from json import load, dump
from pathlib import Path

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultValues
from grinder.errors import GrinderFileManagerOpenError


class GrinderFileManager:
    def __init__(self):
        pass

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    def get_queries(self, queries_file=DefaultValues.QUERIES_FILE) -> list:
        with open(Path(".").joinpath(queries_file), mode="r") as queries_file:
            return load(queries_file)

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    def load_data_from_file(
        self,
        load_dir=DefaultValues.RESULTS_DIRECTORY,
        load_file=DefaultValues.JSON_RESULTS_FILE,
        load_json_dir=DefaultValues.JSON_RESULTS_DIRECTORY,
    ) -> list:
        with open(Path(".").joinpath(load_dir).joinpath(load_json_dir).joinpath(load_file), mode="r") as saved_results:
            return load(saved_results)

    @staticmethod
    def csv_dict_fix(results_to_write: dict, field_name: str) -> list:
        """
        Converts dict
        from: {"one": 1, "two": 2}
        to: [{"test": "one", "count": 1}, {"test": "two", "count": 2}]
        :param results_to_write:
        :param field_name:
        :return:
        """
        dict_to_list_dictpairs: list = []
        for item in results_to_write.items():
            dict_to_list_dictpairs.append(
                {field_name.split(".csv")[0]: item[0], "count": item[1]}
            )
        return dict_to_list_dictpairs

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    def write_results_json(
        self,
        results_to_write: list or dict,
        dest_dir: str,
        json_file: str,
        json_dir=DefaultValues.JSON_RESULTS_DIRECTORY,
    ) -> None:
        if not results_to_write:
            return
        path_to_json_file = Path(".").joinpath(dest_dir).joinpath(json_dir)
        path_to_json_file.mkdir(parents=True, exist_ok=True)
        path_to_json_file = path_to_json_file.joinpath(json_file)
        with open(path_to_json_file, mode="w") as result_json_file:
            dump(results_to_write, result_json_file, indent=4)

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    def write_results_csv(
        self,
        results_to_write: list or dict,
        dest_dir: str,
        csv_file: str,
        csv_dir=DefaultValues.CSV_RESULTS_DIRECTORY,
    ) -> None:
        if not results_to_write:
            return
        path_to_csv_file = Path(".").joinpath(dest_dir).joinpath(csv_dir)
        path_to_csv_file.mkdir(parents=True, exist_ok=True)
        path_to_csv_file = path_to_csv_file.joinpath(csv_file)
        with open(path_to_csv_file, mode="w") as result_csv_file:
            if isinstance(results_to_write, dict):
                results_to_write = GrinderFileManager.csv_dict_fix(
                    results_to_write, csv_file
                )
            maximum_fields = max(results_to_write, key=len)
            writer = DictWriter(result_csv_file, fieldnames=maximum_fields.keys())
            writer.writeheader()
            for row in results_to_write:
                writer.writerow(row)

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    def write_results_csv_exploits_to_cve(
        self,
        results_to_write: list or dict,
        dest_dir: str,
        csv_file: str,
        hosts_results: dict,
        csv_dir=DefaultValues.CSV_RESULTS_DIRECTORY,
    ) -> None:
        if not results_to_write:
            return
        vulnerabilities_mapping = {}
        for host, info in hosts_results.items():
            if not info.get("vulnerabilities"):
                continue
            for vulnerabilities_db, vulnerabilities_info in info.get("vulnerabilities").items():
                if not vulnerabilities_info:
                    continue
                list_of_vulns = vulnerabilities_info.keys()
                for vulnerability in list_of_vulns:
                    if vulnerabilities_mapping.get(vulnerability):
                        if info.get("product") not in vulnerabilities_mapping[vulnerability]:
                            vulnerabilities_mapping[vulnerability].append(info.get("product"))
                    else:
                        vulnerabilities_mapping.update({vulnerability: [info.get("product")]})

        path_to_csv_file = Path(".").joinpath(dest_dir).joinpath(csv_dir)
        path_to_csv_file.mkdir(parents=True, exist_ok=True)
        path_to_csv_file = path_to_csv_file.joinpath(csv_file)
        with open(path_to_csv_file, mode="w", newline='') as result_csv_file:
            _writer = csv_writer(result_csv_file, delimiter=',',
                                 quotechar='"', quoting=QUOTE_ALL)
            _writer.writerow(["CVE with exploit", "Affected Products", "Exploit title", "Bulletin family", 
                              "Exploit description", "id", "Exploit HREF", "type", "CVSS Score",
                              "CVSS Vector", "Vulners HREF"])
            for cve, exploits in results_to_write.items():
                for exploit in exploits:
                    _writer.writerow([cve,
                                      ", ".join(vulnerabilities_mapping.get(cve)),
                                      exploit.get("title"),
                                      exploit.get("bulletinFamily"),
                                      exploit.get("description"),
                                      exploit.get("id"),
                                      exploit.get("href"),
                                      exploit.get("type"),
                                      exploit.get("cvss", {}).get("score"),
                                      exploit.get("cvss", {}).get("vector"),
                                      exploit.get("vhref"),
                                      ])

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    def write_results_png(
        self,
        plot,
        dest_dir: str,
        sub_dir: str,
        png_file: str,
        png_dir=DefaultValues.PNG_RESULTS_DIRECTORY,
    ) -> None:
        if not plot:
            return
        path_to_png_file = Path(".").joinpath(dest_dir).joinpath(png_dir).joinpath(sub_dir)
        path_to_png_file.mkdir(parents=True, exist_ok=True)
        path_to_png_file = path_to_png_file.joinpath(png_file)
        plot.savefig(path_to_png_file)
