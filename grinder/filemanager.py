#!/usr/bin/env python3

from csv import DictWriter, QUOTE_ALL
from csv import writer as csv_writer
from json import load, dump, JSONDecodeError
from pathlib import Path

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultValues
from grinder.errors import (
    GrinderFileManagerOpenError,
    GrinderFileManagerJsonDecoderError,
)


class GrinderFileManager:
    def __init__(self):
        pass

    @staticmethod
    def get_queries(queries_file=DefaultValues.QUERIES_FILE) -> list:
        """
        This function loads file with queries that were defined by the user.
        :param queries_file: filename of file with queries to load
        :return: list with queries from json file
        """
        try:
            with open(Path(".").joinpath(queries_file), mode="r") as queries_file:
                return load(queries_file)
        except JSONDecodeError as unparse_json:
            raise GrinderFileManagerJsonDecoderError(unparse_json) from unparse_json
        except Exception as unexp_error:
            raise GrinderFileManagerOpenError(unexp_error) from unexp_error

    @staticmethod
    def load_data_from_file(
        load_dir=DefaultValues.RESULTS_DIRECTORY,
        load_file=DefaultValues.JSON_RESULTS_FILE,
        load_json_dir=DefaultValues.JSON_RESULTS_DIRECTORY,
    ) -> list:
        """
        This function loads some particular file from the filesystem.
        It is the same as get_queries, but with slightly different
        arguments and handling. With this function, we load
        the results of the last scan, for example.
        :param load_dir: base directory
        :param load_file: subdirectory
        :param load_json_dir: file to load
        :return: list with results (expected)
        """
        try:
            with open(
                Path(".")
                .joinpath(load_dir)
                .joinpath(load_json_dir)
                .joinpath(load_file),
                mode="r",
            ) as saved_results:
                return load(saved_results)
        except JSONDecodeError as unparse_json:
            raise GrinderFileManagerJsonDecoderError(unparse_json) from unparse_json
        except Exception as unexp_error:
            raise GrinderFileManagerOpenError(unexp_error) from unexp_error

    @staticmethod
    def csv_dict_fix(results_to_write: dict, field_name: str) -> list:
        """
        Converts dictionary
        from: {"one": 1, "two": 2}
        to: [{"test": "one", "count": 1}, {"test": "two", "count": 2}].

        This function is required because sometimes we got results
        in unexpected for us (and other functions) format,
        so we need to reformat data to use it as we want.
        :param results_to_write: results that we want to reformat
        :param field_name: strange name, i know, sorry. This argument is used
        to separate required name.
        :return: list of dictionaries instead of dictionary
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
        """
        This function is used to write results to some JSON file. We do
        not have special exception handling here and use
        base filemanager error handler to catch some errors.
        :param results_to_write: results that we want to dump in JSON file
        :param dest_dir: base destination dir to save results
        :param json_file: name of the JSON file
        :param json_dir: subdirectory in results folder to save JSONs
        :return: None
        """
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
        """
        Almost the same case as with the "write_results_json"
        function. We just write results to some CSV file.
        A special case here is calling of function "csv_dict_fix"
        when we need to convert some results in a special way.
        Check it out to understand what is happening here.
        :param results_to_write: results that we want to save in CSV file
        :param dest_dir: base destination dir to save results
        :param csv_file: name of the CSV file
        :param csv_dir: subdirectory in results folder to save CSVs
        :return: None
        """
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
                try:
                    del row["additional_info"]
                except:
                    pass
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
        """
        TL;DR: This function matches exploits to appropriate CVEs.
        In the more long way: this function firstly search for all
        products that connected with some particular CVE, for example,
        let it be CVE-2014-0160 and products like "OpenSSL, Apache, Nginx",
        any other, etc. Then, when all products are collected, we can
        match exploits to this CVEs and also to these products. On
        the finish, we will get results like:
        "CVE #1, List of products, Exploit #1, description"
        "CVE #1, List of products, Exploit #2, description"
        etc.
        :param results_to_write: this is CVE/Exploits collections with definitions
        :param dest_dir: destination dir to write results
        :param csv_file: file to save results
        :param hosts_results: results about all the scanned hosts
        :param csv_dir: directory to save CSVs
        :return: None
        """
        if not results_to_write:
            return
        vulnerabilities_mapping = {}
        for host, info in hosts_results.items():
            if not info.get("vulnerabilities"):
                continue
            for vulnerabilities_db, vulnerabilities_info in info.get(
                "vulnerabilities"
            ).items():
                if not vulnerabilities_info:
                    continue
                list_of_vulns = vulnerabilities_info.keys()
                for vulnerability in list_of_vulns:
                    if vulnerabilities_mapping.get(vulnerability):
                        if (
                            info.get("product")
                            not in vulnerabilities_mapping[vulnerability]
                        ):
                            vulnerabilities_mapping[vulnerability].append(
                                info.get("product")
                            )
                    else:
                        vulnerabilities_mapping.update(
                            {vulnerability: [info.get("product")]}
                        )

        path_to_csv_file = Path(".").joinpath(dest_dir).joinpath(csv_dir)
        path_to_csv_file.mkdir(parents=True, exist_ok=True)
        path_to_csv_file = path_to_csv_file.joinpath(csv_file)
        with open(path_to_csv_file, mode="w", newline="") as result_csv_file:
            _writer = csv_writer(
                result_csv_file, delimiter=",", quotechar='"', quoting=QUOTE_ALL
            )
            _writer.writerow(
                [
                    "CVE with exploit",
                    "Affected Products",
                    "Exploit title",
                    "Bulletin family",
                    "Exploit description",
                    "id",
                    "Exploit HREF",
                    "type",
                    "CVSS Score",
                    "CVSS Vector",
                    "Vulners HREF",
                ]
            )
            for cve, exploits in results_to_write.items():
                for exploit in exploits:
                    _writer.writerow(
                        [
                            cve,
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
                        ]
                    )

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    def write_results_png(
        self,
        plot,
        dest_dir: str,
        sub_dir: str,
        png_file: str,
        png_dir=DefaultValues.PNG_RESULTS_DIRECTORY,
    ) -> None:
        """
        Save plots to .png files
        :param plot: plot file
        :param dest_dir: directory to save results
        :param sub_dir: subdirectory to save results
        :param png_file: png file name
        :param png_dir: png directory to save
        :return: None
        """
        if not plot:
            return
        path_to_png_file = (
            Path(".").joinpath(dest_dir).joinpath(png_dir).joinpath(sub_dir)
        )
        path_to_png_file.mkdir(parents=True, exist_ok=True)
        path_to_png_file = path_to_png_file.joinpath(png_file)
        plot.savefig(path_to_png_file)
