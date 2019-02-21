#!/usr/bin/env python3

from csv import DictWriter
from json import loads, dumps

from grinder.decorators import exception_handler, create_results_directory, create_subdirectory
from grinder.defaultvalues import DefaultValues
from grinder.errors import GrinderFileManagerOpenError


class GrinderFileManager:
    def __init__(self):
        pass

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    def get_queries(self, queries_file=DefaultValues.QUERIES_FILE) -> list:
        with open(queries_file) as queries_file:
            queries = loads(queries_file.read())
        return queries

    @staticmethod
    def csv_dict_fix(results_to_write: dict) -> list:
        dict_to_list_dictpairs: list = []
        for item in results_to_write.items():
            dict_to_list_dictpairs.append({'product': item[0], 'count': item[1]})
        return dict_to_list_dictpairs

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    @create_results_directory()
    @create_subdirectory(subdirectory=DefaultValues.JSON_RESULTS_DIRECTORY)
    def write_results_json(self, results_to_write: dict, dest_dir: str, json_file: str, json_dir=DefaultValues.JSON_RESULTS_DIRECTORY) -> None:
        if not results_to_write:
            return
        with open(f'{dest_dir}/{json_dir}/{json_file}', mode='w') as result_json_file:
            result_json_file.write(dumps(results_to_write))

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    @create_results_directory()
    @create_subdirectory(subdirectory=DefaultValues.CSV_RESULTS_DIRECTORY)
    def write_results_csv(self, results_to_write: dict, dest_dir: str, csv_file: str, csv_dir=DefaultValues.CSV_RESULTS_DIRECTORY) -> None:
        if not results_to_write:
            return
        with open(f'{dest_dir}/{csv_dir}/{csv_file}', mode='w') as result_csv_file:
            if isinstance(results_to_write, dict):
                results_to_write = GrinderFileManager.csv_dict_fix(results_to_write)
            writer = DictWriter(result_csv_file, fieldnames=results_to_write[0].keys())
            writer.writeheader()
            for row in results_to_write:
                writer.writerow(row)

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    @create_results_directory()
    @create_subdirectory(subdirectory=DefaultValues.TXT_RESULTS_DIRECTORY)
    def write_results_txt(self, results_to_write: dict, dest_dir: str, txt_file: str, txt_dir=DefaultValues.TXT_RESULTS_DIRECTORY) -> None:
        if not results_to_write:
            return
        with open(f'{dest_dir}/{txt_dir}/{txt_file}', mode='w') as result_txt_file:
            if isinstance(results_to_write, list):
                for item in results_to_write:
                    result_txt_file.write(f'{item}\n')
            if isinstance(results_to_write, dict):
                result_txt_file.write(dumps(results_to_write))

    @exception_handler(expected_exception=GrinderFileManagerOpenError)
    @create_results_directory()
    @create_subdirectory(subdirectory=DefaultValues.PNG_RESULTS_DIRECTORY)
    def write_results_png(self, plot, dest_dir: str, png_file: str, png_dir=DefaultValues.PNG_RESULTS_DIRECTORY) -> None:
        if not plot:
            return
        plot.savefig(f"{dest_dir}/{png_dir}/{png_file}")
