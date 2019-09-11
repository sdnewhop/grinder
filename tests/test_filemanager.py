#!/usr/bin/env python3
import pytest as pytest_conf
from pytest import raises, fixture
from pathlib import Path
from os import listdir
from json import load

from grinder.filemanager import GrinderFileManager
from grinder.shodanconnector import ShodanConnector
from grinder.errors import GrinderFileManagerOpenError


def setup_module() -> None:
    """
    Create results directory, initialize
    Shodan connector to get some results
    :return: None
    """
    global get_results
    api = ShodanConnector(api_key=pytest_conf.config.getoption("shodan_key"))
    api.search(query="apache", max_records=10)
    get_results = api.get_results()

    Path(".").joinpath("test_results").mkdir(parents=True, exist_ok=True)


def test_filemanager_get_queries_success() -> None:
    """
    Check if we can successfully get query file
    from queries/* directory
    :return: None
    """
    filemanager = GrinderFileManager()
    queries = filemanager.get_queries(queries_file="../queries/servers.json")
    for query_obj in queries:
        assert sorted(query_obj.keys()) == sorted(
            [
                "vendor",
                "product",
                "shodan_queries",
                "censys_queries",
                "scripts",
                "vendor_confidence",
            ]
        )


def test_filemanager_get_queries_error() -> None:
    """
    Check if we can properly handle errors
    in case of unsuccessful query file loading
    :return: None
    """
    filemanager = GrinderFileManager()
    with raises(GrinderFileManagerOpenError):
        filemanager.get_queries(queries_file="not_exists.json")


def test_load_data_from_file_success() -> None:
    """
    Originally this function is used to load results
    file, but in case of functionality we can check
    that this function can load any other
    json file (because results - is just dumped
    dicts)
    :return: None
    """
    filemanager = GrinderFileManager()
    queries = filemanager.load_data_from_file(
        load_dir="../", load_json_dir="queries", load_file="servers.json"
    )
    for query_obj in queries:
        assert sorted(query_obj.keys()) == sorted(
            [
                "vendor",
                "product",
                "shodan_queries",
                "censys_queries",
                "scripts",
                "vendor_confidence",
            ]
        )


def test_load_data_from_file_error() -> None:
    """
    Check how we handle errors in case
    when file can't be loaded or parsed
    :return: None
    """
    filemanager = GrinderFileManager()
    with raises(GrinderFileManagerOpenError):
        filemanager.load_data_from_file(
            load_dir="totally", load_json_dir="wrong", load_file="path.json"
        )


def test_write_results_json() -> None:
    """
    Test if we can successfully save our
    results somewhere in JSON
    :param get_results: results to save
    :return: None
    """
    filemanager = GrinderFileManager()
    filemanager.write_results_json(
        results_to_write=get_results,
        dest_dir="test_results",
        json_dir="filemanager/json",
        json_file="results.json",
    )
    path_to_file = (
        Path(".").joinpath("test_results").joinpath("filemanager").joinpath("json")
    )
    assert "results.json" in listdir(path_to_file)
    with open(path_to_file.joinpath("results.json")) as result_file:
        assert load(result_file) == get_results


def test_write_results_csv() -> None:
    """
    Test if we can successfully save our
    results somewhere in CSV
    :param get_results: results to save
    :return: None
    """
    filemanager = GrinderFileManager()
    new_results = [
        {"ip": host.get("ip_str"), "port": host.get("port")} for host in get_results
    ]
    filemanager.write_results_csv(
        results_to_write=new_results,
        dest_dir="test_results",
        csv_dir="filemanager/csv",
        csv_file="results.csv",
    )
    path_to_file = (
        Path(".").joinpath("test_results").joinpath("filemanager").joinpath("csv")
    )
    assert "results.csv" in listdir(path_to_file)
    with open(path_to_file.joinpath("results.csv"), mode="r") as result_file:
        assert "ip,port" in result_file.read()
