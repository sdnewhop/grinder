#!/usr/bin/env python3
from pytest import raises, fixture
from pathlib import Path
from os import listdir
from json import load

from grinder.filemanager import GrinderFileManager
from grinder.errors import GrinderFileManagerOpenError


class TestDefaultFilemanagerValues:
    TEST_DATA_PATH = Path(".").joinpath("test_data")
    TEST_DATA_QUERIES_PATH = TEST_DATA_PATH.joinpath("test_queries")
    TEST_DATA_RESULTS_PATH = TEST_DATA_PATH.joinpath("test_results")
    TEST_DATA_RESULTS_JSON_PATH = TEST_DATA_RESULTS_PATH.joinpath("json")

    TEST_DATA_ORIGINAL_PATH = TEST_DATA_PATH.joinpath("test_original")
    TEST_DATA_RESULTS_TO_COMPARE_CSV = "results_to_compare.csv"
    TEST_DATA_EXPLOITS_TO_COMPARE_CSV = "exploits_to_compare.csv"

    TEST_RESULTS_PATH = Path(".").joinpath("test_results")
    TEST_RESULTS_FILEMANAGER_PATH = TEST_RESULTS_PATH.joinpath("filemanager")
    TEST_RESULTS_PATH_JSON = TEST_RESULTS_FILEMANAGER_PATH.joinpath("json")
    TEST_RESULTS_PATH_CSV = TEST_RESULTS_FILEMANAGER_PATH.joinpath("csv")

    TEST_QUERIES_FILE = "queries.json"
    TEST_RESULTS_JSON_FILE = "results.json"
    TEST_RESULTS_CSV_FILE = "results.csv"
    TEST_EXPLOITS_JSON_FILE = "exploits.json"
    TEST_EXPLOITS_CSV_FILE = "exploits.csv"


def setup_module() -> None:
    """
    Create results directory,
    initialize some old results
    for testing
    :return: None
    """
    global get_results
    with open(
        TestDefaultFilemanagerValues.TEST_DATA_RESULTS_JSON_PATH.joinpath(
            TestDefaultFilemanagerValues.TEST_RESULTS_JSON_FILE
        ),
        mode="r",
    ) as results_file:
        get_results = load(results_file)[:10]
    Path(".").joinpath("test_results").mkdir(parents=True, exist_ok=True)


def test_filemanager_get_queries_success() -> None:
    """
    Check if we can successfully get query file
    from queries/* directory
    :return: None
    """
    filemanager = GrinderFileManager()
    queries = filemanager.get_queries(
        queries_file=str(
            TestDefaultFilemanagerValues.TEST_DATA_QUERIES_PATH.joinpath(
                TestDefaultFilemanagerValues.TEST_QUERIES_FILE
            )
        )
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
        load_dir=str(TestDefaultFilemanagerValues.TEST_DATA_PATH),
        load_json_dir="test_queries",
        load_file=TestDefaultFilemanagerValues.TEST_QUERIES_FILE,
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
        dest_dir=str(TestDefaultFilemanagerValues.TEST_RESULTS_PATH),
        json_dir=str(Path("filemanager").joinpath("json")),
        json_file=TestDefaultFilemanagerValues.TEST_RESULTS_JSON_FILE,
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
    filemanager.write_results_csv(
        results_to_write=get_results,
        dest_dir=str(TestDefaultFilemanagerValues.TEST_RESULTS_PATH),
        csv_dir=str(Path("filemanager").joinpath("csv")),
        csv_file=TestDefaultFilemanagerValues.TEST_RESULTS_CSV_FILE,
    )
    path_to_file = (
        Path(".").joinpath("test_results").joinpath("filemanager").joinpath("csv")
    )
    assert "results.csv" in listdir(path_to_file)
    with open(path_to_file.joinpath("results.csv"), mode="r") as result_file:
        file_contains = result_file.read().split("\n")
        assert (
            file_contains[0]
            == "product,vendor,query,port,proto,ip,lat,lng,country,vulnerabilities,nmap_scan,scripts"
        )
        assert file_contains[-1] == ""
        for line in file_contains[1:-1]:
            for field in line.split(","):
                assert isinstance(field, str) and field != ""


def test_compare_written_results_with_expected() -> None:
    """
    Check if resuls that we write are the same
    as results that we expect to get
    :return: None
    """
    new_results = TestDefaultFilemanagerValues.TEST_RESULTS_PATH_CSV.joinpath(
        TestDefaultFilemanagerValues.TEST_RESULTS_CSV_FILE
    )
    expected_results = TestDefaultFilemanagerValues.TEST_DATA_ORIGINAL_PATH.joinpath(
        TestDefaultFilemanagerValues.TEST_DATA_RESULTS_TO_COMPARE_CSV
    )
    with open(new_results, mode="r") as new_f, open(
        expected_results, mode="r"
    ) as exp_f:
        new = new_f.readlines()
        expected = exp_f.readlines()
        for zip_line in zip(new, expected):
            assert zip_line[0] == zip_line[1]


def test_csv_dict_to_fix() -> None:
    """
    Test additional filemanager convertor
    :return: None
    """
    filemanager = GrinderFileManager()
    results_to_write = {"one": 1, "two": 2, "three": 3}
    res = filemanager.csv_dict_fix(results_to_write, "test.csv")
    assert res == [
        {"test": "one", "count": 1},
        {"test": "two", "count": 2},
        {"test": "three", "count": 3},
    ]


def test_write_results_csv_exploits_to_cve() -> None:
    """
    Test how we can save exploits info to csv
    :return: None
    """
    with open(
        TestDefaultFilemanagerValues.TEST_DATA_RESULTS_JSON_PATH.joinpath(
            TestDefaultFilemanagerValues.TEST_EXPLOITS_JSON_FILE
        ),
        mode="r",
    ) as vulners_results:
        vulners_by_vulnerabilities = load(vulners_results)
    with open(
        TestDefaultFilemanagerValues.TEST_DATA_RESULTS_JSON_PATH.joinpath(
            "results.json"
        ),
        mode="r",
    ) as hosts_results:
        hosts = load(hosts_results)
        hosts = {host.get("ip"): host for host in hosts}
    filemanager = GrinderFileManager()
    filemanager.write_results_csv_exploits_to_cve(
        results_to_write=vulners_by_vulnerabilities,
        hosts_results=hosts,
        dest_dir=str(TestDefaultFilemanagerValues.TEST_RESULTS_PATH),
        csv_dir=str(Path("filemanager").joinpath("csv")),
        csv_file=TestDefaultFilemanagerValues.TEST_EXPLOITS_CSV_FILE,
    )


def test_compare_written_exploits_with_expected() -> None:
    """
    Check if exploits that we write are the same
    as exploits that we expect to get
    :return: None
    """
    new_results = TestDefaultFilemanagerValues.TEST_RESULTS_PATH_CSV.joinpath(
        TestDefaultFilemanagerValues.TEST_EXPLOITS_CSV_FILE
    )
    expected_results = TestDefaultFilemanagerValues.TEST_DATA_ORIGINAL_PATH.joinpath(
        TestDefaultFilemanagerValues.TEST_DATA_EXPLOITS_TO_COMPARE_CSV
    )
    with open(new_results, mode="r") as new_f, open(
        expected_results, mode="r"
    ) as exp_f:
        new = new_f.readlines()
        expected = exp_f.readlines()
        for zip_line in zip(new, expected):
            assert zip_line[0] == zip_line[1]
