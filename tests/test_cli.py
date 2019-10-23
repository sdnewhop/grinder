#!/usr/bin/env python3

from pytest import fixture, raises
import subprocess
from os import listdir
import random


@fixture
def cli_args(shodan_key: str, censys_id: str, censys_secret: str) -> list:
    """
    Sets all needed arguments for execution and testing
    :param shodan_key: shodan key value
    :param censys_id: censys id value
    :param censys_secret: censys secret value
    :return: all constant arguments
    """
    sk = shodan_key
    ci = censys_id
    cs = censys_secret
    base_args = [
        "./grinder.py",
        "-r",
        "-u",
        "-cu",
        "-cp",
        "-sk",
        sk,
        "-ci",
        ci,
        "-cs",
        cs,
        "-ni",
    ]
    return base_args


@fixture
def query_random() -> str:
    """
    Takes random query file from directory
    :return: query file
    """
    queries = ["queries/" + query for query in listdir("queries")]
    queries.remove("queries/test.json")
    return random.choice(queries)


def test_cli_base_args(cli_args: list, capfd) -> None:
    """
    Execute base arguments and check results
    :param cli_args: needed arguments for execution and testing
    :return: None
    """
    subprocess.run(["./grinder.py"])
    assert "Usage: ./grinder.py -h for help" in str(capfd.readouterr().out)
    subprocess.run(cli_args)
    out, err = capfd.readouterr()
    assert (
        "Oops! File with queries was not found. Create it or set name properly."
        in str(out)
    )
    assert "No such file or directory: 'queries.json'" in str(out)


def test_cli_invalid_base_args(capfd) -> None:
    """
    Check behavior in case of invalid value following flag that doesn't require value
    :return: None
    """
    base_one = ["./grinder.py", "-r"]
    flags = ["-r", "-u", "-cu", "-cp", "-ni"]
    invalid_value = "wrong_one"
    for f in flags:
        base_one.extend([f, invalid_value])
        subprocess.run(base_one)
        out, err = capfd.readouterr()
        assert "unrecognized arguments:" in str(err)
        base_one.pop()
        subprocess.run(base_one)
        out, err = capfd.readouterr()
        assert (
            "Oops! File with queries was not found. Create it or set name properly."
            in str(out)
        )
        base_one.pop()


def test_cli_invalid_args(cli_args: list, capfd) -> None:
    """
    Check behavior in case of invalid args with different flags
    :param cli_args: base arguments
    :return: None
    """
    base_args = cli_args
    invalid_value = "wrong_one"
    invalid_args = base_args

    invalid_args.append(invalid_value)
    subprocess.run(invalid_args)
    out, err = capfd.readouterr()
    assert "unrecognized arguments:" in str(err)

    invalid_args = base_args
    invalid_args.extend(["-nm", "-vs", "-sc", "-vs", "-ts"])
    flags = ["-cm", "-sm", "-nw", "-vw", "-ht", "-tp", "-ml", "-q", "-v", "-tsp", "-vk"]

    expected_invalid_errors = [
        "argument -cm/--censys-max: invalid int value",
        "argument -sm/--shodan-max: invalid int value",
        "argument -nw/--nmap-workers: invalid int value",
        "argument -vw/--vulners-workers: invalid int value",
        "argument -ht/--host-timeout: invalid int value",
        "argument -tp/--top-ports: invalid int value",
        "argument -ml/--max-limit: invalid int value",
        "unrecognized arguments:",
        "unrecognized arguments:",
        "unrecognized arguments:",
        "unrecognized arguments:",
    ]

    for i in range(len(flags)):
        invalid_args.extend([flags[i], invalid_value])
        subprocess.run(invalid_args)
        err1 = capfd.readouterr().err
        assert expected_invalid_errors[i] in str(err1)

        invalid_args.pop()
        subprocess.run(invalid_args)
        out, err = capfd.readouterr()
        if str(err) != str(err1):
            assert "expected one argument" in str(err)
        invalid_args.pop()


def test_cli_vendor_confidence(cli_args: list, query_random: str, capfd) -> None:
    """
    Check behavior in case of different vendor confidence
    :param cli_args: base arguments
    :return: None
    """
    base_args = cli_args
    query = query_random
    base_args.extend(["-q", query, "-vc"])
    vendor_confidence = ["firm", "tentative", "wrong_one"]
    error = "Confidence level for vendors is not valid"

    for vendor in vendor_confidence:
        base_args.append(vendor)
        subprocess.run(base_args)
        out, err = capfd.readouterr()
        if error in str(out):
            assert error in str(out)
        base_args.pop()


def test_cli_query_confidence(cli_args: list, query_random: str, capfd) -> None:
    """
     Check behavior in case of different query confidence
    :param cli_args: base arguments
    :return: None
    """
    base_args = cli_args
    query = query_random
    base_args.extend(["-q", query, "-qc"])
    query_confidence = ["firm", "tentative", "wrong_one"]
    error = "Confidence level for current query is not valid"
    for query in query_confidence:
        base_args.append(query)
        subprocess.run(base_args)
        out, err = capfd.readouterr()
        if error in str(out):
            assert error in str(out)
        base_args.pop()
