#!/usr/bin/env python3

from pytest import fixture
from subprocess import Popen, PIPE


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
        "-d",
    ]
    return base_args


def test_cli_base_args(cli_args: list) -> None:
    """
    Execute base arguments and check results
    :param cli_args: needed arguments for execution and testing
    :return: None
    """
    p = Popen(["./grinder.py"], stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert "Usage: ./grinder.py -h for help" in str(output)

    p = Popen(cli_args, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert (
        "Oops! File with queries was not found. Create it or set name properly."
        in str(output)
    )
    assert "No such file or directory:" in str(output)


def test_cli_invalid_base_args() -> None:
    """
    Check behavior in case of invalid value following flag that doesn't require value
    :return: None
    """
    base_one = ["./grinder.py", "-r"]
    flags = ["-r", "-u", "-cu", "-cp", "-ni", "-d", "-nm", "-vs", "-sc", "-vs", "-ts"]
    invalid_value = "wrong_one"
    for f in flags:
        base_one.extend([f, invalid_value])
        p = Popen(base_one, stdout=PIPE, stderr=PIPE)
        output, error = p.communicate()
        assert p.returncode == 1
        assert "unrecognized arguments:" in str(error)

        base_one.pop()
        p = Popen(base_one, stdout=PIPE, stderr=PIPE)
        output, error = p.communicate()
        assert p.returncode == 1
        assert (
            "Oops! File with queries was not found. Create it or set name properly."
            in str(output)
        )
        base_one.pop()


def test_cli_invalid_args_after_flags(cli_args: list) -> None:
    """
    Check behavior in case of invalid arguments after different flags
    :param cli_args: base arguments
    :return: None
    """
    invalid_args = cli_args
    invalid_value = "wrong_one"

    invalid_args.extend(["-q", invalid_value])
    p = Popen(invalid_args, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert (
        "Oops! File with queries was not found. Create it or set name properly."
        in str(output)
    )
    invalid_args[
        len(invalid_args) - 1
    ] = "tests/test_data/test_queries/cli_arguments_test.json"

    invalid_args.extend(["-v", invalid_value])
    p = Popen(invalid_args, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert "Vendors not found in queries file" in str(output)
    invalid_args = invalid_args[: len(invalid_args) - 2]

    flags_extension = ["-nm", "-vs", "-sc", "-vs", "-ts"]
    invalid_args.extend(flags_extension)

    flags = ["-cm", "-sm", "-nw", "-vw", "-ht", "-tp", "-ml", "-tls"]
    expected_invalid_errors = [
        "argument -cm/--censys-max: invalid int value",
        "argument -sm/--shodan-max: invalid int value",
        "argument -nw/--nmap-workers: invalid int value",
        "argument -vw/--vulners-workers: invalid int value",
        "argument -ht/--host-timeout: invalid int value",
        "argument -tp/--top-ports: invalid int value",
        "argument -ml/--max-limit: invalid int value",
    ]
    for (flag_arg, flag_output) in zip(flags, expected_invalid_errors):
        invalid_args.extend([flag_arg, invalid_value])
        p = Popen(invalid_args, stdout=PIPE, stderr=PIPE)
        output, error = p.communicate()
        assert p.returncode == 1
        assert flag_output in str(error)

        invalid_args.pop()
        p = Popen(invalid_args, stdout=PIPE, stderr=PIPE)
        output, error_without_arg = p.communicate()
        assert p.returncode == 1
        assert "expected one argument" in str(error_without_arg)
        invalid_args.pop()


def test_cli_vendor_confidence(cli_args: list) -> None:
    """
    Check behavior in case of right vendor confidence
    :param cli_args: base arguments
    :return: None
    """
    base_args = cli_args
    base_args.extend(
        ["-q", "tests/test_data/test_queries/cli_arguments_test.json", "-vc"]
    )
    vendor_confidence = ["certain", "firm", "tentative"]
    output_part = "Results are empty"

    for vendor in vendor_confidence:
        base_args.append(vendor)
        p = Popen(base_args, stdout=PIPE, stderr=PIPE)
        output, error = p.communicate()
        assert p.returncode == 1
        assert output_part in str(output)
        base_args.pop()


def test_cli_vendor_confidence_with_invalid_arg(cli_args: list) -> None:
    """
    Check behavior in case of invalid vendor confidence
    :param cli_args: base arguments
    :return: None
    """
    base_args = cli_args
    base_args.extend(
        ["-q", "tests/test_data/test_queries/cli_arguments_test.json", "-vc"]
    )
    base_args.append("wrong_one")
    p = Popen(base_args, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert "Confidence level for vendors is not valid" in str(output)


def test_cli_query_confidence(cli_args: list) -> None:
    """
     Check behavior in case of right query confidence
    :param cli_args: base arguments
    :return: None
    """
    base_args = cli_args
    base_args.extend(
        ["-q", "tests/test_data/test_queries/cli_arguments_test.json", "-qc"]
    )
    query_confidence = ["certain", "firm", "tentative"]
    output_part = "Results are empty"

    for query in query_confidence:
        base_args.append(query)
        p = Popen(base_args, stdout=PIPE, stderr=PIPE)
        output, error = p.communicate()
        assert p.returncode == 1
        assert output_part in str(output)
        base_args.pop()


def test_cli_query_confidence_with_invalid_arg(cli_args: list) -> None:
    """
     Check behavior in case of invalid query confidence
    :param cli_args: base arguments
    :return: None
    """
    base_args = cli_args
    base_args.extend(
        ["-q", "tests/test_data/test_queries/cli_arguments_test.json", "-qc"]
    )
    base_args.append("wrong_one")
    p = Popen(base_args, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert "Confidence level for current query is not valid" in str(output)
