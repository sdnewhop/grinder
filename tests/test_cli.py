#!/usr/bin/env python3

from pytest import fixture
from subprocess import Popen, PIPE
from os import getcwd, X_OK, access
from pathlib import Path


def check_executable_flag(file_to_check: str = "grinder.py") -> list:
    """
    Find the original grinder.py and check if it is executable
    :param file_to_check: filename of module, "grinder.py" by default
    :return: list representation of command to run grinder
    """
    try:
        grinder_dir = Path(__file__).resolve().parents[1]
    except IndexError:
        raise Exception(
            "Wrong path. Please, check that tests are located in grinder root directory."
        )
    full_grinder_path = grinder_dir.joinpath(file_to_check)
    if not access(full_grinder_path, X_OK):
        return ["python3", f"{full_grinder_path}"]
    return [f"{full_grinder_path}"]


class CLITestDefaultValues:
    CLI_QUERY_PATH = "test_data/test_queries/cli_arguments_test.json"
    GRINDER_RUN_COMMAND = check_executable_flag()
    if Path(getcwd()).stem == "grinder":
        CLI_QUERY_PATH = f"tests/{CLI_QUERY_PATH}"


@fixture
def cli_args(shodan_key: str, censys_id: str, censys_secret: str) -> list:
    """
    Set all needed arguments for execution and testing
    :param shodan_key: shodan key value
    :param censys_id: censys id value
    :param censys_secret: censys secret value
    :return: list representation of all arguments in command line
    """
    base_args = [
        *CLITestDefaultValues.GRINDER_RUN_COMMAND,
        "-r",
        "-u",
        "-cu",
        "-cp",
        "-sk",
        shodan_key,
        "-ci",
        censys_id,
        "-cs",
        censys_secret,
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
    p = Popen(CLITestDefaultValues.GRINDER_RUN_COMMAND, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert "grinder.py -h for help" in str(output)

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
    base_one = [*CLITestDefaultValues.GRINDER_RUN_COMMAND, "-r"]
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
    :param cli_args: needed arguments for execution and testing
    :return: None
    """
    invalid_value = "wrong_one"

    cli_args.extend(["-q", invalid_value])
    p = Popen(cli_args, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert (
        "Oops! File with queries was not found. Create it or set name properly."
        in str(output)
    )
    cli_args[-1] = CLITestDefaultValues.CLI_QUERY_PATH

    cli_args.extend(["-v", invalid_value])
    p = Popen(cli_args, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert "Vendors not found in queries file" in str(output)
    cli_args = cli_args[:-2]

    flags_extension = ["-nm", "-vs", "-sc", "-vs", "-ts"]
    cli_args.extend(flags_extension)

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
    for flag_arg, flag_output in zip(flags, expected_invalid_errors):
        cli_args.extend([flag_arg, invalid_value])
        p = Popen(cli_args, stdout=PIPE, stderr=PIPE)
        output, error = p.communicate()
        assert p.returncode == 1
        assert flag_output in str(error)

        cli_args.pop()
        p = Popen(cli_args, stdout=PIPE, stderr=PIPE)
        output, error_without_arg = p.communicate()
        assert p.returncode == 1
        assert "expected one argument" in str(error_without_arg)
        cli_args.pop()


def test_cli_vendor_confidence(cli_args: list) -> None:
    """
    Check behavior in case of right vendor confidence
    :param cli_args: needed arguments for execution and testing
    :return: None
    """
    cli_args.extend(["-q", CLITestDefaultValues.CLI_QUERY_PATH, "-vc"])
    vendor_confidence = ["certain", "firm", "tentative"]
    output_part = "Results are empty"

    for vendor in vendor_confidence:
        cli_args.append(vendor)
        p = Popen(cli_args, stdout=PIPE, stderr=PIPE)
        output, error = p.communicate()
        assert p.returncode == 1
        assert output_part in str(output)
        cli_args.pop()


def test_cli_vendor_confidence_with_invalid_arg(cli_args: list) -> None:
    """
    Check behavior in case of invalid vendor confidence
    :param cli_args: needed arguments for execution and testing
    :return: None
    """
    cli_args.extend(["-q", CLITestDefaultValues.CLI_QUERY_PATH, "-vc", "wrong_one"])
    p = Popen(cli_args, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert "Confidence level for vendors is not valid" in str(output)


def test_cli_query_confidence(cli_args: list) -> None:
    """
    Check behavior in case of right query confidence
    :param cli_args: needed arguments for execution and testing
    :return: None
    """
    cli_args.extend(["-q", CLITestDefaultValues.CLI_QUERY_PATH, "-qc"])
    query_confidence = ["certain", "firm", "tentative"]
    output_part = "Results are empty"

    for query in query_confidence:
        cli_args.append(query)
        p = Popen(cli_args, stdout=PIPE, stderr=PIPE)
        output, error = p.communicate()
        assert p.returncode == 1
        assert output_part in str(output)
        cli_args.pop()


def test_cli_query_confidence_with_invalid_arg(cli_args: list) -> None:
    """
    Check behavior in case of invalid query confidence
    :param cli_args: needed arguments for execution and testing
    :return: None
    """
    cli_args.extend(["-q", CLITestDefaultValues.CLI_QUERY_PATH, "-qc", "wrong_one"])
    p = Popen(cli_args, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    assert p.returncode == 1
    assert "Confidence level for current query is not valid" in str(output)
