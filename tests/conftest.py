#!/usr/bin/env python3


def pytest_addoption(parser):
    parser.addoption("--censys_id", action="store", default="YOUR_CENSYS_ID")
    parser.addoption("--censys_secret", action="store", default="YOUR_CENSYS_SECRET")
    parser.addoption("--shodan_key", action="store", default="YOUR_SHODAN_KEY")
    parser.addoption("--vulners_key", action="store", default="YOUR_VULNERS_KEY")


def pytest_generate_tests(metafunc):
    option_value = metafunc.config.option.censys_id
    if "censys_id" in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("censys_id", [option_value])
    option_value = metafunc.config.option.censys_secret
    if "censys_secret" in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("censys_secret", [option_value])
    option_value = metafunc.config.option.shodan_key
    if "shodan_key" in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("shodan_key", [option_value])
    option_value = metafunc.config.option.vulners_key
    if "vulners_key" in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("vulners_key", [option_value])


options = None


def pytest_configure(config):
    global options
    options = config.option
