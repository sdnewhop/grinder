#!/usr/bin/env python3


def test_censys_id(censys_id):
    assert censys_id != "" and isinstance(censys_id, str)


def test_censys_secret(censys_secret):
    assert censys_secret != "" and isinstance(censys_secret, str)


def test_shodan_key(shodan_key):
    assert shodan_key != "" and isinstance(shodan_key, str)


def test_vulners_key(vulners_key):
    assert vulners_key != "" and isinstance(vulners_key, str)
