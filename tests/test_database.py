#!/usr/bin/env python3

import pytest

from grinder.dbhandling import GrinderDatabase


def setup_module():
    global db
    db = GrinderDatabase()


def test_db_load_results():
    print(type(db.load_last_results()))
    assert isinstance(db.load_last_results(), dict)
