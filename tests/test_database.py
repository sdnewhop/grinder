#!/usr/bin/python3

import pytest

from grinder.dbhandling import GrinderDatabase

def setup_module():
    global db
    db = GrinderDatabase()

def test_db_load_results():
    assert isinstance(db.load_last_results(), list)
