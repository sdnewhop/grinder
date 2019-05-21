#!/usr/bin/env python3

import pytest

from grinder.dbhandling import GrinderDatabase


def setup_module():
    global db
    db = GrinderDatabase()
