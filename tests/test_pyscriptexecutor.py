import pytest
from grinder import example
from grinder import pyscriptexecutor


def test_req():
    assert example.r == 200
