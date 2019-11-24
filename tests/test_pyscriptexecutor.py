#!/usr/bin/env python3
import pytest
import requests

from grinder.errors import GrinderScriptExecutorRunScriptError
from grinder.pyscriptexecutor import PyScriptExecutor


CONFIG = {
    'host_v4': '127.0.0.1',
    'port_v4': 8080,
    'host_v6': '::1',
    'port_v6': 8090,
}


def test_executor_should_rise_exception_on_bad_path():
    with pytest.raises(GrinderScriptExecutorRunScriptError) as exception:
        PyScriptExecutor().run_script(CONFIG, 'some_script_that_does_not_exist.py')


def test_executor_should_return_none():
    digit_like_name = 123
    script_name_without_py = 'script_name'

    result = PyScriptExecutor().run_script(CONFIG, digit_like_name)
    assert result is None

    result = PyScriptExecutor().run_script(CONFIG, script_name_without_py)
    assert result is None


def test_should_not_work_with_scripts_without_main_method():
    with pytest.raises(GrinderScriptExecutorRunScriptError) as exception:
        PyScriptExecutor().run_script(CONFIG, 'test_without_main_method.py')


def test_execute_source_with_server():
    PyScriptExecutor().run_script(CONFIG, 'pyscript_executor_source_fixture.py')

    r1 = requests.get('http://127.0.0.1:8080')
    r2 = requests.get('http://[::1]:8090')

    assert r1.status_code == 200
    assert r2.status_code == 200
