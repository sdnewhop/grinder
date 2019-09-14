#!/usr/bin/env python3
from pytest import raises
from time import sleep

from grinder.decorators import exception_handler, timer


class DecoratorCustomException(Exception):
    def __init__(self, error_args: Exception):
        super().__init__(self)
        self.error_args = error_args

    def __str__(self):
        return "This error must be catched"


def test_exception_handler() -> None:
    """
    Check behavior of custom exception handler.
    In this case we check that custom exception
    will replace original exception and we can catch
    it in our own way
    :return: None
    """

    @exception_handler(expected_exception=DecoratorCustomException)
    def my_error_function():
        raise Exception("Something goes wrong here")

    with raises(DecoratorCustomException):
        my_error_function()


def test_timer_handler(capsys) -> None:
    """
    Check behavior of custom timer wrapper
    :return: None
    """

    @timer
    def my_long_time_function(time: float):
        sleep(time)

    my_long_time_function(0.1)
    assert "Done in 0.1s (00:00:00)\n" == capsys.readouterr().out
    my_long_time_function(1.0)
    assert "Done in 1.0s (00:00:01)\n" == capsys.readouterr().out
