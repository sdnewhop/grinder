#!/usr/bin/env python3

from pathlib import Path
from shutil import rmtree
from pytest import raises
from hashlib import sha512

from grinder.plots import GrinderPlots
from grinder.errors import (
    GrinderPlotsCreatePieChartError,
    GrinderPlotsSavePieChartError,
)
from grinder.defaultvalues import DefaultValues


class PlotsTestDefaultValues:
    """
    Needed Paths for test
    """

    PLOTS_DIRECTORY: Path = (
        Path(".")
        .joinpath(DefaultValues.RESULTS_DIRECTORY)
        .joinpath(DefaultValues.PNG_RESULTS_DIRECTORY)
    )
    PLOTS_SUB_DIRECTORY: str = "test_plots"
    PATH_TO_FILE: Path = PLOTS_DIRECTORY.joinpath(PLOTS_SUB_DIRECTORY)
    FILE_NAME: str = "test_plots.png"
    PATH_WITH_FILE: Path = PATH_TO_FILE.joinpath(FILE_NAME)


def test_plots_file_case():
    """
    Check if a directory with a file was created
    and check the resulting size of a file and the number of results of the plot
    :return:
    """
    plots = GrinderPlots()
    results = {"test_value": 1, "another_one": 0, "one_more": 3}
    plots.create_pie_chart(results=results, suptitle=f"Test value")
    plots.save_pie_chart(
        relative_path=PlotsTestDefaultValues.PLOTS_SUB_DIRECTORY,
        filename=f"{PlotsTestDefaultValues.FILE_NAME}",
    )
    assert PlotsTestDefaultValues.PATH_TO_FILE.is_dir()
    assert PlotsTestDefaultValues.PATH_TO_FILE.exists()
    assert PlotsTestDefaultValues.PATH_WITH_FILE.exists()
    expected_hash = "6cb9d8d226c9cef60d5b774b1e61ecf1d1a23a3200daed7217b42231550cd992dd0f195a1a055600e1f1827cf80f10416cc556ae206267bf4ac2fbef18732c82"
    assert (
        sha512(PlotsTestDefaultValues.PATH_WITH_FILE.read_bytes()).hexdigest()
        == expected_hash
    )
    assert plots.results_figure_id == 1

    rmtree(PlotsTestDefaultValues.PATH_TO_FILE)


def test_plots_raise_error_in_creating() -> None:
    """
    Test if an error of creating pie chart raising
    in cases of some different types of incorrect values
    :return: None
    """
    plots = GrinderPlots()
    results = [None, "{}", "test"]
    for res in results:
        with raises(GrinderPlotsCreatePieChartError) as create_error:
            plots.create_pie_chart(results=res, suptitle=f"Test value")
        assert "object has no attribute 'values'" in str(create_error.value)
        assert plots.results_figure_id == 0

    results = [{"test": None}, {"another": "value"}, {None: None}]
    for res in results:
        with raises(GrinderPlotsCreatePieChartError) as create_error:
            plots.create_pie_chart(results=res, suptitle=f"Test value")
        assert "unsupported operand type(s) for +:" in str(create_error.value)
        assert plots.results_figure_id == 0


def test_plots_raise_error_in_saving() -> None:
    """
    Test if an error of creating pie chart raising
    in cases of wrong argument
    :return: None
    """
    plots = GrinderPlots()
    results = {"test": 1}
    with raises(GrinderPlotsSavePieChartError) as create_error:
        plots.create_pie_chart(results=results, suptitle=f"Test value")
        plots.save_pie_chart(
            relative_path=PlotsTestDefaultValues.PLOTS_SUB_DIRECTORY, filename=None
        )
    assert "expected str, bytes or os.PathLike object" in str(create_error.value)
    PlotsTestDefaultValues.PATH_TO_FILE.rmdir()


def test_plots_float_value_case() -> None:
    """
    Check the behaviour of creating the pie chart
    in the case of the value of float type
    :return: None
    """
    plots = GrinderPlots()
    results = {"test": 3.0}
    with raises(GrinderPlotsCreatePieChartError) as create_error:
        plots.create_pie_chart(results=results, suptitle=f"Test value")
    assert "Unknown format code 'd' for object of type 'float'" in str(
        create_error.value
    )
    assert plots.results_figure_id == 0


def test_plots_empty_value_case() -> None:
    """
    Check the behaviour of creating the pie chart
    in the case of an empty dictionary
    :return: None
    """
    plots = GrinderPlots()
    results = {}
    plots.create_pie_chart(results=results, suptitle=f"Test value")
    plots.save_pie_chart(
        relative_path=PlotsTestDefaultValues.PLOTS_SUB_DIRECTORY,
        filename=f"{PlotsTestDefaultValues.FILE_NAME}",
    )
    assert plots.results_figure_id == 0
    assert not PlotsTestDefaultValues.PATH_WITH_FILE.exists()
    assert not PlotsTestDefaultValues.PATH_TO_FILE.exists()
