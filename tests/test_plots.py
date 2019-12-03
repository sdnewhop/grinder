#!/usr/bin/env python3

from pathlib import Path
from pytest import raises

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

    PlotsDirectory: Path = (
        Path(".")
        .joinpath(DefaultValues.RESULTS_DIRECTORY)
        .joinpath(DefaultValues.PNG_RESULTS_DIRECTORY)
    )
    PlotSubDirectory: str = "test_plots"
    PathToFile: Path = PlotsDirectory.joinpath(PlotSubDirectory)
    FileName: str = "test_plots.png"
    PathWithFile: Path = PathToFile.joinpath(FileName)


def remove_directory():
    """
    Remove a file with all created directories after tests
    :return: None
    """
    PlotsTestDefaultValues.PathWithFile.unlink()
    PlotsTestDefaultValues.PathToFile.rmdir()


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
        relative_path=PlotsTestDefaultValues.PlotSubDirectory,
        filename=f"{PlotsTestDefaultValues.FileName}",
    )
    assert PlotsTestDefaultValues.PathToFile.is_dir()
    assert PlotsTestDefaultValues.PathToFile.exists()
    assert PlotsTestDefaultValues.PathWithFile.exists()
    assert PlotsTestDefaultValues.PathWithFile.stat().st_size == 72997
    assert plots.results_figure_id == 1

    remove_directory()


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
            relative_path=PlotsTestDefaultValues.PlotSubDirectory, filename=None
        )
    assert "expected str, bytes or os.PathLike object" in str(create_error.value)
    PlotsTestDefaultValues.PathToFile.rmdir()


def test_plots_float_value_case() -> None:
    """
    Check the behavior of creating the pie chart
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
    Check the behavior of creating the pie chart
    in the case of an empty dictionary
    :return: None
    """
    plots = GrinderPlots()
    results = {}
    plots.create_pie_chart(results=results, suptitle=f"Test value")
    plots.save_pie_chart(
        relative_path=PlotsTestDefaultValues.PlotSubDirectory,
        filename=f"{PlotsTestDefaultValues.FileName}",
    )
    assert plots.results_figure_id == 0
    assert not PlotsTestDefaultValues.PathWithFile.exists()
    assert not PlotsTestDefaultValues.PathToFile.exists()
