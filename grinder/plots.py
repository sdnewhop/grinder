#!/usr/bin/env python3

from matplotlib import use as mpl_use
from sys import platform
from os import environ

# Fix possible problems with Mac OS X venv backend
if platform == "darwin":
    mpl_use("TkAgg")
    environ.update({"TK_SILENCE_DEPRECATION": "1"})

from matplotlib import pyplot as plot

from grinder.decorators import exception_handler
from grinder.defaultvalues import DefaultPlotValues, DefaultValues
from grinder.errors import (
    GrinderPlotsAdjustAutopctError,
    GrinderPlotsCreatePieChartError,
    GrinderPlotsSavePieChartError,
)
from grinder.filemanager import GrinderFileManager


class GrinderPlots:
    """
    Pie charts and plots creator
    """

    def __init__(self):
        self.plot = None
        self.results_figure_id: int = 0

    @exception_handler(expected_exception=GrinderPlotsSavePieChartError)
    def save_pie_chart(self, relative_path: str, filename: str) -> None:
        """
        Save pie chart with filemanager in png
        :param relative_path: subdirectory to save
        :param filename: filename to save
        :return: None
        """
        filemanager = GrinderFileManager()
        if self.plot:
            filemanager.write_results_png(
                self.plot,
                png_file=filename,
                dest_dir=DefaultValues.RESULTS_DIRECTORY,
                sub_dir=relative_path,
            )
            self.plot.close()

    @exception_handler(expected_exception=GrinderPlotsAdjustAutopctError)
    def __adjust_autopct(self, values: list):
        """
        Percents adjuster to show on plot
        :param values: values to adjust
        :return: function of adjustment
        """

        def percent_and_count(pct):
            total = sum(values)
            val = int(round(pct * total / 100.0))
            return f"{pct:1.1f}%\n({val:d})"

        return percent_and_count

    @exception_handler(expected_exception=GrinderPlotsCreatePieChartError)
    def create_pie_chart(self, results: dict, suptitle: str) -> None:
        """
        Create pie chart based on results,
        add suptitle to picture
        :param results: results to create plot
        :param suptitle: suptitle of plot
        :return: None
        """
        if not results.values():
            return
        values = [value for value in results.values()]
        keys = [key for key in results.keys()]
        percents = []

        total = sum(values)
        if total == 0:
            return
        for value in values:
            try:
                percent = (value / total) * 100
            except ZeroDivisionError:
                return
            percents.append(f"{percent:1.1f}% ({value:d})")

        plot.figure()
        plot.subplots_adjust(bottom=0.05, left=0.40, right=0.90, top=0.90, hspace=0.35)

        explode = [0 for _ in range(len(keys))]
        max_value = max(values)
        explode[list(values).index(max_value)] = 0.1

        patches, texts = plot.pie(
            values,
            labels=percents,
            explode=explode,
            textprops={"fontsize": DefaultPlotValues.PLOT_LABEL_FONT_SIZE},
        )
        plot.legend(
            patches,
            [f"{key} - {percent}" for key, percent in zip(keys, percents)],
            loc="upper left",
            bbox_to_anchor=(-0.65, 1),
            prop={"size": DefaultPlotValues.PLOT_LEGEND_SIZE},
        )

        plot.axis("equal")
        plot.suptitle(suptitle, fontsize=DefaultPlotValues.PLOT_SUPTITLE_FONT_SIZE)
        plot.gcf().set_dpi(DefaultPlotValues.PLOT_DPI)

        self.plot = plot
        self.results_figure_id = self.results_figure_id + 1
