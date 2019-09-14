#!/usr/bin/env python3

from json import dump

from grinder.defaultvalues import DefaultValues
from pathlib import Path


class MapMarkers:
    def __init__(self):
        pass

    @staticmethod
    def update_markers(results: list, map_directory=None) -> None:
        """
        This function saves copy of results to map directory
        as markers.json file. After that flask backend can
        use this file as markers for map.
        :param results: results to use as map markers (hosts results)
        :param map_directory: directory with map files to save results
        :return: None
        """
        if not map_directory:
            map_directory = DefaultValues.MARKERS_DIRECTORY
        path_to_save = (
            Path(".").joinpath(map_directory).joinpath("static").joinpath("data")
        )
        path_to_save.mkdir(parents=True, exist_ok=True)
        with open(path_to_save.joinpath("markers.json"), mode="w") as json_markers:
            dump(results, json_markers, indent=4)
