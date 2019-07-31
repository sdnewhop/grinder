#!/usr/bin/env python3

from json import dump

from grinder.defaultvalues import DefaultValues
from pathlib import Path


class MapMarkers:
    def __init__(self):
        pass

    def update_markers(self, results: list, map_directory=None) -> None:
        if not map_directory:
            map_directory = DefaultValues.MARKERS_DIRECTORY
        path_to_save = Path(".").joinpath(map_directory).joinpath("static").joinpath("data")
        path_to_save.mkdir(parents=True, exist_ok=True)
        with open(path_to_save.joinpath("markers.json"), mode="w") as json_markers:
            dump(results, json_markers, indent=4)