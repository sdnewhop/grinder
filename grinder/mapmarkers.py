#!/usr/bin/env python3

from json import dumps

from grinder.defaultvalues import DefaultValues
from pathlib import Path


class MapMarkers:
    def __init__(self):
        pass

    def update_markers(self, results: list, map_directory=None) -> None:
        if not map_directory:
            map_directory = DefaultValues.MARKERS_DIRECTORY
        with open(Path(".")
                  .joinpath(map_directory)
                  .joinpath("static")
                  .joinpath("data")
                  .joinpath("markers.js"), mode="w") as js_markers:
            js_dump_results = dumps(results)
            js_markers.write("var markers = {markers}".format(markers=js_dump_results))
