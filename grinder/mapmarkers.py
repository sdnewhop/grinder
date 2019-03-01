#!/usr/bin/env python3

from json import dumps

from grinder.defaultvalues import DefaultValues


class MapMarkers:
    def __init__(self):
        pass

    def update_markers(self, results: dict, map_directory=None) -> None:
        if not map_directory:
            map_directory = DefaultValues.MARKERS_DIRECTORY
        with open(f'{map_directory}/maps/markers.js', mode='w') as js_markers:
            js_dump_results = dumps(results)
            js_markers.write('var markers = {markers}'.format(markers=js_dump_results))
