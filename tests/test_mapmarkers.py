#!/usr/bin/env python3

from pathlib import Path
from shutil import rmtree
from grinder.mapmarkers import MapMarkers


class MapTestDefaultValues:
    """
    Needed Paths for test
    """

    MAP_DIRECTORY: str = "tests/test_data/test_mapmarkers"
    PATH_TO_TEST_MAP_DIRECTORY: Path = Path(".").joinpath(MAP_DIRECTORY)
    PATH_TO_FILE: Path = PATH_TO_TEST_MAP_DIRECTORY.joinpath("static").joinpath("data")
    PATH_WITH_FILE: Path = PATH_TO_FILE.joinpath("markers.json")


def test_mapmarkers_file_case() -> None:
    """
    Check if a file with all directories were created
    and check the resulting size and the content of a file
    :return:
    """
    results = ["test"]
    MapMarkers().update_markers(
        results, map_directory=MapTestDefaultValues.MAP_DIRECTORY
    )
    assert MapTestDefaultValues.PATH_TO_TEST_MAP_DIRECTORY.exists()
    assert MapTestDefaultValues.PATH_TO_FILE.exists()
    assert MapTestDefaultValues.PATH_WITH_FILE.exists()
    assert MapTestDefaultValues.PATH_WITH_FILE.stat().st_size == 14
    assert MapTestDefaultValues.PATH_WITH_FILE.read_text() == '[\n    "test"\n]'


def test_mapmarkers_invalid_value() -> None:
    """
    Update markers with wrong arguments and in an empty case
    :return: None
    """
    MapMarkers().update_markers(
        "test_value", map_directory=MapTestDefaultValues.MAP_DIRECTORY
    )
    assert MapTestDefaultValues.PATH_WITH_FILE.stat().st_size == 12
    assert MapTestDefaultValues.PATH_WITH_FILE.read_text() == '"test_value"'

    MapMarkers().update_markers(None, map_directory=MapTestDefaultValues.MAP_DIRECTORY)
    assert MapTestDefaultValues.PATH_WITH_FILE.stat().st_size == 4
    assert MapTestDefaultValues.PATH_WITH_FILE.read_text() == "null"

    MapMarkers().update_markers("[]", map_directory=MapTestDefaultValues.MAP_DIRECTORY)
    assert MapTestDefaultValues.PATH_WITH_FILE.stat().st_size == 4
    assert MapTestDefaultValues.PATH_WITH_FILE.read_text() == '"[]"'

    MapMarkers().update_markers([], map_directory=MapTestDefaultValues.MAP_DIRECTORY)
    assert MapTestDefaultValues.PATH_WITH_FILE.stat().st_size == 2
    assert MapTestDefaultValues.PATH_WITH_FILE.read_text() == "[]"

    rmtree(MapTestDefaultValues.MAP_DIRECTORY)
