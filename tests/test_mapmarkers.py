#!/usr/bin/env python3

from pathlib import Path
from grinder.mapmarkers import MapMarkers


class MapTestDefaultValues:
    """
    Needed Paths for test
    """

    MapDirectory: str = "tests/test_data/test_mapmarkers"
    PathToTestMapDirectory: Path = Path(".").joinpath(MapDirectory)
    PathToFile: Path = PathToTestMapDirectory.joinpath("static").joinpath("data")
    PathWithFile: Path = PathToFile.joinpath("markers.json")


def remove_directory() -> None:
    """
    Remove a file with all created directories after tests
    :return: None
    """
    MapTestDefaultValues.PathWithFile.unlink()
    MapTestDefaultValues.PathToFile.rmdir()
    MapTestDefaultValues.PathToTestMapDirectory.joinpath("static").rmdir()
    MapTestDefaultValues.PathToTestMapDirectory.rmdir()


def test_mapmarkers_file_case() -> None:
    """
    Check if a file with all directories were created
    and check the resulting size and the content of a file
    :return:
    """
    results = ["test"]
    MapMarkers().update_markers(
        results, map_directory=MapTestDefaultValues.MapDirectory
    )
    assert MapTestDefaultValues.PathToTestMapDirectory.exists()
    assert MapTestDefaultValues.PathToFile.exists()
    assert MapTestDefaultValues.PathWithFile.exists()
    assert MapTestDefaultValues.PathWithFile.stat().st_size == 14
    assert MapTestDefaultValues.PathWithFile.read_text() == '[\n    "test"\n]'


def test_mapmarkers_invalid_value() -> None:
    """
    Update markers with wrong arguments and in an empty case
    :return: None
    """
    MapMarkers().update_markers(
        "test_value", map_directory=MapTestDefaultValues.MapDirectory
    )
    assert MapTestDefaultValues.PathWithFile.stat().st_size == 12
    assert MapTestDefaultValues.PathWithFile.read_text() == '"test_value"'

    MapMarkers().update_markers(None, map_directory=MapTestDefaultValues.MapDirectory)
    assert MapTestDefaultValues.PathWithFile.stat().st_size == 4
    assert MapTestDefaultValues.PathWithFile.read_text() == "null"

    MapMarkers().update_markers("[]", map_directory=MapTestDefaultValues.MapDirectory)
    assert MapTestDefaultValues.PathWithFile.stat().st_size == 4
    assert MapTestDefaultValues.PathWithFile.read_text() == '"[]"'

    MapMarkers().update_markers([], map_directory=MapTestDefaultValues.MapDirectory)
    assert MapTestDefaultValues.PathWithFile.stat().st_size == 2
    assert MapTestDefaultValues.PathWithFile.read_text() == "[]"
    remove_directory()
