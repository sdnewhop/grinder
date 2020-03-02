from flask import (
    Flask,
    send_from_directory,
    jsonify,
    wrappers,
    request,
    redirect,
)
from pathlib import Path
from json import load
from platform import system
from subprocess import run, PIPE, TimeoutExpired

app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


class StorageData:
    MARKERS: list = []
    SEARCH_MARKERS: list = []
    MARKERS_DIR: str = "data"
    MARKERS_FILE: str = "markers.json"


class ReloadFiles:
    MARKERS: str = str(
        Path(f"./static/{StorageData.MARKERS_DIR}/{StorageData.MARKERS_FILE}")
    )


def ping(host: str) -> bool:
    """
    Return ping status (online, offline) for particular host
    :param host: host to ping
    :return: is host online?
    """
    param = "-n" if system().lower() == "windows" else "-c"
    command = ["ping", param, "1", host]
    try:
        return run(command, stdout=PIPE, stderr=PIPE, timeout=5).returncode == 0
    except:
        return False


@app.before_first_request
def load_markers(
    path: str = StorageData.MARKERS_DIR, filename: str = StorageData.MARKERS_FILE
) -> None:
    """
    Load JSON with markers
    :param path: path to directory with markers
    :param filename: default markers name
    :return: None
    """
    try:
        with open(
            Path(".").joinpath("static").joinpath(path).joinpath(filename), mode="r"
        ) as markers_json:
            StorageData.MARKERS = load(markers_json)
    except FileNotFoundError:
        print(
            "File with markers not found. Please, finish some scan and run server again."
        )
    print(" * Map markers was successfully loaded")


@app.route("/favicon.ico", methods=["GET"])
def favicon() -> wrappers.Response:
    """
    Return favicon for application
    :return: flask response
    """
    return send_from_directory(Path(".").joinpath("static"), "favicon.ico")


@app.route("/<path:directory>/<path:filename>", methods=["GET"])
def static_mapping(directory: str or Path, filename: str) -> wrappers.Response:
    """
    Return all files that mapped statically
    :param directory: directory with static files
    :param filename: filename in this directory
    :return: flask response
    """
    return send_from_directory(
        Path(".").joinpath("static").joinpath(directory), filename
    )


@app.route("/api/viewraw/<path:host_id>", methods=["GET"])
def api_raw_host(host_id: str or int) -> wrappers.Response:
    """
    Return raw information about host in JSON
    :param host_id: id of host in list of hosts
    :return: flask response
    """
    markers = StorageData.SEARCH_MARKERS or StorageData.MARKERS
    try:
        return jsonify(markers[int(host_id)])
    except IndexError:
        return jsonify({"error": "request index is out of range"})
    except TypeError:
        return jsonify({"error": "request index is invalid"})
    except:
        return jsonify({"error": "unexpected error was happened"})


@app.route("/api/viewraw/<path:host_id>/ping", methods=["GET"])
def api_raw_host_ping(host_id: str or int) -> wrappers.Response:
    """
    Ping host by id
    :param host_id: id of host in list of hosts
    :return: flask response
    """
    markers = StorageData.SEARCH_MARKERS or StorageData.MARKERS
    try:
        host_info = markers[int(host_id)]
        if ping(host_info.get("ip")):
            return jsonify({"status": "online"})
        return jsonify({"status": "offline"})
    except (TimeoutExpired, TimeoutError):
        return jsonify({"error": "timeout"})
    except:
        return jsonify({"error": "ping error"})


@app.route("/api/viewall", methods=["GET"])
def api_raw_all() -> wrappers.Response:
    """
    Return full list of hosts in JSON
    :return: flask response
    """
    markers = StorageData.SEARCH_MARKERS or StorageData.MARKERS
    try:
        return jsonify(markers)
    except:
        return jsonify({"error": "unexpected error was happened"})


@app.route("/", methods=["GET"])
def root() -> wrappers.Response:
    """
    Serve root/index page
    :return: flask response
    """
    StorageData.SEARCH_MARKERS = []
    return app.send_static_file("index.html")


@app.route("/update", methods=["GET"])
def api_update_data() -> wrappers.Response:
    """
    Update JSON with markers
    :return: wrappers.Response object
    """
    load_markers()
    return redirect("/")


@app.route("/reset", methods=["GET"])
def reset_search() -> wrappers.Response:
    """
    Reset search filter
    :return: wrappers.Response object
    """
    return redirect("/")


@app.route("/search", methods=["GET"])
def search() -> wrappers.Response:
    """
    Search for some specific keywords in results
    :return: wrappers.Response object
    """
    query = request.args.get("query", default="", type=str)
    StorageData.SEARCH_MARKERS = [
        host for host in StorageData.MARKERS if query.lower() in str(host).lower()
    ]
    return app.send_static_file("index.html")


if __name__ == "__main__":
    load_markers()
    app.run(debug=True, host="0.0.0.0", port=5000, extra_files=[ReloadFiles.MARKERS])
