from flask import Flask, send_from_directory, jsonify, json, wrappers
from pathlib import Path
from sys import exit
from json import load
from platform import system
from subprocess import run, PIPE


MARKERS: list = []

app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True


def ping(host: str) -> bool:
    """
    Return ping status (online, offline) for particular host
    :param host: host to ping
    :return: is host online?
    """
    param = "-n" if system().lower() == "windows" else "-c"
    command = ["ping", param, "1", host]
    return run(command, stdout=PIPE, stderr=PIPE).returncode == 0


@app.before_first_request
def load_markers(path: str = "data", filename: str = "markers.json") -> None:
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
            markers_list = load(markers_json)
    except FileNotFoundError:
        print(
            "File with markers not found. Please, finish some scan and run server again."
        )
        exit(1)

    global MARKERS
    MARKERS = markers_list
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
    try:
        return jsonify(MARKERS[int(host_id)])
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
    try:
        host_info = MARKERS[int(host_id)]
        ip = host_info.get("ip")
        if ping(ip) == True:
            return jsonify({"status": "online"})
        else:
            return jsonify({"status": "offline"})
    except:
        return jsonify({"error": "can not ping host"})


@app.route("/api/viewall", methods=["GET"])
def api_raw_all() -> wrappers.Response:
    """
    Return full list of hosts in JSON
    :return: flask response
    """
    try:
        return jsonify(MARKERS)
    except:
        return jsonify({"error": "unexpected error was happened"})


@app.route("/", methods=["GET"])
def root():
    """
    Serve root/index page
    :return: flask response
    """
    return app.send_static_file("index.html")


if __name__ == "__main__":
    load_markers()
    app.run(debug=True, host="0.0.0.0", port=5000)
