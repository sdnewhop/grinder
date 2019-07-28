from flask import Flask, send_from_directory, jsonify, json
from pathlib import Path
from re import search


app = Flask(__name__)

MARKERS: list = []


@app.route("/favicon.ico")
def serve_favicon():
    return send_from_directory(Path(".").joinpath("static"), "favicon.ico")


@app.route("/<path:directory>/<path:filename>")
def serve_static_files(directory, filename):
    return send_from_directory(
        Path(".").joinpath("static").joinpath(directory), filename
    )


@app.route("/api/viewraw/<path:host_id>")
def serve_raw_host_info(host_id):
    try:
        return jsonify(MARKERS[int(host_id)])
    except IndexError as out_of_range:
        return jsonify({"error": "request index is out of range"})
    except TypeError as invalid_id:
        return jsonify({"error": "request index is invalid"})
    except:
        return jsonify({"error": "unexpected error was happened"})

@app.route("/api/viewall")
def serve_all_host_info():
    try:
        return jsonify(MARKERS)
    except:
        return jsonify({"error": "unexpected error was happened"})

@app.route("/")
def root():
    return app.send_static_file("index.html")


def load_markers(path: str = "data", filename: str = "markers.js"):
    with open(
        Path(".").joinpath("static").joinpath(path).joinpath(filename), mode="r"
    ) as markers_js:
        markers_contains = markers_js.read()
        markers_list = search(r"var markers = (.+)", markers_contains)
        if not markers_list:
            return
        markers_list = markers_list.group(1)

        global MARKERS
        MARKERS = json.loads(markers_list)


if __name__ == "__main__":
    load_markers()
    app.run(debug=True, host="0.0.0.0", port=5000)
