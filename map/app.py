from flask import Flask, send_from_directory, jsonify, json
from pathlib import Path
from sys import exit, argv
from json import load


MARKERS: list = []

app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True


@app.before_first_request
def load_markers(path: str = "data", filename: str = "markers.json"):
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
def favicon():
    return send_from_directory(Path(".").joinpath("static"), "favicon.ico")


@app.route("/<path:directory>/<path:filename>", methods=["GET"])
def static_mapping(directory, filename):
    return send_from_directory(
        Path(".").joinpath("static").joinpath(directory), filename
    )


@app.route("/api/viewraw/<path:host_id>", methods=["GET"])
def api_raw_host(host_id):
    try:
        return jsonify(MARKERS[int(host_id)])
    except IndexError:
        return jsonify({"error": "request index is out of range"})
    except TypeError:
        return jsonify({"error": "request index is invalid"})
    except:
        return jsonify({"error": "unexpected error was happened"})


@app.route("/api/viewall", methods=["GET"])
def api_raw_all():
    try:
        return jsonify(MARKERS)
    except:
        return jsonify({"error": "unexpected error was happened"})


@app.route("/", methods=["GET"])
def root():
    return app.send_static_file("index.html")


# In case if running with python app.py
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
