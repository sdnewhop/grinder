#!/usr/bin/env python3

from requests import get
from requests.exceptions import ConnectionError, ConnectTimeout, ContentDecodingError


def main(host_info: dict, timeout: int = 3) -> dict:
    """
    Check if host is TensorFlow Serving Model
    :param host_info: host information
    :param timeout: host timeout
    :return: dictionary with status and data
    """
    output = {
        "html": "",
        "status": ""
    }

    try:
        url = f"http://{host_info.get('ip')}:{host_info.get('port')}/v1/models/versions/metadata"
        resp = get(url, verify=False, timeout=timeout).text
    except (TimeoutError, ConnectionError, ConnectTimeout, ContentDecodingError):
        output.update({"status": "Timeout Error Was Caught"})
        return output
    if "404" in resp:
        status = "Not TensorFlow Serving Server"
    else:
        status = "Found TensorFlow Serving Server"
    output.update({"html": resp, "status": status})
    return output
