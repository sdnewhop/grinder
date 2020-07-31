#!/usr/bin/env python3

from requests import get
from requests.exceptions import ConnectionError, ConnectTimeout, ContentDecodingError
from requests_toolbelt.utils import dump


def main(host_info: dict, timeout: int = 3) -> dict:
    """
    Get raw HTTP response as decoded bytes (headers + response body)
    :param host_info: host information
    :param timeout: host timeout
    :return: dictionary with status and data
    """
    output = {"http_response": "", "status": "Success"}

    try:
        proto = "https" if host_info.get("port") in [443, 8443] else "http"
        url = f"{proto}://{host_info.get('ip')}:{host_info.get('port')}"
        response = get(url, verify=False, timeout=timeout)
        response_dump = bytearray()
        dump._dump_response_data(
            response, prefixes=dump.PrefixSettings(b"", b""), bytearr=response_dump
        )
    except (TimeoutError, ConnectTimeout):
        output.update({"status": "Timeout error was caught"})
    except ConnectionError as connection_err:
        output.update({"status": f"Connection error was caught: {str(connection_err)}"})
    except ContentDecodingError as content_err:
        output.update(
            {"status": f"Content decoding error was caight: {str(content_err)}"}
        )
    except Exception as unexp_err:
        output.update({"status": f"Unexpected error was caught: {str(unexp_err)}"})
    else:
        output.update({"http_response": response_dump.decode("utf-8")})
    return output


if __name__ == "__main__":
    host_info = {"ip": "localhost", "port": 80}
    print(main(host_info))
