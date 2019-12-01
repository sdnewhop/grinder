#!/usr/bin/env python3

from requests import get
from requests.exceptions import ConnectionError, ConnectTimeout, ContentDecodingError


def main(host_info: dict, timeout: int = 3) -> dict:
    """
    Check HTTP status
    :param host_info: host information
    :param timeout: host timeout
    :return: dictionary with status and data
    """
    output = {"http_status": "", "status": "Success"}

    try:
        proto = "https" if host_info.get("port") in [443, 8443] else "http"
        url = f"{proto}://{host_info.get('ip')}:{host_info.get('port')}"
        status_code = get(url, verify=False, timeout=timeout).status_code
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
        output.update({"http_status": status_code})
    return output


if __name__ == "__main__":
    host_info = {"ip": "localhost", "port": 80}
    print(main(host_info))
