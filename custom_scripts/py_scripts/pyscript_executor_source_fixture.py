import time
from threading import Thread

from http.server import HTTPServer, SimpleHTTPRequestHandler
from socket import AF_INET6


class HTTPServer6(HTTPServer):
    address_family = AF_INET6


def setup_module(host_v4, port_v4, host_v6, port_v6) -> None:
    global server_v4
    server_v4 = HTTPServer(
        (host_v4, port_v4),
        SimpleHTTPRequestHandler,
    )
    s_v4 = Thread(target=server_v4.serve_forever, daemon=True)
    s_v4.start()

    global server_v6
    server_v6 = HTTPServer6(
        (host_v6, port_v6),
        SimpleHTTPRequestHandler,
    )
    s_v6 = Thread(target=server_v6.serve_forever, daemon=True)
    s_v6.start()


def teardown_module() -> None:
    """
    Stop HTTPServer
    :return:
    """
    time.sleep(1)

    server_v4.shutdown()
    server_v6.shutdown()


def main(config: dict):
    host_v4 = config['host_v4']
    port_v4 = config['port_v4']

    host_v6 = config['host_v6']
    port_v6 = config['port_v6']

    setup_module(host_v4, port_v4, host_v6, port_v6)

    Thread(target=teardown_module, daemon=True)
