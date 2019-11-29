from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread
from typing import Dict, Any

from grinder.pyscriptexecutor import PyScriptExecutor


class HTTPTestServer:
    def __init__(
        self,
        configuration: Dict[str, Any]
    ):
        host = configuration['host']
        port = configuration['port']

        print('3')

        self._server = HTTPServer(
            (host, port),
            SimpleHTTPRequestHandler
        )

    def run_server(self):
        server_thread = Thread(target=self._server.serve_forever, daemon=True)
        print('setuped')
        server_thread.start()

    def shutdown_server(self):
        self._server.shutdown()
        print('shutdowned')


def test_pyscript_executor():
    script_path = 'test/example.py'

    test_server_config = {
        'host': 'localhost',
        'port': 8080,
    }

    test_request_config = {
        'address': 'http://127.0.0.1:8080'
    }
    print('1')
    test_server = HTTPTestServer(test_server_config)

    print('2')
    status_code = PyScriptExecutor.run_script(test_request_config, script_path)

    test_server.shutdown_server()

    assert status_code == 200
