from typing import Dict, Any

import requests


def main(config: Dict[str, Any]):
    response = requests.head(config['address'])
    return response.status_code
