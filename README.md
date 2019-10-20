# Grinder Framework
[![Required OS](https://img.shields.io/badge/OS-Linux%20based-blue)](https://en.wikipedia.org/wiki/Linux)
[![Python3 Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL--2.0-blue)](/LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000)](https://github.com/psf/black)
[![Last Commit](https://img.shields.io/github/last-commit/sdnewhop/grinder)](https://github.com/sdnewhop/grinder)

:mag_right: Internet-connected Devices Census Python Framework 
![Grinder Screenshot](/docs/screenshot.png?raw=true "Grinder Help")
## Contents
1. [Description](#description)
1. [Grinder Workflow](#grinder-workflow)
1. [Grinder Map](#grinder-map)
1. [Requirements](#requirements)
1. [Current Features](#current-features)
1. [Setup and Configure Environment](#setup-and-configure-environment)
1. [Build in Docker](#build-in-docker)
1. [Tests](#tests)
1. [Usage](#usage)
1. [Wiki](#wiki)
1. [Examples](#examples)
1. [Add Your Own Queries](#add-your-own-queries)
## Description
The Grinder framework was created to automatically enumerate and fingerprint different hosts on the Internet using different back-end systems: search engines, such as Shodan or Censys, for discovering hosts and NMAP engine for fingerprinting and specific checks. The Grinder framework can be used in many different areas of researches, as a connected Python module in your own project or as an independent ready-to-use from the box tool.  
## Grinder Workflow
![Grinder Workflow](/docs/workflow.png?raw=true "Grinder Workflow")
## Grinder Map
### Information
Grinder Framework can easily build an interactive map with found hosts in your browser:
![Grinder Map 1](/docs/map_1.png?raw=true "Grinder Map 1")
Also, Grinder can show you some basic information:
![Grinder Map 2](/docs/map_2.png?raw=true "Grinder Map 2")
![Grinder Map 3](/docs/map_3.png?raw=true "Grinder Map 3")


## Requirements
- [Python 3.6+](https://www.python.org/downloads/)
- [python3-tk](https://docs.python.org/3/library/tkinter.html)
- [Shodan](https://account.shodan.io/register) and [Censys](https://censys.io/register) accounts  
Required to collect hosts, both free and full accounts are suitable. Also, it's possible to use only one account (Censys or Shodan, Shodan is preferable).
- [Vulners](https://vulners.com/) account  
Required to make additional reports on vulnerabilities and exploits. If this feature is not required for you, you can use Grinder without Vulners account.
- [Nmap Security Scanner 7.60+](https://nmap.org/download.html)  
Version 7.60 and newer has been tested with currently used in Grinder scripts (ssl-cert.nse, vulners.nse, etc.).
- [TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker)  
Required only for TLS scanning. Version 3.0 has been tested.
- [TLS-Scanner](https://github.com/RUB-NDS/TLS-Scanner)  
Required only for TLS scanning.
## Current Features
### Already Implemented
- Collecting hosts and additional information using Shodan and Censys search engines
- Scanning ports and services with boosted multiprocessed Nmap Scanner wrapper
- Scanning vulnerabilities and additional information about them with Vulners database and Shodan CVEs database
- Retrieving information about SSL certificates
- Scanning for SSL/TLS configuration and supported ciphersuites
- Scanning for SSL/TLS bugs, vulnerabilities and attacks
- Building an interactive map with information about the hosts found
- Creating plots and tables based on the collected results
- Custom scanning scripts support (in LUA or Python3)
- Confidence filtering system support
- Special vendors scanning and filtering support
- Searching for documents, security bulletins, public exploits and many more things based on detected by Grinder vulnerabilities and software

### Development and Future Updates
 - [Grinder Development Project](https://github.com/sdnewhop/grinder/projects/2?fullscreen=true)  
 
The Grinder framework is still in progress and got features to improve, so all the tasks and other features will always be described in this project. If you got some awesome ideas or any other interesting things for Grinder, you can always open a pull request or some issues in this repository.
## Setup and Configure Environment
### Grinder Installing
1. Install [Nmap Security Scanner](https://nmap.org/download.html) if not installed.
2. Install [python3-tk](https://docs.python.org/3/library/tkinter.html) package if not installed (Linux only)
```
sudo apt-get install python3-tk
```
3. Install virtualenv if not installed
```
sudo pip3 install virtualenv 
```
or
```
pip3 install --upgrade virtualenv
```
4. Clone the repository
```
git clone https://github.com/sdnewhop/grinder
```
5. Clone and install [TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker) (if you want to use TLS scanning features with Grinder).
6. Clone [TLS-Scanner](https://github.com/RUB-NDS/TLS-Scanner) in directory with Grinder and install it (if you want to use TLS scanning features with Grinder.
7. Create virtual environment
```
cd grinder
python3 -m venv grindervenv
source grindervenv/bin/activate
```
8. Check if virtual environment successfully loaded
```
which python
which pip
```
9. Install project requirements in virtual environment
```
pip3 install -r requirements.txt
```
10. Run the script
```
./grinder.py -h
```
11. Set your Shodan, Censys and Vulners keys via a command line arguments on every run
```
./grinder.py -sk YOUR_SHODAN_KEY -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -vk YOUR_VULNERS_KEY
```
or via an environment variable permanently
```
export SHODAN_API_KEY=YOUR_SHODAN_API_KEY_HERE
export CENSYS_API_ID=YOUR_CENSYS_API_ID_HERE
export CENSYS_API_SECRET=YOUR_CENSYS_API_SECRET_HERE
export VULNERS_API_KEY=YOUR_VULNERS_API_KEY_HERE
```
12. Deactivate virtual environment after use and restore default python interpreter
```
deactivate
```

### Run Local Grinder Map Server
1. First, complete all steps from the "Setup and Configure Environment/Grinder Installing" section.
2. After the scan is completed, go to the "map" folder
```
cd map/
```
3. Run Flask (use `--help` key for more information)
```
flask run
```
4. Open in your browser
```
http://localhost:5000/
```
Also, Grinder map server provides simple API methods such as `/api/viewall/`, `/api/viewraw/<host_id>`, you can learn more from list of application routes
```
flask routes
```

## Build in Docker
To build the basic lightweight Grinder framework version (without TLS-Attacker and TLS-Scanner) as a docker image you can use the script `docker_build.sh`, and to run this image you can use the script `docker_run.sh`:
```bash
docker run -it --rm --volume $(pwd)/results:/code/results --volume $(pwd)/map:/code/map grinder-framework -h
```

## Tests
To run basic tests for some modules, you need to change directory to `tests/`:
```
cd tests/
```
And run basic tests with the next command - please, pay attention that you need to provide API keys for some modules (like Shodan, Censys) because tests are implemented to check all real functional features of this search engines in Grinder modules and wrappers:
```
pytest --shodan_key SHODAN_API_KEY --censys_id CENSYS_ID_KEY --censys_secret CENSYS_SECRET_KEY
```
Note: tests are still WIP, so please, feel free to create issues If you encounter any problems with it. Currently tests provided for some basic modules and features (Censys, Shodan, Filemanager, Database).


## Usage
### Help on Command Line Arguments
```bash
  .,-:::::/ :::::::..   ::::::.    :::.:::::::-.  .,:::::: :::::::..
,;;-'````'  ;;;;``;;;;  ;;;`;;;;,  `;;; ;;,   `';,;;;;'''' ;;;;``;;;;
[[[   [[[[[[/[[[,/[[['  [[[  [[[[[. '[[ `[[     [[ [[cccc   [[[,/[[['
"$$c.    "$$ $$$$$$c    $$$  $$$ "Y$c$$  $$,    $$ $$""""   $$$$$$c
 `Y8bo,,,o88o888b "88bo,888  888    Y88  888_,o8P' 888oo,__ 888b "88bo,
   `'YMUP"YMMMMMM   "W" MMM  MMM     YM  MMMMP"`   """"YUMMMMMMM   "W"

usage: grinder.py [-h] [-r] [-u] [-q QUERIES_FILE] [-sk SHODAN_KEY]
                  [-vk VULNERS_KEY] [-cu] [-cp] [-ci CENSYS_ID]
                  [-cs CENSYS_SECRET] [-cm CENSYS_MAX] [-sm SHODAN_MAX] [-nm]
                  [-nw NMAP_WORKERS] [-vs] [-vw VULNERS_WORKERS]
                  [-ht HOST_TIMEOUT] [-tp TOP_PORTS] [-sc]
                  [-vc VENDOR_CONFIDENCE] [-qc QUERY_CONFIDENCE]
                  [-v [VENDORS [VENDORS ...]]] [-ml MAX_LIMIT] [-d] [-ts]
                  [-tsp TLS_SCAN_PATH] [-vr] [-ni]

The Grinder framework was created to automatically enumerate and fingerprint
different hosts on the Internet using different back-end systems

optional arguments:
  -h, --help            show this help message and exit
  -r, --run             Run scanning
  -u, --update-markers  Update map markers
  -q QUERIES_FILE, --queries-file QUERIES_FILE
                        JSON File with Shodan queries
  -sk SHODAN_KEY, --shodan-key SHODAN_KEY
                        Shodan API key
  -vk VULNERS_KEY, --vulners-key VULNERS_KEY
                        Vulners API key
  -cu, --count-unique   Count unique entities
  -cp, --create-plots   Create graphic plots
  -ci CENSYS_ID, --censys-id CENSYS_ID
                        Censys API ID key
  -cs CENSYS_SECRET, --censys-secret CENSYS_SECRET
                        Censys API SECRET key
  -cm CENSYS_MAX, --censys-max CENSYS_MAX
                        Censys default maximum results quantity
  -sm SHODAN_MAX, --shodan-max SHODAN_MAX
                        Shodan default maximum results quantity.
  -nm, --nmap-scan      Initiate Nmap scanning
  -nw NMAP_WORKERS, --nmap-workers NMAP_WORKERS
                        Number of Nmap workers to scan
  -vs, --vulners-scan   Initiate Vulners API scanning
  -vw VULNERS_WORKERS, --vulners-workers VULNERS_WORKERS
                        Number of Vulners workers to scan
  -ht HOST_TIMEOUT, --host-timeout HOST_TIMEOUT
                        Default host timeout in seconds for scanning with
                        Vulners and Nmap core
  -tp TOP_PORTS, --top-ports TOP_PORTS
                        Quantity of popular top-ports in addition to Shodan
                        ports
  -sc, --script-check   Initiate custom scripts additional checks
  -vc VENDOR_CONFIDENCE, --vendor-confidence VENDOR_CONFIDENCE
                        Set confidence level for vendors
  -qc QUERY_CONFIDENCE, --query-confidence QUERY_CONFIDENCE
                        Set confidence level for queries
  -v [VENDORS [VENDORS ...]], --vendors [VENDORS [VENDORS ...]]
                        Set list of vendors to search from queries file
  -ml MAX_LIMIT, --max-limit MAX_LIMIT
                        Maximum number of unique entities in plots and results
  -d, --debug           Show more information
  -ts, --tls-scan       Check for possible TLS attacks and bugs (require TLS-
                        Scanner)
  -tsp TLS_SCAN_PATH, --tls-scan-path TLS_SCAN_PATH
                        Path to TLS-Scanner.jar (if TLS-Scanner directory not
                        in Grinder root, else not required)
  -vr, --vulners-report
                        Make additional vulners reports
  -ni, --not-incremental
                        Turn off incrememental scan - make clean scan (without
                        previous results)
```
## Wiki
Additional extended documentation for the framework is available on the [repository wiki](https://github.com/sdnewhop/grinder/wiki), including additional information about flags, the internal structure of the framework, queries, and more.

## Examples
Run the most basic enumeration with Shodan and Censys engines without map markers and plots (results will be saved in database and output JSON):
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -r
```
Run an enumeration with 10 Nmap scanning workers, where maximum Censys results is 555 hosts per query and maximum Shodan results is 1337 hosts per query, update map markers, count unique entities and create plots:
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q FILE_WITH_QUERIES.json -cu -cp -cm 555 -sm 1337 -nm -nw 10 -r 
```
Run an enumeration with Nmap scanning, Vulners scanning and Vulners additional reports:
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -cu -cp -nm -nw 10 -vs -vw 10 -vr -vk YOUR_VULNERS_API_KEY_HERE -r
```
Run an enumeration with TLS scanning features:
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -ts -r 
```
Run an enumeration with filtering by vendors (only Nginx and Apache, for example) and confidence levels (only "Certain" level, for example) for queries and vendor:
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q FILE_WITH_QUERIES.json -v nginx apache -qc Certain -vc Certain -r
```
Run an enumeration with 10 workers of Nmap Vulners API scanning:
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q FILE_WITH_QUERIES.json -vs -vw 10 -r
```
Run an enumeration with custom scripts which are described in .json file with queries:
```bash
./grinder.py -sc -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -r
```
Run Grinder with debug information about scanning:
```bash
./grinder.py -d -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -r
```
For more options and help use
```bash
./grinder.py -h
```
## Add Your Own Queries
To add your own vendors and products with queries you can simply create a new .json file in the directory with queries and choose it while running Grinder in the "run" scan mode.

Format of file with queries:
```json
[
    {
        "vendor": "YOUR OWN VENDOR HERE",
        "product": "YOUR OWN PRODUCT HERE",
        "shodan_queries": [
            {
                "query": "YOUR SHODAN QUERY HERE",
                "query_confidence": "QUERY CONFIDENCE LEVEL {tentative|firm|certain}"
            }
        ],
        "censys_queries": [
            {
                "query": "YOUR CENSYS QUERY HERE",
                "query_confidence": "QUERY CONFIDENCE LEVEL {tentative|firm|certain}"
            }
        ],
        "scripts": {
            "py_script": "NAME OF PYTHON SCRIPT FROM /custom_scripts/py_scripts",
            "nse_script": "NAME OF NSE SCRIPT FROM /custom_scripts/nse_scripts"
        },
        "vendor_confidence": "VENDOR CONFIDENCE LEVEL {tentative|firm|certain}"
    }
]
```
