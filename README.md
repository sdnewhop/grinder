# Grinder Framework
[![Required OS](https://img.shields.io/badge/OS-Linux%20based-blue)](https://en.wikipedia.org/wiki/Linux)
[![Python3 Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL--2.0-blue)](/LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000)](https://github.com/psf/black)
[![Last Commit](https://img.shields.io/github/last-commit/sdnewhop/grinder)](https://github.com/sdnewhop/grinder)
  
:mag_right: Internet-connected Devices Census Python Framework 
  
## Screenshot
<div align="center">
  <img src="https://raw.githubusercontent.com/sdnewhop/grinder/master/docs/images/screenshot.png" alt="Grinder Framework Interface">
  <p align="center"><i>The basic CLI interface of the Grinder Framework</i></p>
</div> 
  
## Table of Contents
1. [Description](#description)
1. [Slides](#slides)
1. [Grinder Workflow](#grinder-workflow)
1. [Grinder Map](#grinder-map)
   - [Screenshots](#screenshots)
   - [Description](#description)
1. [Requirements](#requirements)
   - [Legend](#legend)
   - :pushpin: [Basic](#basic)
   - :pushpin: [Accounts](#accounts)
   - [Additional scanning](#additional-scanning)
   - [TLS configuration](#tls-configuration)
1. [Current Features](#current-features)
   - [Already Implemented](#already-implemented)
   - :fire: [Additional Modules](#additional-modules)
   - [Development and Future Updates](#development-and-future-updates)
1. :pushpin: [Grinder Installing](#grinder-installing)
   - [Setup and Configure Environment](#setup-and-configure-environment)
   - [Running Grinder Map Server Locally](#running-grinder-map-server-locally)
1. [Building and Running in Docker](#building-and-running-in-docker)
   - [Description](#description)
   - [Services and Images](#services-and-images)
   - [Provided Scripts and Preparations](#provided-scripts-and-preparations)
   - [Environment](#environment)
   - :pushpin: [Building](#building)
   - :pushpin: [Running](#running)
1. [Tests](#tests)
1. [CLI Interface](#cli-interface)
   - [Help on Command Line Arguments](#help-on-command-line-arguments)
1. [Wiki](#wiki)
1. :pushpin: [Usage Examples](#usage-examples)
   - [Show Help](#show-help)
   - [Basic Enumeration](#basic-enumeration)
   - [Enumeration with Limited Results](#enumeration-with-limited-results)
   - [Enumeration with Nmap Scanning](#enumeration-with-nmap-scanning)
   - [Enumeration with Additional Analytics, Map and Plots](#enumeration-with-additional-analytics-map-and-plots)
   - [Enumeration with Analytics from Vulners](#enumeration-with-analytics-from-vulners)
   - [Enumeration with TLS Configuration and Attacks Scanning](#enumeration-with-tls-configuration-and-attacks-scanning)
   - [Enumeration with Additional Filtering](#enumeration-with-additional-filtering)
   - [Enumeration with Additional Custom Scripts](#enumeration-with-additional-custom-scripts)
   - [Enumeration with Additional Debug Information](#enumeration-with-additional-debug-information)
1. :pushpin: [Add Your Own Queries](#add-your-own-queries)
   - [Description](#description)
   - [Queries Template](#queries-template)
   - [Queries Example](#queries-example)
  
## Description
The Grinder framework was created to automatically enumerate and fingerprint different hosts on the Internet using various back-end systems: search engines (such as Shodan or Censys) for discovering hosts and NMAP engine for fingerprinting and specific checks. Also, Grinder supports Vulners API to get information about available public exploits and vulnerabilities, documents related to found vulnerabilities and other features.  
  
The Grinder framework can be used in many different areas of research, as a connected Python module in your project or as an independent ready-to-use from the box tool. 
  
## Slides
1. One framework to rule them all: a framework for Internet-connected device census. PHDays 2019. ([Talk Page](http://2019.phdays.com/en/program/reports/one-framework-to-rule-them-all-a-framework-for-internet-connected-device-census/), [Slides](/docs/slides/phdays-9-one-framework-to-rule-them-all-a-framework-for-internet-connected-device-census.pdf))
1. One Framework to rule them all: A framework for Internet-connected Device Census. OFFZONE 2019. ([Talk Page](https://2019.offzone.moscow/report/one-framework-to-rule-them-all-a-framework-for-internet-connected-device-census/), [Slides](/docs/slides/offzone-grinder-2019.pdf))
## Grinder Workflow
![Grinder Workflow](/docs/images/workflow.png?raw=true "Grinder Workflow")
  
## Grinder Map
### Screenshots
<div align="center">
  <img src="https://raw.githubusercontent.com/sdnewhop/grinder/master/docs/images/map_1.png" alt="Grinder Framework Map (1)">
  <p align="center"><i>The Grinder Framework can easily build an interactive map with found hosts in your browser</i></p>
  <img src="https://raw.githubusercontent.com/sdnewhop/grinder/master/docs/images/map_2.png" alt="Grinder Framework Map (2)">
  <p align="center"><i>Also, the Grinder Framework can show you some basic information</i></p>
  <img src="https://raw.githubusercontent.com/sdnewhop/grinder/master/docs/images/map_3.png" alt="Grinder Framework Map (3)">
  <p align="center"><i>...And some additional information</i></p>
</div> 
  
### Description
To visualize gained data, the Grinder Framework provides an interactive world map with all results. Grinder map back-end that was written in Flask supports additional REST API methods to get more information about all scanned hosts or some particular host from the map, also it is possible to show some additional information about host interactively from the map.  
  
For example, the hosts will be automatically checked for availability with ping from back-end, also for every host many additional features are available: current host can be directly opened in Shodan, Censys, and ZoomEye web interfaces, the host can be shown on Google Maps with all available information about geolocation. Also, it is possible to make an IP lookup or open raw information in JSON directly in a browser or from your application with provided API methods.
  
## Requirements
### Legend
:heavy_exclamation_mark: required  
:heavy_plus_sign: not required to run (or required only for additional modules)
### Basic
- :heavy_exclamation_mark: [Python 3.6+](https://www.python.org/downloads/)
- :heavy_exclamation_mark: [python3-tk](https://docs.python.org/3/library/tkinter.html) library
- :heavy_exclamation_mark: [FreeType](https://www.freetype.org/) library (Python 3.8+)
### Accounts
- :heavy_exclamation_mark: [Shodan](https://account.shodan.io/register) and [Censys](https://censys.io/register) accounts  
Required to collect hosts, both free and full accounts are suitable. Also, it's possible to use only one account (Censys or Shodan, Shodan is preferable).
- :heavy_plus_sign: [Vulners](https://vulners.com/) account  
Required to make additional reports on vulnerabilities and exploits. If this feature is not required for you, you can use Grinder without Vulners account.
### Additional scanning
- :heavy_plus_sign: [Nmap Security Scanner 7.60+](https://nmap.org/download.html)  
Version 7.60 and newer has been tested with currently used in Grinder scripts (ssl-cert.nse, vulners.nse, etc.).
### TLS configuration
- :heavy_plus_sign: [Java 8](https://openjdk.java.net/install/)  
Required to build TLS-Attacker and TLS-Scanner.  
- :heavy_plus_sign: [TLS-Attacker 3.0](https://github.com/RUB-NDS/TLS-Attacker/releases/tag/3.0)  
Required only for TLS scanning.
- :heavy_plus_sign: [TLS-Scanner 2.9](https://github.com/RUB-NDS/TLS-Scanner/releases/tag/2.9)  
Required only for TLS scanning.
  
## Current Features
### Already Implemented
- :mag: Collecting hosts and additional information using Shodan and Censys search engines
- :rocket: Scanning ports and services with boosted multi-processed Nmap Scanner wrapper
- :syringe: Scanning vulnerabilities and additional information about them with Vulners database and Shodan CVEs database
- :memo: Retrieving information about SSL certificates
- :key: Scanning for SSL/TLS configuration and supported cipher suites
- :key: Scanning for SSL/TLS bugs, vulnerabilities and attacks
- :earth_asia: Building an interactive map with information about the hosts found
- :bar_chart: Creating plots and tables based on the collected results
- :wrench: Custom scanning scripts support (in LUA or Python3)
- :chart_with_downwards_trend: Confidence filtering system support
- :chart_with_upwards_trend: Special vendors scanning and filtering support
- :bulb: Searching for documents, security bulletins, public exploits and many more things based on detected by Grinder vulnerabilities and software

### Additional Modules
:rocket: **Note #1:** You can run multiple Python scripts simultaneously per multiple hosts, so you can build your own chain of scripts and checks to get the most information from your hosts. Feel free to add your modules with PR or give us an idea with feature issue.  
  
:construction: **Note #2:** Multiple NSE scripts running task is still in WIP status. So, NSE scripts will be ran consistently, one after one. New NSE script engine for Grinder is comming up, stay tuned.  

#### DICOM Patient Info Getter
**Location:** `py_scripts/dicom_getter/dicom_getter.py`  
**Description:** This module allows you to grab different patient information (including files) from medical servers
#### HTTP Raw Response Grabber
**Location:** `py_scripts/http_response_grabber/http_response_grabber.py`   
**Description:** This module allows you to grab the HTTP response (headers + body) in decoded raw-bytes format
#### HTTP Status
**Location:** `py_scripts/http_status/http_status.py`  
**Description:** This module allows you to check the HTTP status of the resource
#### SCP (SSH) Grabber
**Location:** `py_scripts/scp_grabber/scp_grabber.py`  
**Description:** This module allows you to grab and download files from different SSH servers (you need to define login/password in the module)
#### Sleep
**Location:** `py_scripts/sleep/sleep.py`  
**Description:** This is just a sleep module for test
#### SNMP Walker (easysnmp implementation)
**Location:** `py_scripts/snmp_walker_easysnmp/snmp_walker_easysnmp.py`  
**Description:** This module allows you to collect information from SNMP servers
#### SNMP Walker (system call implementation)
**Location:** `py_scripts/snmp_walker_os/snmp_walker_os.py`  
**Description:** The same as previous, but in another way
#### Tensor Serving Server Checker
**Location:** `py_scripts/tensor_serving_checker/tensor_serving_checker.py`  
**Description:** This module allows you to check, if the resource is TensorFlow Serving Server or not
#### Test
**Location:** `py_scripts/test/test.py`  
**Description:** Just an empty test script to check the functionality
  
### Development and Future Updates
 - [Grinder Development Project](https://github.com/sdnewhop/grinder/projects/2?fullscreen=true)  
 
:construction: **Note:** The Grinder framework is still in progress and got features to improve, so all the tasks and other features will always be described in this project. If you got some awesome ideas or any other interesting things for Grinder, you can always open a pull request or some issues in this repository.
  
## Grinder Installing
:bulb: **Note #1:** If you are familiar with pipenv package manager, all steps related to virtualenv can be replaced with `pipenv sync` command.  
  
:bulb: **Note #2:** If you are familiar with Docker and docker-compose, you can build framework with Docker, see [Building and Running in Docker](#building-and-running-in-docker)  
  
:bulb: **Note #3:** Only for macOS version 10.13 and higher, Python version 3.7.* and lower: to use additional scripts, which include other network libraries, you must additionally set the environment variable before starting - in your shell configuration file (`~/.bashrc`, `~/.zshrc`) or before starting the framework:
```bash
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
./grinder.py -h
```
  
### Setup and Configure Environment  
1. Install [Nmap Security Scanner](https://nmap.org/download.html) if not installed.
2. Install [python3-tk](https://docs.python.org/3/library/tkinter.html) package if not installed (Linux only)
```bash
sudo apt-get install python3-tk
```
3. Install [FreeType](https://www.freetype.org/) library (Python 3.8+)
```bash
sudo apt-get install build-essential libfreetype6-dev python-dev
```
4. Install virtualenv if not installed
```bash
sudo pip3 install virtualenv 
```
or
```bash
pip3 install --upgrade virtualenv
```
5. Clone the repository
```bash
git clone https://github.com/sdnewhop/grinder
```
6. Clone and install [TLS-Attacker 3.0](https://github.com/RUB-NDS/TLS-Attacker/releases/tag/3.0) (if you want to use TLS scanning features with Grinder).
7. Clone [TLS-Scanner 2.9](https://github.com/RUB-NDS/TLS-Scanner/releases/tag/2.9) in directory with Grinder and install it (if you want to use TLS scanning features with Grinder.
8. Create virtual environment
```bash
cd grinder
python3 -m venv grindervenv
source grindervenv/bin/activate
```
9. Check if virtual environment successfully loaded
```bash
which python3
which pip3
```
10. Install project requirements in virtual environment
```bash
pip3 install -r requirements.txt
```
11. _(MacOS version 10.13 and higher, Python version 3.7.* and lower)_  
Export additional environment variable to run different Python3 scripts
```bash
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```
12. Run the framework
```bash
./grinder.py -h
```
13. Set your Shodan, Censys and Vulners keys via a command line arguments on every run
```bash
./grinder.py -sk YOUR_SHODAN_KEY -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -vk YOUR_VULNERS_KEY
```
or via an environment variable permanently
```bash
export SHODAN_API_KEY=YOUR_SHODAN_API_KEY_HERE
export CENSYS_API_ID=YOUR_CENSYS_API_ID_HERE
export CENSYS_API_SECRET=YOUR_CENSYS_API_SECRET_HERE
export VULNERS_API_KEY=YOUR_VULNERS_API_KEY_HERE
```
14. Deactivate virtual environment after use and restore default python interpreter
```bash
deactivate
```

### Running Grinder Map Server Locally
1. First, complete all steps from the [Setup and Configure Environment/Grinder Installing](#setup-and-configure-environment) section above.
2. After the scan is completed, go to the "map" folder
```bash
cd map/
```
3. Run Flask (use `--help` key for more information)
```bash
flask run
```
4. Open in your browser
```
http://localhost:5000/
```
Also, Grinder map server provides simple API methods such as `/api/viewall/`, `/api/viewraw/<host_id>`, you can learn more from list of application routes
```bash
flask routes
```

## Building and Running in Docker
### Description
The Grinder Framework also supports building as a set of Docker images: one for the framework itself, one for the map and the last one temporary image for the TLS-Scanner. You can use them separately from each other, or all at once - all of these services are linked via docker-compose.yml file.  

### Services and Images
- `tls-scanner` as `grinder/tls-scanner:2.9` image
- `grinder` as `grinder/grinder-framework:1.0` image
- `map` as `grinder/grinder-map:1.0` image
  
### Provided Scripts and Preparations
To make the building process simple and convenient, a set of scripts provided in the repository to simplify routine actions.
- `docker_build.sh` script simply runs `docker-compose build`, so you can do it by yourself.
- `docker_run.sh` prepare all the required files and directories to link your host files with the ones in containers.

### Environment
First of all, you need to provide all the required environment variables via the `.env` or `docker-compose` file itself.

Required variables are (`docker-compose`):
```
SHODAN_API_KEY: ${SHODAN_API_KEY:-YOUR_SHODAN_API_KEY_HERE}
CENSYS_API_ID: ${CENSYS_API_ID:-YOUR_CENSYS_API_ID_HERE}
CENSYS_API_SECRET: ${CENSYS_API_SECRET:-YOUR_CENSYS_API_SECRET_HERE}
VULNERS_API_KEY: ${VULNERS_API_KEY:-YOUR_VULNERS_API_KEY_HERE}
```
Or in the same way for the `.env` file:
```
SHODAN_API_KEY=...
CENSYS_API_ID=...
CENSYS_API_SECRET=...
VULNERS_API_KEY=...
```
  
### Building
To build the Grinder Framework as an Alpine-based set of Docker images you can use the script `docker_build.sh`:
```bash
chmod +x docker_build.sh
./docker_build.sh
```
  
### Running
To run the Grinder Framework with all included services (Map, Framework and TLS-Scanner) you can use the script `docker_run.sh`:
```bash
chmod +x docker_run.sh
./docker_run.sh
```
After that, you can open map at `http://localhost:5000/`, shell of the Grinder Framework will be automatically open inside the container. All the data will be saved on your hosts directly via Docker volumes and mappings.

## Tests
To run basic tests for different scanning and analytics modules, you need to change directory to `tests/`:
```bash
cd tests/
```
And run basic tests with the next command - please, pay attention that you need to provide API keys for some modules (like Shodan, Censys) because tests are implemented to check all real functional features of these search engines in Grinder modules and wrappers:
```bash
pytest --shodan_key SHODAN_API_KEY --censys_id CENSYS_ID_KEY --censys_secret CENSYS_SECRET_KEY
```
:construction: **Note:** tests are still WIP, so please, feel free to create issues If you encounter any problems with it. Currently tests provided for some basic modules and features (Censys, Shodan, Filemanager, Database).


## CLI Interface
### Help on Command Line Arguments
```bash
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
  -scw SCRIPT_WORKERS, --script-workers SCRIPT_WORKERS
                        Number of script checking workers
  -scm, --script-mute   Suppress scripts output (stdout, stderr)
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

## Usage Examples
### Show Help
#### Description
Show all available CLI keys for the Grinder Framework
#### Example
```bash
./grinder.py -h
```
  
### Basic Enumeration
#### Description
Run the most basic enumeration with Shodan and Censys engines without map markers and plots updating (results will be saved in database and output JSON)
  
#### Template
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -r
```
  
#### Example
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q queries/servers.json -r
```
  
### Enumeration with Limited Results
#### Description
Run an enumeration where maximum Censys results is 555 hosts per query and maximum Shodan results is 1337 hosts per query
  
#### Template
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -cm CENSYS_RESULTS_LIMIT -sm SHODAN_RESULTS_LIMIT -r 
```
  
#### Example
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q queries/servers.json -cm 555 -sm 1337 -r 
```
  
### Enumeration with Nmap Scanning
#### Description
Run an enumeration with 10 Nmap Network Scanner scanning workers
  
#### Template
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -nm -nw NUMBER_OF_NMAP_WORKERS -r 
```
  
#### Example
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q queries/servers.json -nm -nw 10 -r 
```
  
### Enumeration with Additional Analytics, Map and Plots
#### Description
Run an enumeration, count unique entities, create plots and update Grinder Map markers data
  
#### Template
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -cu -cp -u -r 
```
  
#### Example
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q queries/servers.json -cu -cp -u -r 
```
  
### Enumeration with Analytics from Vulners
#### Description
Run an enumeration with Vulners scanning and Vulners additional reports, quantity of Vulners workers is equal to 10

#### Template
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -vs -vw NUMBER_OF_VULNERS_WORKERS -vr -vk YOUR_VULNERS_API_KEY_HERE -r
```

#### Example
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q queries/servers.json -vs -vw 10 -vr -vk YOUR_VULNERS_API_KEY_HERE -r
```

### Enumeration with TLS Configuration and Attacks Scanning
#### Description
Run an enumeration with TLS scanning features
  
#### Template
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -ts -r 
```

#### Example
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q queries/servers.json -ts -r 
```

### Enumeration with Additional Filtering
#### Description
Run an enumeration with filtering by vendors (only Nginx and Apache, for example) and confidence levels (only "Certain" level, for example) for queries and vendor
  
#### Template
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q FILE_WITH_QUERIES.json -v VENDOR_TO_INCLUDE_IN_1 VENDOR_TO_INCLUDE_IN_2 -qc QUERY_CONFIDENCE -vc VENDOR_CONFIDENCE -r
```
  
#### Example
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q queries/servers.json -v nginx apache -qc certain -vc certain -r
```

### Enumeration with Additional Custom Scripts
#### Description
Run an enumeration with custom scripts which are described in JSON file with queries in 10 workers
  
#### Template
```bash
./grinder.py -sc -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -sc -scw NUMBER_OF_SCRIPT_WORKERS -r
```
  
#### Example
```bash
./grinder.py -sc -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q queries/servers.json -sc -scw 10 -r
```
  
### Enumeration with Additional Debug Information
#### Description
Run Grinder with debug information about scanning
  
#### Template
```bash
./grinder.py -d -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -r
```
  
#### Example
```bash
./grinder.py -d -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q queries/servers.json -r
```
  
## Add Your Own Queries
### Description
To add your own vendors and products with queries you can simply create a new JSON file in the directory with queries and choose it while running Grinder in the "run" scan mode.

### Queries Template
```json
[
    {
        "vendor":"Your vendor name here ('Apache', for example; any string is allowed and required)",
        "product":"Your product name here ('HTTP Server', for example; any string is allowed and required)",
        "shodan_queries":[
            {
                "query":"Shodan query here ('Apache', 'Server: Apache', for example; any string is allowed and required)",
                "query_confidence":"Query confidence level ('tentative', 'firm' or 'certain' - you can sort and modify your search with these keywords, use query confidence flag for this purpose)"
            }
        ],
        "censys_queries":[
            {
                "query":"Censys query here ('Apache', 'Server: Apache', for example; any string is allowed and required)",
                "query_confidence":"Query confidence level ('tentative', 'firm' or 'certain' - you can sort and modify your search with these keywords, use query confidence flag for this purpose)"
            }
        ],
        "scripts":{
            "py_script":"3 types of definitions are allowed: you can use a simple string here, for example, 'test/test.py'; you can use a list here, for example, ['test1/test1.py', 'test2/test2.py']; you can use a dictionary here, for example, {'test': 'test/test.py'}",
            "nse_script":"Currently, you can run only 1 NSE script per time, this is WIP. Define the script with string, for example, 'test/test.nse'"
        },
        "vendor_confidence":"Vendor confidence level ('tentative', 'firm' or 'certain' - you can sort and modify your search with these keywords, use vendor and product confidence flags for this purpose)"
    }
]
```
### Queries Example
:construction: **Note:** Queries in the `queries/` directory may be different due to the different stages of development, but mostly all of them are still supported and tested. The most actual query template and an example are provided below, so if you need or want to try your queries, you can use this example to get the freshest features. 
```json
[
    {
        "vendor":"Apache Software Foundation",
        "product":"Apache HTTP Server",
        "shodan_queries":[
            {
                "query":"Apache",
                "query_confidence":"certain"
            }
        ],
        "censys_queries":[
            {
                "query":"Apache",
                "query_confidence":"certain"
            }
        ],
        "scripts":{
            "py_script":"http_status/http_status.py",
            "nse_script":""
        },
        "vendor_confidence":"certain"
    },
    {
        "vendor":"Nginx",
        "product":"Nginx",
        "shodan_queries":[
            {
                "query":"Nginx",
                "query_confidence":"certain"
            }
        ],
        "censys_queries":[
            {
                "query":"Nginx",
                "query_confidence":"certain"
            }
        ],
        "scripts":{
            "py_script":[
                "http_response_grabber/http_response_grabber.py",
                "http_status/http_status.py",
                "test/test.py"
            ],
            "nse_script":""
        },
        "vendor_confidence":"certain"
    },
    {
        "vendor":"Flask",
        "product":"Flask",
        "shodan_queries":[
            {
                "query":"Flask",
                "query_confidence":"certain"
            }
        ],
        "censys_queries":[
            {
                "query":"Flask",
                "query_confidence":"certain"
            }
        ],
        "scripts":{
            "py_script":{
                "grabber":"http_response_grabber/http_response_grabber.py",
                "status":"http_status/http_status.py",
                "test":"test/test.py"
            },
            "nse_script":""
        },
        "vendor_confidence":"certain"
    }
]
```
