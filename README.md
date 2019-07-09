# Grinder Framework
:mag_right: Internet-connected Devices Census Python Framework 
![Grinder Screenshot](/docs/screenshot.png?raw=true "Grinder Help")
## Contents
1. [Description](#description)
1. [Grinder Workflow](#grinder-workflow)
1. [Requirements](#requirements)
1. [Current Features](#current-features)
1. [Setup and Configure Environment](#setup-and-configure-environment)
1. [Build in Docker](#build-in-docker)
1. [Usage](#usage)
1. [Examples](#examples)
1. [Add Your Own Queries](#add-your-own-queries)
## Description
The Grinder framework was created to automatically enumerate and fingerprint different hosts on the Internet using different back-end systems: search engines, such as Shodan or Censys, for discovering hosts and NMAP engine for fingerprinting and specific checks. The Grinder framework can be used in many different areas of researches, as a connected Python module in your own project or as an independent ready-to-use from the box tool.  
## Grinder Workflow
![Grinder Workflow](/docs/workflow.png?raw=true "Grinder Workflow")
## Requirements
- [Python 3.6+](https://www.python.org/downloads/)
- [Shodan](https://account.shodan.io/register) and [Censys](https://account.shodan.io/register) accounts
- [Nmap Security Scanner](https://nmap.org/download.html)
## Current Features
 - [Grinder Development Project](https://github.com/sdnewhop/grinder/projects/2?fullscreen=true)  
 
The Grinder framework is still in progress and got features to improve, so all the tasks and other features will always be described in this project. If you got some awesome ideas or any other interesting things for Grinder, you can always open a pull request or some issues in this repository.
## Setup and Configure Environment
1. Clone the repository
```
git clone https://github.com/sdnewhop/grinder
```
2. Create virtual environment
```
cd grinder
python3 -m venv grindervenv
source grindervenv/bin/activate
```
3. Check if virtual environment successfully loaded
```
which python
which pip
```
4. Install project requirements in virtual environment
```
pip3 install -r requirements.txt
```
5. Run the script
```
./grinder.py -h
```
6. Set your Shodan and Censys keys via a command line argument
```
./grinder.py -sk YOUR_SHODAN_KEY -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET
```
or via an environment variable
```
export SHODAN_API_KEY=YOUR_SHODAN_API_KEY_HERE
export CENSYS_API_ID=YOUR_CENSYS_API_ID_HERE
export CENSYS_API_SECRET=YOUR_CENSYS_API_SECRET_HERE
```
7. Deactivate virtual environment after use and restore default python interpreter
```
deactivate
```
## Build in Docker
To build the Grinder framework as a docker image you can use the script `docker-build.sh`, and to run this image you can use the script `docker-run.sh`:
```bash
docker run -it --rm --volume $(pwd)/results:/code/results --volume $(pwd)/map:/code/map grinder-framework -h
```
## Usage
### Help on Command Line Arguments
```bash
usage: grinder.py [-h] [-r] [-u] [-q QUERIES_FILE] [-sk SHODAN_KEY] [-cu]
                  [-cp] [-ci CENSYS_ID] [-cs CENSYS_SECRET] [-cm CENSYS_MAX]
                  [-sm SHODAN_MAX] [-nm] [-nw NMAP_WORKERS] [-vs]
                  [-vw VULNERS_WORKERS] [-sc] [-vc VENDOR_CONFIDENCE]
                  [-qc QUERY_CONFIDENCE] [-v [VENDORS [VENDORS ...]]]
                  [-ml MAX_LIMIT] [-d]

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

```
## Examples
Run the most basic enumeration with Shodan and Censys engines without map markers and plots (results will be saved in database and output JSON):
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q FILE_WITH_QUERIES.json -r
```
Run an enumeration with 10 Nmap scanning workers, where maximum Censys results is 555 hosts per query and maximum Shodan results is 1337 hosts per query, update map markers, count unique entities and create plots:
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q FILE_WITH_QUERIES.json -cu -cp -cm 555 -sm 1337 -nm -nw 10 -r 
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
    },
    {
    
    }
]
```
