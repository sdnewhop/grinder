# grinder
Internet-connected Devices Census Python Framework 
![Grinder Screenshot](/screenshot.png?raw=true "Grinder Help")
## Description
The Grinder framework was created to automatically enumerate and fingerprint different hosts on the Internet using different back-end systems: search engines, such as Shodan or Censys, for discovering hosts and NMAP engine for fingerprinting and specific checks. The Grinder framework can be used in many different areas of researches, as a connected Python module in your own project or as an independent ready-to-use from the box tool.  
## Requirements
- Python 3.6+
- Shodan and Censys accounts
## Current features
[Grinder Development Project](https://github.com/sdnewhop/grinder/projects/2?fullscreen=true)
## Setup and configure environment
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
## Usage
```bash
usage: grinder.py [-h] [-r] [-u] [-q QUERIES_FILE] [-sk SHODAN_KEY] [-cu]
                  [-cp] [-ci CENSYS_ID] [-cs CENSYS_SECRET] [-cm CENSYS_MAX]
                  [-nm] [-nw NMAP_WORKERS] [-vs] [-vw VULNERS_WORKERS]
                  [-c CONFIDENCE] [-v [VENDORS [VENDORS ...]]] [-ml MAX_LIMIT]

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
  -nm, --nmap-scan      Initiate Nmap scanning
  -nw NMAP_WORKERS, --nmap-workers NMAP_WORKERS
                        Number of Nmap workers to scan
  -vs, --vulners-scan   Initiate Vulners API scanning
  -vw VULNERS_WORKERS, --vulners-workers VULNERS_WORKERS
                        Number of Vulners workers to scan
  -c CONFIDENCE, --confidence CONFIDENCE
                        Set confidence level
  -v [VENDORS [VENDORS ...]], --vendors [VENDORS [VENDORS ...]]
                        Set list of vendors to search from queries file
  -ml MAX_LIMIT, --max-limit MAX_LIMIT
                        Maximum number of unique entities in plots and results

```

## Tests
You can run tests from root grinder directory with command
```
pytest
```
## Examples
Run the most basic enumeration with Shodan and Censys engines without map markers and plots (results will be saved in database and output JSON):
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -q queries.json -r
```
Run an enumeration with 10 Nmap scanning workers, where maximum Censys results is 555 hosts per query, update map markers, count unique entities and create plots
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q queries.json -cu -cp -cm 555 -nm -nw 10 -r 
```
Run an enumeration with filtering by vendors (only Nginx and Apache, for example) and confidence levels (only "Firm" level, for example):
```bash
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q queries.json -v nginx apache -c Firm -r
```
Run an enumeration with 10 workers of Nmap Vulners API scanning:
```
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q queries.json -vs -vw 10 -r
```
For more options and help use
```bash
./grinder.py -h
```
