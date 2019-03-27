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
```
usage: grinder.py [-h] [-r] [-u] [-q QUERIES_FILE] [-sk SHODAN_KEY] [-cu]
                  [-cp] [-ci CENSYS_ID] [-cs CENSYS_SECRET] [-cm CENSYS_MAX]
                  [-nm]

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

```

## Tests
You can run tests from root grinder directory with command
```
pytest
```
## Examples
Run an enumeration with Nmap scanning, where maximum Censys results is 555 hosts per query, update map markers, count unique entities and create plots
```
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q queries.json -cu -cp -cm 555 -nm -r 
```
For more options and help use
```
./grinder.py -h
```
