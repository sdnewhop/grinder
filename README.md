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
https://github.com/sdnewhop/grinder
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
pip install -r requirements.txt
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
## Tests
You can run tests from root grinder directory with command
```
pytest
```
## Run
Basic usage
```
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -ci YOUR_CENSYS_ID -cs YOUR_CENSYS_SECRET -u -q queries.json -cu -cp -r
```
For more options and help use
```
./grinder.py -h
```
