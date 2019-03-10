# grinder
Python framework to automatically discover and enumerate hosts from Shodan  
![Grinder Screenshot](/screenshot.png?raw=true "Grinder Help")
## Requirements
- Python 3.6+
## Current features
[Grinder Development Project](https://github.com/sdnewhop/grinder/projects/2?fullscreen=true)
## Setup and configure environment
Create virtual environment
```
python3 -m venv grindervenv
source grindervenv/bin/activate
```
Check if venv successfully loaded
```
which python
which pip
```
Install project requirements in venv
```
pip install -r requirements.txt
```
Deactivate venv after use
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
./grinder.py -sk YOUR_SHODAN_API_KEY_HERE -u -q queries.json -cu -cp -r
```
For more options and help use
```
./grinder.py -h
```
