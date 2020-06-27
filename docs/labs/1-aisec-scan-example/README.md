# AISec (AIFinger) ML Scanning Example

Internet census of Machine Learning and Artificial Intelligence Frameworks and Applications with the Grinder Framework. 

## Table of Contents
1. [Goals](#goals)
1. [Prerequisites and requirements](#prerequisites-and-requirements)
1. [Running and Scanning](#running-and-scanning)
1. [Results](#results)
1. [Interactive Map](#interactive-map)

## Goals 
The goal of this lab is to reproduce the results of passive and active fingerprinting of Machine Learning and Artificial Intelligence Frameworks and Applications using a common Threat Intelligence approach and to answer the following questions:

* How to detect AI/ML backed systems in the Internet and Entreprise network? 
* Is AI/ML apps secure at Internet scale? 
* What is AI/ML apps security level in a general sense at the present time? 

## This Lab Contains
1. This document with additional information and description
1. Additional `.sh` scripts with set of different scanning commands

## Prerequisites and Requirements
### TL;DR
:bulb: **Note #1:** The fastest and recommended  way
  
1. Install [Docker](https://docs.docker.com/engine/install/ubuntu/)  
1. Install [Docker Compose](https://docs.docker.com/compose/install/)  
1. Clone and run the Grinder Framework. These commands will drop you directly into the running container with Grinder
```bash
git clone https://github.com/sdnewhop/grinder.git
cd grinder/
chmod +x docker_build.sh docker_run.sh
./docker_build.sh
./docker_run.sh
```
4. From the other terminal window, check that both services are ready and up  
```bash
CONTAINER ID        IMAGE                           COMMAND                  CREATED             STATUS              PORTS                    NAMES
1ebac2c5dc6e        grinder/grinder-framework:1.0   "/bin/sh /app/entryp…"   6 seconds ago       Up 5 seconds                                 grinder_framework
33620c19ab60        grinder/grinder-map:1.0         "python3 app.py"         7 seconds ago       Up 6 seconds        0.0.0.0:5000->5000/tcp   grinder_map
```
![Running Services](/docs/labs/1-aisec-scan-example/assets/services_up.png?raw=true "Running services")

  
If everything is okay here - **congratulations!** :sparkles: Continue with steps 5-7.  
If something is wrong, see the :point_right: [Troubleshooting](#troubleshooting) notes below. If you want to try different possible options of the installation, see the :point_right: [Installation and Running Options](#installation-and-running-options) part below.
  
5. _(Additional)_ Copy scripts to the container from the other terminal window (or you can copy-paste commands from them, that will be fine too)
```bash
(on host system)        docker cp docs/labs/1-aisec-scan-example/commands grinder_framework:/app
(in running container)  chmod +x /app/commands/*
```
6. _(Additional)_ Set your Shodan or Censys keys as an environment variable (to skip the `-sk` key and use the Grinder Framework without this key)  
```bash
export SHODAN_API_KEY=YOUR_SHODAN_API_KEY_HERE
```
7. _(Additional)_ Run any script from `/app/commands/` in your running container to start the scan
```bash
./commands/basic.sh
```
  
### Troubleshooting
:bulb: **Note #2 (Troubleshooting):** If something goes wrong with `./docker_build.sh` or `./docker_run.sh`, run it with `sudo`:  
```bash
sudo ./docker_build.sh
sudo ./docker_run.sh
```
  
:bulb: **Note #3 (Troubleshooting):** Or add yourself to the `Docker` group, if you don't want to run it with `sudo`:  
```bash
sudo groupadd docker
sudo gpasswd -a $USER docker
```
Log out and log in to activate the group changes, and try to run the scripts again:  
```bash
./docker_build.sh
./docker_run.sh
```
### Installation and Running Options
To run the scan with the Grinder Framework you need to have the computer or virtual machine with installed Linux-flavoured system like Kali Linux or Ubuntu. MacOS is also ok and fully supported.

The prefered way to run the Grinder Framework in case of the lab environment (or if you don't want to install all the dependencies and other things directly into your system) is to build it with Docker - for more information about this method you can follow the next section of the documentation: :point_right: [Building and Running in Docker](https://github.com/sdnewhop/grinder/tree/add_labs#building-and-running-in-docker)

To install the Grinder framework with all the dependencies directly, you can follow the next section of the documentation: :point_right: [Grinder Installing](https://github.com/sdnewhop/grinder/tree/add_labs#grinder-installing)

## Running and Scanning
### Basic Scan
:bulb: **Note #4 (Speed):** This is the most basic scan, so depends on different reasons it might be **slow** (30-45 minutes for all 50+ products from AI-Finger). If you want to try the basic idea faster with less results, you can go to the next part below (see :point_right: [Faster Scan with Less Results](#faster-scan-with-less-results))

To get the basic scanning results with different ML/AI solutions from the Grinder Framework you can run the following command inside the running Docker container shell (which you will get after `./docker_run.sh` running):
```bash
./grinder.py -r -u -q queries/aisec_aifinger_all.json -sk YOUR_SHODAN_API_KEY_HERE -cu -cp -ni
```
This command will do the following:
1. `-r` - initiate scan run
1. `-u` - update map markers to put all the results on the interactive map
1. `-q queries/aisec_aifinger_all.json` - select the file with the queries. In this case, we use `aisec_aifinger_all.json` query file.
1. `-sk YOUR_SHODAN_API_KEY_HERE` - your paid plan API key for the Shodan
1. `-cu` - count unique entities, like unique vulnerabilities, countries, continents etc.
1. `-cp` - create graphical plots to visualize the unique data
1. `-ni` - not increment any previous results (because for now we don't have any earlier results)
  
:bulb: **Note #5 (Censys Scan):** If you also have Censys API keys with paid plan, you can add it with the following keys:
```
  -ci CENSYS_ID, --censys-id CENSYS_ID
                        Censys API ID key
  -cs CENSYS_SECRET, --censys-secret CENSYS_SECRET
                        Censys API SECRET key
```
:bulb: **Note #6 (Limit Results):** If you want to speed up scanning (in case if you don't need to get overall full results), you can set the results limit for every query - for example, 10-100 hosts per query. To do this, you can use the following keys:
```
  -cm CENSYS_MAX, --censys-max CENSYS_MAX
                        Censys default maximum results quantity (for example, --censys-max 50)
  -sm SHODAN_MAX, --shodan-max SHODAN_MAX
                        Shodan default maximum results quantity (for example, --shodan-max 50)
```
  
### Faster Scan with Less Results
To get the faster scanning process with different ML/AI solutions from the Grinder Framework you can run the following command inside the running Docker container shell (which you will get after `./docker_run.sh` running):
```bash
./grinder.py -r -u -q queries/aisec_aifinger_all.json -sk YOUR_SHODAN_API_KEY_HERE -cu -cp -ni -sm 50 -cm 50 -vc certain -qc certain
```
This command will do the following:
1. `-r` - initiate scan run
1. `-u` - update map markers to put all the results on the interactive map
1. `-q queries/aisec_aifinger_all.json` - select the file with the queries. In this case, we use `aisec_aifinger_all.json` query file.
1. `-sk YOUR_SHODAN_API_KEY_HERE` - your paid plan API key for the Shodan
1. `-cu` - count unique entities, like unique vulnerabilities, countries, continents etc.
1. `-cp` - create graphical plots to visualize the unique data
1. `-ni` - not increment any previous results (because for now we don't have any earlier results)
1. `-sm 50` - limit Shodan results with 50 hosts per query
1. `-cm 50` - limit Censys results with 50 hosts per query (if Censys keys are provided)
1. `-vc certain` - include only trusted presice vendors
1. `-qc certain` - include only trusted presice queries

### Include Additional Checks
You can also run an active phase scanning with Nmap Network Scanner or/and Vulners API Script. To do it, add the following keys:
```
  -nm, --nmap-scan      Initiate Nmap scanning
  -nw NMAP_WORKERS, --nmap-workers NMAP_WORKERS
                        Number of Nmap workers to scan
  -vs, --vulners-scan   Initiate Vulners API scanning
  -vw VULNERS_WORKERS, --vulners-workers VULNERS_WORKERS
                        Number of Vulners workers to scan
```
So the Grinder Framework scanning command can be the following:
```bash
./grinder.py -r -u -q queries/aisec_aifinger_all.json -sk YOUR_SHODAN_API_KEY_HERE -cu -cp -ni -sm 50 -cm 50 -vc certain -qc certain -nm -nw 50 -vs -vw 50
```

## Results
### Framework Output
After running any of the commands from above, you will see the the following output (the quantity and queries is just an example, your results and output may be slightly different):
```
  .,-:::::/ :::::::..   ::::::.    :::.:::::::-.  .,:::::: :::::::..
,;;-'````'  ;;;;``;;;;  ;;;`;;;;,  `;;; ;;,   `';,;;;;'''' ;;;;``;;;;
[[[   [[[[[[/[[[,/[[['  [[[  [[[[[. '[[ `[[     [[ [[cccc   [[[,/[[['
"$$c.    "$$ $$$$$$c    $$$  $$$ "Y$c$$  $$,    $$ $$""""   $$$$$$c
 `Y8bo,,,o88o888b "88bo,888  888    Y88  888_,o8P' 888oo,__ 888b "88bo,
   `'YMUP"YMMMMMM   "W" MMM  MMM     YM  MMMMP"`   """"YUMMMMMMM   "W"

File with queries: queries/aisec_aifinger_all.json
0 / 51 :: Current product: Deeplearning4j
0 / 2 :: Current Shodan query is: http.title:"DL4J Training UI"
│ Shodan results count: 2
│ Real results count: 2
└ Done in 10.11s (00:00:10)
1 / 2 :: Current Shodan query is: http.favicon.hash:-165549574
│ Shodan results count: 2
│ Real results count: 2
└ Done in 22.26s (00:00:22)
1 / 51 :: Current product: FATE
0 / 2 :: Current Shodan query is: http.title:"FATE Board"
│ Shodan results count: 52
│ Real results count: 52
└ Done in 8.96s (00:00:08)
1 / 2 :: Current Shodan query is: all:"FATE" "Content-Length: 2831"
│ Shodan results count: 1
│ Real results count: 1
└ Done in 32.57s (00:00:32)

...
```
Wait until scanning process will finish (it will take some time, which is depends on your network connection, API plan, Shodan API endpoint load etc.).

### Results Structure
When scanning process is finished, you can see the results in `grinder/results/` directory. The structure of the results is:  
```bash
results
├── csv
├── json
└── png
    ├── all_results
    └── limited_results

5 directories
```
:bulb: **Note #7 (Recommended Representation):** `JSON` format is prefereble representation for the results. Main file that include all the results is `results/json/all_results.json`

Structure can be described as:
1. `csv` - all results in `CSV` format representation
1. `json` - all results in `JSON` format representation
1. `png` - different plots and graphics

### Results Format
The resulting file (`all_results.json`) format can be described with the following example:
```json
[
    {
        "product": "Megarac SP",
        "vendor": "American Megatrends",
        "query": "\"3.14.17-ami\"",
        "port": 123,
        "proto": "ntp",
        "ip": "**.**.**.**",
        "lat": 51.4416,
        "lng": 7.5633,
        "country": "Germany",
        "organization": "O2 Deutschland",
        "vulnerabilities": {
            "shodan_vulnerabilities": {},
            "vulners_vulnerabilities": {}
        },
        "nmap_scan": {},
        "scripts": {
            "py_script": null,
            "nse_script": null
        }
    }
]
```
The plots example from the `results/png/limited_results/`. This plots were based on the data from 100 random hosts.

![Results by Countries](/docs/labs/1-aisec-scan-example/assets/results_countries.png?raw=true "Results by Countries")
![Results by Organizations](/docs/labs/1-aisec-scan-example/assets/results_organizations.png?raw=true "Results by Organizations")

## Interactive Map
Map starts automatically with the container. Container will expose port 5000 to the host machine, so you can get access to the map via [http://localhost:5000/](http://localhost:5000/) when scanning is finished. 

Map allows you to find and sort results by vendor, products, CVEs and many other things. To do it, try to use search field in the right upper corner of the map. Also, map provides basic information about the hosts.

For example:  
1. To show only American Megatrends Megarac SP product on the map, search for it with "Megarac SP" phrase:  
:point_right: [http://localhost:5000/search?query=Megarac+SP](http://localhost:5000/search?query=Megarac+SP)
1. To find host by ip, you can search for it directly:  
:point_right: [http://localhost:5000/search?query=180.150.54.99](http://localhost:5000/search?query=180.150.54.99)
1. To search for some particular protocol, for example, `https-simple-new`:  
:point_right: [http://localhost:5000/search?query=https-simple-new](http://localhost:5000/search?query=https-simple-new)

All available routes:
```
Endpoint           Methods  Rule
-----------------  -------  ---------------------------------
api_raw_all        GET      /api/viewall
api_raw_host       GET      /api/viewraw/<path:host_id>
api_raw_host_ping  GET      /api/viewraw/<path:host_id>/ping
api_update_data    GET      /update
reset_search       GET      /reset
root               GET      /
search             GET      /search
```
