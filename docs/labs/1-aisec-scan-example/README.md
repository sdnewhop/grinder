# AISec (AIFinger) ML Scanning Example

Internet census of Machine Learning and Artificial Intelligence Frameworks and Applications with the Grinder Framework. 

## Goals 
The goal of this lab is to reproduce the results of passive and active fingerprinting of Machine Learning and Artificial Intelligence Frameworks and Applications using a common Threat Intelligence approach and to answer the following questions:

* How to detect AI/ML backed systems in the Internet and Entreprise network? 
* Is AI/ML apps secure at Internet scale? 
* What is AI/ML apps security level in a general sense at the present time? 

## Prerequisites and requirements
### Installation and running
To run the scan with the Grinder Framework you need to have the computer or virtual machine with installed Linux-flavoured system like Kali Linux or Ubuntu. MacOS is also ok and fully supported.

The prefered way to run the Grinder Framework in case of the lab environment (or if you don't want to install all the dependencies and other things directly into your system) is to build it with Docker - for more information about this method you can follow the next section of the documentation: [Building and Running in Docker](https://github.com/sdnewhop/grinder/tree/add_labs#building-and-running-in-docker)

To install the Grinder framework with all the dependencies directly, you can follow the next section of the documentation: [Grinder Installing](https://github.com/sdnewhop/grinder/tree/add_labs#grinder-installing)

### TL;DR
:bulb: **Note:** The fastest and recommended  way
  
1. Install [Docker](https://docs.docker.com/engine/install/ubuntu/)  
1. Install [Docker Compose](https://docs.docker.com/compose/install/)  
1. Clone and run the Grinder Framework  
```bash
git clone https://github.com/sdnewhop/grinder.git
cd grinder/
chmod +x docker_build.sh docker_run.sh
./docker_build.sh
./docker_run.sh
```
1. Check that services ready:  
```bash
CONTAINER ID        IMAGE                           COMMAND                  CREATED             STATUS              PORTS                    NAMES
1ebac2c5dc6e        grinder/grinder-framework:1.0   "/bin/sh /app/entryp…"   6 seconds ago       Up 5 seconds                                 grinder_framework
33620c19ab60        grinder/grinder-map:1.0         "python3 app.py"         7 seconds ago       Up 6 seconds        0.0.0.0:5000->5000/tcp   grinder_map
```
You are ready to go.
  
:bulb: **Note #1 (Troubleshooting):** If something goes wrong with `./docker_build.sh` or `./docker_run.sh`, run it with `sudo`:  
```bash
sudo ./docker_build.sh
sudo ./docker_run.sh
```
  
:bulb: **Note #2 (Troubleshooting):** Or add yourself to the `Docker` group, if you don't want to run it with `sudo`:  
```bash
sudo groupadd docker
sudo gpasswd -a $USER docker
```
Log out and log in to activate the group changes, and try to run the scripts again:  
```bash
./docker_build.sh
./docker_run.sh
```
