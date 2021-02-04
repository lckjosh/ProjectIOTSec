# ProjectIOTSec
This is a IOT Pentesting Framework Tool that has been coded in Python3 for Ubuntu 18.04

[![python](https://img.shields.io/badge/python-3.8-blue.svg)](https://www.python.org/downloads/)
![OS](https://img.shields.io/badge/OS-Ubuntu-orange.svg)

ProjectIOTSec is a software which seeks to automate the discovery and exploitation process of IoT devices. This is a IOT Pentesting Framework which contains the exploit modules for IOT devices. ProjectIOTSec is able to identify any device present inside a network using a port scan application (masscan), perform different brute-force attacks and probe some IoT exploits against the identified targets to validate the presence of known vulnerabilities.

## Main Features
Below is provided a list of the main activity and probe that ProjectIOTSec is able to perform:

- Service discovery and banner grabbing with masscan
- Bruteforce 
  - SSH
  - FTP
  - Telnet
- ASUS RT-AC3200 Router Exploit
- QNAP TS-412 NAS Exploit 
- D-Link DCS-933L IP Camera Exploit
- VeraEdge Home Controller Exploit
- Foscam C2 IP Camera Exploit
- Generation of HTML Report

## Installation

### Cloning the repo
```
git clone https://github.com/lckjosh/ProjectIOTSec.git
cd ProjectIOTSec
```

### Install Dependencies
```
sudo apt install masscan curl
sudo pip3 install -r requirements.txt
```

## Usage  
__NOTE: RUN `sudo python3 projectiotsec.py` to run as user with root privileges.__  
__Main Menu:__
```
  _____           _           _   _____ ____ _______ _____           
 |  __ \         (_)         | | |_   _/ __ \__   __/ ____|          
 | |__) | __ ___  _  ___  ___| |_  | || |  | | | | | (___   ___  ___ 
 |  ___/ '__/ _ \| |/ _ \/ __| __| | || |  | | | |  \___ \ / _ \/ __|
 | |   | | | (_) | |  __/ (__| |_ _| || |__| | | |  ____) |  __/ (__ 
 |_|   |_|  \___/| |\___|\___|\__|_____\____/  |_| |_____/ \___|\___|
                _/ |                                                 
               |__/                                                  


1. Scan Network
2. Post Exploitation Scan
3. Exit
```
