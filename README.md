# ProjectIOTSec
This is a IOT Pentesting Framework Tool that has been developed in Python3 and in Ubuntu 18.04.5 LTS 

[![python](https://img.shields.io/badge/python-3.8-blue.svg)](https://www.python.org/downloads/)
![OS](https://img.shields.io/badge/OS-Ubuntu-orange.svg)

ProjectIOTSec is a software which seeks to aid in the discovery, exploitation and post exploitation detection of IoT devices. This IOT Pentesting Framework contains exploit modules for various different IOT devices. ProjectIOTSec is able to identify any device present inside a network using a port scan application (Masscan), perform different brute-force attacks and probe some IoT exploits against the identified targets to validate the presence of known vulnerabilities.

## Main Features
Below is a list of the main activities and exploits that ProjectIOTSec is able to perform:

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

Please choose option number: 
```
