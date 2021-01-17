# ProjectIOTSec
This is a IOT Pentesting Framework Tool that has been coded in Python3 for Ubuntu 18.04

[![python](https://img.shields.io/badge/python-3.4-blue.svg)](https://www.python.org/downloads/)
![OS](https://img.shields.io/badge/OS-Ubuntu-orange.svg)

ProjectIOTSec is a software which seeks to automate the discovery and exploitation process of IoT devices. This is a IOT Pentesting Framework which contains the exploit modules for IOT devices. ProjectIOTSec is able to identify any device present inside a network using a port scan application (masscan), perform different brute-force attacks and probe some IoT exploits against the identified targets to validate the presence of known vulnerabilities.

## Main Features
Below is provided a list of the main activity and probe that IoT-SecurityCheker is able to perform:

- Service discovery and banner grabbing with masscan
- Bruteforce 
- ASUS RT-AC3200 Router Exploit
- QNAP TS-412 NAS Exploit 
- Dlink DCS-933L IP Camera Exploit
- VeraEdge Home Controller Exploit
- Foscam C2 IP Camera Exploit

## Installation

### Dependencies
- Python3
- Ubuntu 18.04 OS

### Cloning and Compilation
```
git clone https://github.com/lckjosh/ProjectIOTSec.git
```
## Usage  
__NOTE: RUN `sudo python3 projectiotsec.py` to run as user with root privileges.
```
sudo python3 projectiotsec.py

Options:
[1] Perform scan of network using Masscan
[2] Help page (effectively a man page)
[3] Exit program

