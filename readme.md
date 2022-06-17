# Network Scanner
## Disclaimer
This script is for educational purposes only, I don't endorse or promote it's illegal usage

## Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Languages](#languages)
4. [Installations](#installations)
5. [Usage](#usage)
6. [Run](#run)

## Overview
This script scans a LAN for active devices and open ports

## Features
* Scans a LAN for active devices
* Scans a LAN or target_IP for a specified port
* Scans a LAN or target_IP for a range of specified ports

## Languages
* Python 3.9.7

## Installations
```shell
pip install netifaces
pip install scapy
```

## Usage
Instantiating the network scanner class
```python
target = "Konoha"
scanner = Network_Scanner(target)
```

Scanning for active devices in the LAN
```python
lan_report = scanner.lanReport #This scans for active devices in the LAN
```

Scanning for a specific open port in the LAN
```python
target_IP = "LAN" #You can replace 'LAN' with a specific target IP if you don't want to scan the whole LAN for the port
port = 22
report, open_devices = scanner.portScan(target_IP, port)
```

Scanning for a range of open ports in the LAN
```python
target_IP = "LAN" #You can replace 'LAN' with a specific target IP if you don't want to scan the whole LAN for the ports
start_port=1
end_port=1000
report = scanner.portScanner(target_IP, start_port, end_port)
```

## Run
```bash
python network-scanner.py
```
