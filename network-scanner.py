#I want create a python script that allows me to scan all devices in a local area network for a specified open port

#Useful libraries that I would be working with
import os
import sys
import socket
import subprocess
import ip_info
import port_scanner as psn
import queue
import uuid
import requests
import datetime
from threading import Thread
import threader as th
from scapy.all import *
import netifaces


#Declaring the various variables
class Network_Scanner:
    #Initializing the various arguments for the port scanner class
    def __init__(self, target: str):
        self.openPorts = []
        self.user, self.host, self.publicIP, self.privateIP = ip_info.main()
        self.queue_ = queue.Queue()
        self.router = netifaces.gateways()["default"][netifaces.AF_INET][0]
        self.target = target
        self.date_time = datetime.now().strftime("%H:%M:%S %p. %d %B, %Y")
        self.report = f"""{'~' * 30} NETWORK SCANNER REPORT {'~' * 30}

        ~~~ Mission Details ~~~
Target: {self.target}
Username: {self.user}
Hostname: {self.host}
Private IP: {self.privateIP}
Public IP: {self.publicIP}
Time Stamp: {self.date_time}

        \n     ~~~ Mission Briefing ~~~      \n\n"""

    #This function gets the subnet mask of an IP address
    def netmask(self) -> str:
        proc = subprocess.Popen('ipconfig', stdout = subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            #print(line)
            if self.privateIP.encode() in line:
                #print("Main Line: ", line)
                #print(f"Ip encode: {ip.encode()}")
                break
        mask = proc.stdout.readline().rstrip().split(b':')[-1].replace(b' ', b'').decode()
        return str(mask)

    #This function gets the list of all possible devices in the LAN
    def devices_(self) -> list:
        mask = self.netmask()
        addr = self.router.rstrip().split('.')
        possibleDevices = []
        if mask.count("0") == 1:
            ipStart = f"{addr[0]}.{addr[1]}.{addr[2]}."
            for i in range(256):
                possibleDevices.append(f"{ipStart}{i}")
        elif mask.count("0") == 2:
            ipStart = f"{addr[0]}.{addr[1]}."
            for i in range(256):
                for j in range(256):
                    possibleDevices.append(f"{ipStart}{i}.{j}")
        elif mask.count("0") == 3:
            ipStart = f"{addr[0]}."
            for i in range(256):
                for j in range(256):
                    for k in range(256):
                        possibleDevices.append(f"{ipStart}{i}.{j}.{k}")
        else:
            for i in range(256):
                for j in range(256):
                    for k in range(256):
                        for l in range(256):
                            possibleDevices.append(f"{i}.{j}.{k}.{l}")
        return possibleDevices

    #This function allows us to ping an ip address to check for active response
    def ping_(self, ip: str):
        response = os.popen(f"ping {ip}").read()
        #print(f"Response: {response}")
        if "Destination host unreachable." not in response:
            print(f"{ip} is ACTIVE")
            return ip
        else:
            #print(f"{ip} is INACTIVE")
            pass

    #This function helps get the vendor of a specified mac address
    def macVendor(self, mac_address):
        url = "https://api.macvendors.com/"
        response = requests.get(url + mac_address)
        if response.status_code != 200:
            raise Exception("[!] Invalid MAC Address!")
        return response.content.decode()

    #This gets all possible devices in the lan based on the ip address
    #@property
    def lanScan(self):
        possibleDevices = self.devices_()
        #print(f"Possible Devices: {possibleDevices}")
        #This handles the threading of pinging all possible devices in the network for response
        threads = []
        pinged_ip = []
        print(f"Starting LAN Scanning under router [{self.router}]...")
        if possibleDevices:
            for ip in possibleDevices:
                t1 = Thread(target = lambda q, arg1: q.put(self.ping_(arg1)), args = (self.queue_, ip, ))
                threads.append(t1)

            for t in threads:
                t.start()

            for t in threads:
                t.join()
                res = self.queue_.get()
                if res:
                    #print(f"RES: {res}")
                    pinged_ip.append(res)
        
        for i in pinged_ip:
            if i == self.router:
                pinged_ip.remove(i)
        print(f"My Data: {pinged_ip}")
        return pinged_ip, self.router

    #This section would handle getting hostnames from ip address that are up
    @property
    def lanReport(self):
        ip_, router = self.lanScan()
        self.report += f"""{'~' * 30} LAN REPORT {'~' * 30}

Active Devices Under Router[[{router}]] LAN \n\n\tID\t|\tHostname\t|\tIP_ADDRESS\t|\tMAC ADDRESS\t|\tDEVICE COMPANY\t\n{'~' * 100}\n"""
        id = 1
        for i in ip_:
            try:
                try:
                    hostname = socket.gethostbyaddr(f"{i}")
                except:
                    hostname = "Null"
                try:
                    if i == self.privateIP:
                        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
                    else:
                        mac = getmacbyip(f"{i}")
                except:
                    mac = "Null"
                try:
                    vendor = self.macVendor(mac)
                except:
                    vendor = "Null"
                if hostname == "Null":
                    self.report += f"\t{id}\t|\t{hostname}\t|\t{i}\t|\t{mac}\t|\t{vendor}\t\n"
                else:
                    self.report += f"\t{id}\t|\t{hostname[0]}\t|\t{hostname[2][0]}\t|\t{mac}\t|\t{vendor}\t\n"
            except Exception as e:
                stat = f"An error occured when compiling the LAN report due to [{e}]\n"
                self.report += stat
                print(stat)
            finally:
                id += 1
        print()
        #report = f"{self.report}"
        print(self.report)
        return self.report

    #This scans lan or an ip for a open specified port
    def portScan(self, ip_: str, port: int): #If theres a connection to the socket, it's open and therefore True else its False
        if ip_ == "LAN":
            ip_, router = self.lanScan()
            header = f"Active Devices Under Router[[{router}]] LAN scanned for Port {port}"
        else:
            ip_ = [str(ip_)]
            header = f"Result for scanned Port {port} on {ip_}"
        portName = socket.getservbyport(port)
        self.report += f"""{'~' * 30} PORT SCAN REPORT {'~' * 30}

{header}\n\n\tID\t|\tHostname\t|\tIP_ADDRESS\t|\tPORT {port} ({portName}) STATUS\t\n{'~' * 100}\n"""
        open_devices = []
        id = 1
        print(f"Scanned IP: {ip_}")
        for i in ip_:
            try:
                socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_.connect((i, port))
                print(f"Port {port} is open on {i}")
                open_devices.append(i)
                status = "OPEN"
            except:
                print(f"Port {port} is not open on {i}")
                status = "CLOSE"
            finally:
                try:
                    hostname = socket.gethostbyaddr(f"{i}")
                    self.report += f"\t{id}\t|\t{hostname[0]}\t|\t{hostname[2][0]}\t|\t{status}\t\n"
                except:
                    hostname = "Null"
                    self.report += f"\t{id}\t|\t{hostname}\t|\t{i}\t|\t{status}\t\n"
                id += 1
        print(self.report)
        return self.report, open_devices

    #This function scans a lan or ip for a range of open specified ports
    def portScanner(self, ip_: str, start: int, end: int) -> str:
        if ip_ == "LAN":
            ip_, router = self.lanScan()
            header = f"Active Devices Under Router[[{router}]] LAN scanned for Port [{start} - {end}]"
        else:
            ip_ = [str(ip_)]
            header = f"Result for scanned Ports on {ip_}"
        id = 1
        print(f"IP: {ip_}")
        self.report += f"""{'~' * 30} PORT SCANNER REPORT {'~' * 30}

{header}\n\n\tID\t|\tHostname\t|\tIP_ADDRESS\t|\tOPEN PORTS\t\n{'~' * 100}\n"""
        threads = [] 
        ports = []
        try:
            for i in ip_:
                openPorts = th.thread_(target = psn.portScannerThread, args = (i, start, end, ))
                threads.append(openPorts)

            for p in threads:
                res = p.join()
                ports.append(res)
        except Exception as e:
            print(f"An Error occurred in port scanner threading function due to [{e}]")
            #openPorts = "Null"
        finally:
            print("Ports: ", ports)
            print("Ports[0]: ", ports[0])
            for i in ports:
                try:
                    print(f"I[0]: {i[0]}")
                    print(f"I[1]: {i[1]}")
                    if i[1]:
                        pass
                    else:
                        i[1] = "None"
                    ports_ = {}
                    hostname = socket.gethostbyaddr(f"{i[0]}")
                    
                    for p in i[1]:
                        ports_[p] = f"{socket.getservbyport(p)}"
                    self.report += f"\t{id}\t|\t{hostname[0]}\t|\t{hostname[2][0]}\t|\t{ports_}\t\n"
                except Exception as e:
                    print(f"An error occured in compiling result due to [{e}]")
                    hostname = "Null"
                    self.report += f"\t{id}\t|\t{hostname}\t|\t{i[0]}\t|\t{ports_}\t\n"
                id += 1
        print(self.report)
        return self.report




if __name__ == "__main__":
    print("NETWORK SCANNER \n")

    target = "Konoha"
    scanner = Network_Scanner(target)
    #lan_report = scanner.lanReport #This scans for active devices in the LAN
    #report, open_devices = scanner.portScan("LAN", 22) #This scans the lan for open port 22
    report = scanner.portScanner("LAN", 1, 500)

    print("\nExecuted successfully!!")