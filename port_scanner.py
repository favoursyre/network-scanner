#I want to create a script that scans for open ports

#Useful libraries that I would be working with -->
import os
import sys
from queue import Queue
import socket
import threading


#This class function handles the port scanning
class portScanner:
    #Initializing the various arguments for the port scanner class
    def __init__(self, target_IP: str, startScan: int, endScan: int):
        self.target = target_IP
        self.startScan = startScan
        self.endScan = endScan
        self.portList = range(startScan, endScan)
        self.queue = Queue()
        self.openPorts = []

    #This scans various ports in the provided ip and searches for open port
    def portScan(self, port: int) -> bool: #If theres a connection to the socket, it's open and therefore True else its False
        try:
            socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_.connect((self.target, port))
            return True
        except Exception as e:
            #print(f"An error in portScan function due to [{e}]")
            return False

    #This fills the queue with the available ports
    def fillQueue(self):
        for port in self.portList:
            self.queue.put(port)

    #This checks if the port is available and then prints the 
    def worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            if portScanner.portScan(self, port):
                print(f"Port {port} is open")
                self.openPorts.append(port)

    #This function handles the returning of needed functions
    def openports_(self) -> list:
        return self.openPorts


#This function handles the threading of the port scanner function
def portScannerThread(target_IP: str, startScan: int, endScan: int, threadNum: int = 500) -> list:
    port_scanner_ = portScanner(target_IP, startScan, endScan)
    port_scanner_.fillQueue() #This calls the fill queue function
    openPorts = port_scanner_.openports_() #This gets the openports
    threadList = []

    for i in range(threadNum):
        thread = threading.Thread(target = port_scanner_.worker) #This calls the function and threads it based on the specified range
        threadList.append(thread)

    for thread in threadList: #This starts the thread
        thread.start()

    for thread in threadList: #This synchornizes the threading
        thread.join()

    print(f"Finished Scanning!! \nThere are {len(openPorts)} open ports, here they are {openPorts}")
    openPorts.sort()
    return [target_IP, openPorts]

def main() -> list:
    target = input("Enter the IP address of the system you want to scan: ")
    startScan = int(input("Enter the start scan: "))
    endScan = int(input("Enter the end scan: "))
    threadNum = int(input("Enter the thread num: "))
    print("\nStarting Scanning!!!")
    openPorts = portScannerThread(target, startScan, endScan, threadNum)
    print(f"Open ports: {openPorts}")
    return openPorts

if __name__ == "__main__":
    print("Port Scanner \n")

    open_ports = main()

    print("\nExecuted successfully!")

