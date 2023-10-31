#!/usr/bin/python3
# https://github.com/n0nexist/SubnetDiscovery

import os
import sys
import socket
import threading
import time
import re

def restartProgram():
    """ restarts itself """
    os.execl(sys.executable, sys.executable, *sys.argv)

try:
	from scapy.all import ARP, Ether, srp, conf
except ImportError:
    print("\033[31mInstalling scapy...")
    os.popen("pip3 install scapy").read()
    restartProgram()

try:
	import ipaddress
except ImportError:
    print("\033[31mInstalling ipaddress...")
    os.popen("pip3 install ipaddress").read()
    restartProgram()

try:
    import manuf
except ImportError:
    print("\033[31mInstalling manuf...")
    os.popen("pip3 install manuf").read()
    restartProgram()

print("""\033[35m
         _     _ _         
 ___ _ _| |_ _| |_|___ ___ 
|_ -| | | . | . | |_ -|  _|
|___|___|___|___|_|___|___|
\033[36m·\033[35m subnet discovery tool
\033[36m·\033[35m github.com/n0nexist
""")

parser = manuf.MacParser()

waiting_hosts = []

port_service_list = [
    (20, "FTP Data"),
    (21, "FTP Control"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (465, "SMTPS"),
    (587, "SMTP (Submission)"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (8080, "HTTP Proxy"),
    (5555, "ADB"),
    (8008, "ChromeCast")
]

try:
	if sys.argv[1]:
		print(f"""
SubnetDiscovery 1.1 by n0nexist.github.io
usage: {sys.argv[0]} (without arguments)
		""")
		exit(-1)
except Exception:
	pass

def getSubnet():
    """ returns the current subnet """

    subnets = os.popen("ip addr").read().split("inet ")

    for x in range(len(subnets)):
        if x>0:
            y = subnets[x].split(" ")[0]
            print(f"\033[0;36m{x}\033[0m) \033[4;32m{y}\033[0m")
    
    return subnets[int(input("\n\033[36msubnet: "))].split(" ")[0]

def macAddrInfo(mac_address):
    """ gets info from a mac address """

    global parser

    try:
        return parser.get_manuf(mac_address)
    except Exception as e:
        return f"Error: {str(e)}"

def appendToFile(stri):
    """ appends a string to the subdisc.txt file """

    try:
        f = open("subdisc.txt","a")
        f.write(stri)
        f.close()
    except Exception as e:
        print(f"\033[31m{e}")

def check_port(host, port, result):
    """ checks wether a port is open on a remote host """
    s = socket.socket()
    s.settimeout(2)
    if s.connect_ex((host, port)) == 0:
        try:
            service = "\033[4;37m"+[service for p, service in port_service_list if p == port][0]
        except:
            service = f"\033[2;31m<unknown>"
        result.append(f"\033[1;34m{port}\033[30m - {service}\033[0m")
    s.close()

def getPorts(host):
    """ function to check common ports on a host """
    open_ports = []
    threads = []
    
    for port in range(1,1024):
        thread = threading.Thread(target=check_port, args=(host, port, open_ports))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return open_ports

def remove_ansi_escape(text):
    """ removes ansi escape codes from a string """
    ansi_escape = re.compile(r'\033\[[0-9;]*m')
    return ansi_escape.sub('', text)

def processHost(sent,received):
    """ prints information about an host """

    ip = received.psrc
    mac = received.hwsrc
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = "unknown hostname"

    infoString = f"\033[36m{ip}\033[0m <> \033[1;35m{hostname}\033[0m <> \033[91m{mac}\033[3;37m ({macAddrInfo(mac)})\033[0m"

    result = getPorts(ip)
    for port_info in result:
        infoString += f"\n{port_info}"
    infoString += "\n"    

    purgedString = remove_ansi_escape(infoString)

    print(infoString)
    appendToFile(purgedString+"\n")

def discover():
    """ discovers other hosts in the subnet """

    subnet = getSubnet()
    destination = "ff:ff:ff:ff:ff:ff"
    arp = ARP(pdst=subnet)
    ether = Ether(dst=destination)
    packet = ether/arp
    print(f"\033[1;91mSending arp packets to \033[0;36m{subnet}\033[0m ->\033[1;37m {destination}\033[0m...")
    result = srp(packet, timeout=3, verbose=1)[0]
    for sent, received in result:
        threading.Thread(target=processHost,args=(sent,received,)).start()

try:
    discover()
except Exception as e:
    print(f"\033[31m{e}")
    exit(-1)
