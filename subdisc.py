#!/usr/bin/python3
# https://github.com/n0nexist/SubnetDiscovery

import os

try:
	from scapy.all import ARP, Ether, srp, conf
except ImportError:
	print("\033[31mInstalling scapy...")
	os.popen("pip3 install scapy").read()

try:
	import ipaddress
except ImportError:
	print("\033[31mInstalling ipaddress...")
	os.popen("pip3 install ipaddress").read()

import socket
import requests
import threading
import sys

try:
	if sys.argv[1]:
		print(f"""
SubnetDiscovery by n0nexist.github.io
usage: {sys.argv[0]} (without arguments)
		""")
		exit(-1)
except Exception:
	pass

def getSubnet():
    """ returns the current subnet """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
    subnet = ipaddress.IPv4Network(f"{ip_address}/24", strict=False)
    return str(subnet)

def macAddrInfo(mac_address):
    """ gets info from a mac address """

    endpoint = f"https://api.macvendors.com/{mac_address}"
    r = requests.get(endpoint)
    if r.status_code != 200:
        return "*unknown mac vendor*"
    return r.text

def processHost(sent,received):
    """ prints information about an host """

    ip = received.psrc
    mac = received.hwsrc
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = "unknown hostname"
    print(f"\033[36m{ip}\033[0m <> \033[1;35m{hostname}\033[0m <> \033[91m{mac}\033[3;37m ({macAddrInfo(mac)})\033[0m")

def discover():
    """ discovers other hosts in the subnet """

    subnet = getSubnet()
    destination = "ff:ff:ff:ff:ff:ff"
    arp = ARP(pdst=subnet)
    ether = Ether(dst=destination)
    packet = ether/arp
    print(f"\033[3mSending arp packets to \033[0;36m{subnet}\033[0m ->\033[1;37m {destination}\033[0m...")
    result = srp(packet, timeout=3, verbose=0)[0]
    for sent, received in result:
        threading.Thread(target=processHost,args=(sent,received,)).start()

try:
    discover()
except Exception as e:
    print(f"\033[31m{e}")
    exit(-1)