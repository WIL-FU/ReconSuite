#reconsuite proto 0.0
#author: wil jankovic
#
# ReconSuite - passive/active web recon orchestration tool used for pentesting/red teaming/CTFs.
# includes
#  - port scanning
#  - http/s probing
#  - banner grabbing
#  - fingerprinting
#  - passive subdomain enumeration
#  - VHOST fuzzing
#  - CMS detection
#  - DNS enumeration
#  - TLS inspection
#  - automatic Markdown report generation
#  - detailed AI-generated summary of all gathered data
# disclaimer: this is only to be used in controlled, authorized environments, or for educational purposes.

import os
import socket
import subprocess
import time
import scapy.all as scapy
from urllib.parse import urlparse
import socket
import xml.etree.ElementTree as ET
import requests
import json
import shutil

l=[]
p=[]
isHttps = False
def resolve_ip(addr):
    try:
        parsed = urlparse(addr)

        hostname = parsed.netloc if parsed.netloc else addr

        ip = socket.gethostbyname(hostname)
        return ip

    except socket.gaierror:
        print("[-] Hostname could not be resolved")
        return None
def ping(addr):
    print("[+] Attempting to ping server...")
    time.sleep(1)
    icmp = scapy.IP(dst=addr) / scapy.ICMP()
    rsp = scapy.sr1(icmp, timeout=0.1)
    if rsp == None:
        print("[!] No response from server. The target may not be reachable.")
    else:
        print("[*] Server responded. The target is alive.")

def scan_ports(addr):
    print("[+] Scanning ports")
    print("[+] Powered by nmap")
    time.sleep(1)
    pscan = subprocess.call(["nmap", "-oX" , "scan.xml" , "-Pn" , "-sT" , "-vvv" , addr])
def loadScannedPorts(xmlfile):
    # xml sucks
    portProtocols = []
    portNums = []
    portStates = []
    # get all nmap attributes we need
    tree = ET.parse(xmlfile)
    root = tree.getroot()
    ports = root.findall(".//port")
    for port in ports:
        portProtocols.append(port.attrib["protocol"])
        portNums.append(port.attrib["portid"])
        state = port.find("state")
        portStates.append(state.attrib["state"])
        # what...
        l.append(f" - {port.attrib["protocol"].upper()} port {port.attrib["portid"]}: {state.attrib['state']}. Nmap service name: {port.find("service").attrib['name']}")
        p.append(port.attrib["portid"])
def writeToMd():
    m_lines = l
    with open("doc.md", "w") as f:
        for line in m_lines:
            f.write(line + "\n")

def checkIfWebserver(addr):
    #print("\nPlease consult the following nmap results, and use ReconSuite's current findings to determine whether a potential web server exists. If it does exist, enter 'y'. Otherwise, enter 'n'.")
    #choice = input("[$] Does a web server exist?: ")
    #if choice.lower() == "y":
    #    return True
    #else:
    #    return False
    print("[+] Checking if web server exists")
    time.sleep(1)
    try:
        r = requests.get(f"https://{addr}", timeout=3)
        print(f"[*] HTTPS server detected ({r.status_code})")
        isHttps = True
        return
    except requests.RequestException:
        print("[!] Not HTTPS")
    try:
        r = requests.get(f"http://{addr}", timeout=3)
        print(f"[*] HTTP server detected ({r.status_code})")
        isHttps = False
        return
    except requests.RequestException:
        print("[!] Not HTTP or unreachable")
        return

def checkIfCMS(addr):
    print("[+] Checking if CMS exists")
    print("[+] Powered by CMSeeK v.1.1.3")
    time.sleep(1)
    x=""
    cmscan = subprocess.call(["python3", "cmsdetection/cmseek.py", "-u", f"{addr}"])
    if os.path.exists(f"cmsdetection/Result/{addr}/cms.json"):
        with open(f"cmsdetection/Result/{addr}/cms.json", "r") as f:
            data = json.load(f)
        cms_name = data["cms_name"]

        if (cms_name != ""):
            l.append("## CMS")
            l.append(f"- {cms_name}")
            l.append(" ")
    else:
        print("[!] Could not get CMS details")

def checkForSubdomains(addr):
    print("[+] Enumerating subdomains")
    print("[+] Powered by subfinder v2.14.0")
    time.sleep(1)
    subfinder = "./sub/subfinder"
    with open("subs.txt", "w") as f:
        subprocess.run([f"{subfinder}", "-d", addr, "-json"], stdout=f)
    subdomains = []
    l.append("## Subdomains")
    with open("subs.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line:  # Skip empty lines if any
                data = json.loads(line)
                subdomains.append(data["host"])
                l.append(f"- {data["host"]}")
    l.append(" ")

def normalize_url(target):
    parsed = urlparse(target)

    if parsed.scheme:
        return target

    if isHttps:
        return f"https://{target}"
    else:
        return f"http://{target}"
def get_hostname(target):
    parsed = urlparse(target)
    if parsed.hostname:
        return parsed.hostname
def get_dnsinfo(target):
    print("[+] Enumerating DNS")
    print("[+] Powered by DiG")
    time.sleep(1)
    with open("dns.txt", "w") as f:
        subprocess.run(["sh", "./dig.sh"], stdout=f)

print("ReconSuite 1.0\n")
print("By Wil Jankovic\n")
print("Disclaimer: This is only to be used in controlled, authorized environments, or for educational purposes.\n")
print("----------------------------------------------------------------------------------------------------------")
if os.geteuid() != 0:
    print("[-] Please run this script as root")
    quit(1)
ip = input("[$] Enter IP/URL: ")
l.append("# Recon Report")
l.append(" ")
address = resolve_ip(ip)
l.append("## Target")
l.append(f"- IP: {address}")
l.append(" ")
ping(address)
scan_ports(address)
l.append("## Nmap results")
l.append(" ")
loadScannedPorts("scan.xml")
checkIfWebserver(address)
checkIfCMS(get_hostname(normalize_url(ip)))
checkForSubdomains(get_hostname(normalize_url(ip)))
get_dnsinfo(normalize_url(ip))
writeToMd()