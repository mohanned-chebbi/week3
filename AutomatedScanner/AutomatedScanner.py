import requests,nmap,re
import socket as s
from docx import Document

# Get the ip adress of a domain name

domain = input("Enter domain name: ")
ip = s.gethostbyname(domain)
printdomain=(f'the ip address of {domain} is {ip}')
print(printdomain)

# Check open ports of an IP address

nmScan = nmap.PortScanner()
nmScan.scan(ip)

for host in nmScan.all_hosts():
    for proto in nmScan[host].all_protocols():
        lport = nmScan[host][proto].keys()
        for port in lport:
            openPorts=('Open Port: '+str(port)+'/'+proto.upper()+' - Service: '+nmScan[host][proto][port]['name']+'\n')
print(openPorts)

# List the related CVE to web server

res=nmScan.scan(hosts=ip,arguments="-sV --script=vuln ",ports=openPorts)
cvee=re.compile(r'(CVE-(\d)*-(\d)*)').findall(str(res))
print(cvee)

# List the domain sub-domains

file = open('subdomains_name.txt', 'r')
content = file.read()
subdomainsNames = content.splitlines()
for subdomain  in  subdomainsNames:
    url1 = f"http://{subdomain}.{domain}"
    url2 = f"https://{subdomain}.{domain}"
    try:
        requests.get(url1)
        URL1=(f'[+] {url1}')
        requests.get(url2)
        URL2=(f'[+] {url2}')
    except requests.ConnectionError:
        pass

# Generate a detailed report as Docx that contains all the previous steps

document = Document()
document.add_heading('Scan Repor', 0)

p = document.add_paragraph(printdomain)
p = document.add_paragraph(openPorts)
p = document.add_paragraph(cvee)
p = document.add_paragraph(URL1)
p = document.add_paragraph(URL2)

document.add_page_break()
document.save('AutomatedScanner.docx')
