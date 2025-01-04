<div align="center"><h1> Enumeration </h1></div>


## Passive Information Gathering

<details>
<summary>whois</summary></br>

Tool :
```bash
whois megacorpone.com -h 192.168.50.251          # -h (local whois server if exist)
whois 185.188.105.11 

```

Webistes :
```bash
https://who.is/
https://whois.domaintools.com/
https://viewdns.info/
https://lookup.icann.org/en
https://www.statscrop.com/www/iidic.com
https://website.informer.com/
```

</details>

<details>
<summary>Google Hacking</summary></br>

Query Examples :
```bash
site:megacorpone.com filetype:txt
site:megacorpone.com -filetype:html           (exclude html files)
site:digikala.com ext:xml                                           (find xml pages) (xml-py-php-html)
site:iidic.com intext:حقوق
intitle:iidic "user"                                                        (find pages with iidic in title and "user" on the page content)
site:*.com intitle:"index of" "parent directory"     (misconfigure to find parent directory in index)
site: gov.* intitle:"index.of" *.csv password
inurl:admin filetype:xlsx site:gov.* password
inurl:pastebin "SHODAN_API_KEY"
site:edu intext:"index of" "payroll" filetype:xlsx
```

Query Sources :
```bash
https://www.exploit-db.com/google-hacking-database
![image](https://github.com/user-attachments/assets/d75c21a5-39f4-4021-8c4b-2a8ad036be80)
```
</details>

<details>
<summary>GitHub</summary></br>

Query Example :
```bash
owner:megacorpone path:user                  (find any files with "user" in the filename)

Search syntax:
https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax
```

Tool :
```bash
https://github.com/gitleaks/gitleaks
```
</details>

<details>
<summary>Shodan</summary></br>

Query Example :
```bash
port:3389 country:ir has_Screenshot:true                      
title:"+tm01" has_Screenshot:true          #(+tm01 = a model of camera)
net:10.8.12.0/24 http.favicon.hash:1768726119
http.html:"wp-config .php"
Html:"hacked by" country:ir
```

</details>

<details>
<summary>Censys</summary></br>

Query Example :
```bash
services.http.response.body:nooranet
services.http.response.headers.x_powered_by : php/8
location.country_code: IR and services.service_name: {"FTP", "Telnet"}
location.country_code: IR and services.port: {9200}
```

</details>

<details>
<summary>Useful Websites</summary></br>

Technology Found :
```bash
https://builtwith.com/
https://www.wappalyzer.com/
```

SSL Check :
```bash
https://www.ssllabs.com/ssltest/
https://www.cdn77.com/tls-test
```

DNS and Domain :
```bash
https://searchdns.netcraft.com/?url=http://mci.ir
https://passivedns.mnemonic.no/
https://dnshistory.org/dns-records/iidic.com
https://viewdns.info/
https://dnsdumpster.com/
https://www.nslookup.io/
http://www.kloth.net/services/nslookup.php
```

IP and Geo :
```bash
https://www.liveipmap.com/
https://www.iptrackeronline.com/
https://www.infobyip.com/
https://www.ipfingerprints.com/
```

Subdomain :
```bash
https://crt.sh/
https://shadowcrypt.net/tools/subdomain
https://www.virustotal.com/gui/home/search
```

Genral Info :
```bash
https://sitereport.netcraft.com/
https://dorksearch.com/
https://www.yougetsignal.com/
https://web.archive.org/
https://securitytrails.com/
https://website.informer.com/
```

</details>


## Active Information Gathering

<details>
<summary>DNS Enumeration</summary></br>

Host:
```bash
host digikala.com
Host 192.168.200.10
Host -a digikala.com
host -t txt digikala.com
host -t ns digikala.com
Host -t SOA digikala.com
host -t CNAME digikala.com
Host -t PTR digikala.com
host -t mx digikala.com
```

Nslookup:
```bash
nslookup mail.megacorptwo.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
nslookup -query=A example.com
nslookup -query=MX example.com
nslookup -query=NS example.com
nslookup -query=TXT example.com
nslookup -query=SOA example.com
nslookup -query=CNAME sub.example.com
nslookup -query=ANY example.com
```

Tools:
```bash
#DNSRECON:

dnsrecon -d digikala.com -t std
dnsrecon -d digikala.com -D ~/list.txt  -t brt            #(-t brt = bruteforce , -D = disctionary , -t std = standard)


#DNSENUM:

dnsenum digikala.com

```

</details>

<details>
<summary>Subdomain Enumeration</summary></br>

Host Command:
```bash
# 1 line
for domain in $(cat list.dic);do host $domain.megacorpone.com;done | grep -v "not found"

# python code

#!/bin/bash
Read -p "dic ro bede: " dic
Read -p "esm domain ra benevis" dom
for domain in $(cat $dic);do host $domain.$dom;done | grep -v "not found"
```

Nslookup Command:
```bash
Get-Content subdomains.txt | ForEach-Object { nslookup "$_.example.com" }
```

Reverse Lookup Zone:
```bash
for ip in $(seq 155 192);do host 50.7.67.$ip;done | grep -v "not found"
```
</details>


<details>
<summary>Port Scan</summary></br>

NC:
```bash
#TCP:

nc -nvv -w 1 -z 192.168.50.152 3388-3390            #(-n = not toresolve hostnames and ports to names , -w 1 = set timeout on 1sec , -z = dny the send recive data and just check opening)

#UDP:

nc -nv -u -z -w 1 192.168.50.149 120-123            #(-u = UDP)
```

Windows:
```bash
Test-NetConnection -Port 445 192.168.50.151

#Auto:
foreach ($port in 1..1024) {if (($a=Test-NetConnection 192.168.87.131 -Port $port -WarningAction SilentlyContinue).tcptestsucceeded -eq $true){ "TCP port $port is Open"}}

```

Rustscan:
```bash
#installation:
https://github.com/RustScan/RustScan/releases

	1- Download .deb
	2- dpkg -i rustscan_2.3.0_amd64.deb


#Usage:
rustscan -a www.google.com, 127.0.0.1

https://github.com/RustScan/RustScan/wiki/Things-you-may-want-to-do-with-RustScan-but-don't-understand-how
```

</details>



<details>
<summary>SMB Enumeration</summary></br>

SMB Enumeration (Linux):
```bash
#Port 139 UDP
#Port 445 TCP

nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254


$NMAP NSE for SMB path:
ls -l /usr/share/nmap/scripts/smb*

Example:
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
```


SMB Enumeration (Windows):
```bash
#Find netbios name in domain 
sudo nbtscan -r 192.168.50.0/24

#then
net view \\dc01 /all
```

enum4linux:
```bash
enum4linux $ip
```
</details>


<details>
<summary>SMTP Enumeration</summary></br>

SMTP Enumeration (Linux):
```bash
#port 25
#Use NC OR telnet to make session , Then ask about existing emails with VRFY

nc -nv 192.168.50.8 25
VRFY root


#Python Code for Automation Email Fuzzing:
#	Usage:  python3 smtp.py root 192.168.50.8


	#!/usr/bin/python
	import socket
import sys
	if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)
	# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))
	# Receive the banner
banner = s.recv(1024)
	print(banner)
	# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)
	print(result)
	# Close the socket
s.close()
```

SMTP Enumeration (Windows):
```bash
#Check the OPEN SMTP port:

Test-NetConnection -Port 25 192.168.50.8

#Install and use telnet to make session in windows:
#dism /online /Enable-Feature /FeatureName:TelnetClient

telnet 192.168.50.8 25

```
</details>

<details>
<summary>SMB Enumeration</summary></br>

SMB Enumeration (Discover):
```bash
#Port 161 UDP

# find SNMP with Nmap OR onesixtyone:

sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt

onesixtyone 192.168.1.0/24 public       #(Default Community string = Public)
onesixtyone -c Desktop/wordlist-common-snmp-community-strings.txt 192.168.201.0/24      #(dic for community)

```

SMB Enumeration (Discover):
```bash
#show all data like , process , interfaces, softwares, windows users …
snmpwalk -c public -v1 -t 10 192.168.201.151 -Oa

#Also you can read just a part of data:  (-c public = community string , -Oa =  conver hex to ASCII)

#Windows users
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25

#Running Process:
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2

#Installed softwares:
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2

#Open tcp ports:
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3

#Interfaces Names:
snmpwalk -c public -v1 192.168.201.151 1.3.6.1.2.1.2.2.1 -Oa

```
</details>



## NMAP

<details>
<summary>NMAP Basics</summary></br>

Switches :

| Nmap Flag              | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `-sV`                  | Attempts to determine the version of the services running                    |
| `-p <x>` or `-p-`      | Port scan for port `<x>` or scan all ports                                   |
| `-Pn`                  | Disable host discovery and scan for open ports                               |
| `--top-ports=20`       | Top 20 ports in file (`/usr/share/nmap/nmap-services`)                       |
| `-sn`                  | Enable host discovery (`-sn 192.168.1.1-254`)                               |
| `-p-`                  | Find open ports                                                             |
| `-A`                   | Enables OS and version detection, executes in-build scripts for further enumeration |
| `-sC`                  | Scan with the default Nmap scripts                                          |
| `-v`                   | Verbose mode                                                                |
| `-sU`                  | UDP port scan                                                               |
| `-sS`                  | TCP SYN port scan                                                           |
| `-O`                   | OS Version Detection (fingerprinting)                                       |
| `--osscan-guess`       | Guess the OS if unsure (`-O 192.168.1.1 --osscan-guess`)                    |
| `-oG`                  | Save result of Nmap in a file (`-oG result.txt`)                             |
| `-sT`                  | Full TCP Connect Scan (needed in certain proxy setups)                      |
| `--script vuln`        | Check vulnerability scripts                                                 |
| `--osscan-guess`       | Guess the OS if unsure (`-O 192.168.1.1 --osscan-guess`)                    |


Examples:
```bash
Nmap -Pn -sV -sC --script vuln 10.10.0.73.76
nmap -p 80 192.168.50.1-253 -oG web-sweep.txt
nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt
nmap -O 192.168.50.14 --osscan-guess
nmap -sT -A 192.168.50.14
```
</details>

<details>
<summary>NMAP Advance</summary></br>

Decoy :
```bash
#Decoy = send packet from other source ip

nmap -D 9.9.9.9,1.1.1.1 192.168.1.99
```

Fragmentation :
```bash
nmap -f 192.168.1.2
```
</details>

<details>
<summary>NMAP NSE</summary></br>

NSE Detatils :
```bash
#NSE path:
https://nmap.org/nsedoc/scripts/
/usr/share/nmap/scripts

#finde NSE in kali:
locate *.nse
locate *.nse | grep ftp

#Add NSE to Path:
#search google like "cve-2021-41773 nse" Download NSE and copy to main path (/usr/share/nmap/scripts)
```

Important Scripts :
```bash
-sC                                                          # Default scripts
--script vuln                                                # check vuln scripts , example: nmap -sV -p 443 --script "vuln" 192.168.1.1
-p 445 --script=smb-enum-shares.nse,smb-enum-users.nse       # smb scripts
nmap --script http-headers 192.168.50.6                      # gather http headers
nmap -T 5 --script http-title 192.168.149.1/24               # show title in http web pages
nmap -sV -p 443 --script "vuln" 192.168.1.1
Nmap -sV -p 443 --script "cve-2021-41773" 192.168.1.1        # choose specific NSE
nmap -v -p 21 --script ftp-anon 132.65.116.10-17             # check anonymous user for ftp
Nmap -p80 --script=http-enum 192.168.1.1                     # web service finger prints     
nmap -v -p 1433 --script ms-sql-info 114.143.55.154-160      # ms sql information
```
</details>



## Active Directory

<details>
<summary>Domain Info</summary></br>

net Command (CMD):
```bash
# if you have access to a Domain system use this commands in CMD
net user /domain                    #(show all domain users)
net user <username> /domain         #(show all info about selected user)
net group /domain                   #(show all domain groups)
net group "Tier 1 Admins" /domain   #(show all info about selected group)
net accounts /domain                #(show info about password policy)
```

Get-ADUser (PowerShell):
```
# if you have access to a Domain system use this commands in PowerShell

Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *         #(show all info about the selected user in the domain)
Get-ADGroup -Identity "Tier 2 Admins" -Server za.tryhackme.com -Properties *       #(show all info about selected group)
Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com                #(show all memebers of selected group)
Get-ADDomain -Server za.tryhackme.com                                              #(show all info about the Domain)

```

RSAT:
```
# if you have Graphical access to a domain system install RSAT on it and then use MMC to connect  (there is chance that your user has acces to do that)


install:
Press Start
Search "Apps & Features" and press enter
Click Manage Optional Features
Click Add a feature
Search for "RSAT"
Select "RSAT: Active Directory Domain Services and Lightweight Directory Tools" and click Install

------------------------------------------------------------------------------------------------

RUN:
In MMC, we can now attach the AD RSAT Snap-In:

Click File -> Add/Remove Snap-in
Select and Add all three Active Directory Snap-ins
Click through any errors and warnings
Right-click on Active Directory Domains and Trusts and select Change Forest
Enter za.tryhackme.com as the Root domain and Click OK
Right-click on Active Directory Sites and Services and select Change Forest
Enter za.tryhackme.com as the Root domain and Click OK
Right-click on Active Directory Users and Computers and select Change Domain
Enter za.tryhackme.com as the Domain and Click OK
Right-click on Active Directory Users and Computers in the left-hand pane
Click on View -> Advanced Features

```

BloodHound :
```bash
# search in your documents for info about install and run bloodhound
```

</details>

## Web Application

<details>
<summary>Finding Subdomains</summary></br>

Assetfinder :
```bash
# https://github.com/tomnomnom/assetfinder
assetfinder [--subs-only] <domain>
```

Amass :
```bash
# https://github.com/owasp-amass/amass
amass enum -d tesla.com
```

</details>

<details>
<summary>Checking Live Subdomains</summary></br>

Httprobe :
```bash
# https://github.com/tomnomnom/httprobe
cat recon/example/domains.txt | httprobe
cat recon/example/domains.txt| sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> livedomains.txt
```
    
</details>

<details>
<summary>Automating</summary></br>

Find Live Subdomains :
```bash
# https://github.com/Gr1mmie/sumrecon/blob/master/sumrecon.sh
```
    
</details>
