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
site:edu intext:"index of"" "payroll" filetype:xlsx
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
 Get-ADDomain -Server za.tryhackme.com                                             #(show all info about the Domain)

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
