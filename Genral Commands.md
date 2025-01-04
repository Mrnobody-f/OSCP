<div align="center"><h1> Linux Commands </h1></div>



<details>
<summary>FTP</summary></br>

```bash
ftp -p 10.129.42.253
```
</details>



<details>
<summary>SSH</summary></br>

```bash
ssh Bob@10.10.10.10
```
</details>


<details>
<summary>Locate</summary></br>

```bash
locate scripts/citrix
locate *.nse | grep ftp

```
</details>


<details>
<summary>find</summary></br>

```bash
find /path/to/search -name "filename.txt"
find /path/to/search -name "*.txt"   # Find all .txt files
find /path/to/search -mtime -7   # Files modified in the last 7 days
```
</details>


<details>
<summary>Netcat (NC)</summary></br>

```bash
nc -lvp 192.168.1.1 8080      #listen on this port
nc 127.0.0.1 1234             #send request to ip and port
```
</details>


<details>
<summary>SMB</summary></br>

smbclient:
```bash
smbclient -L //10.10.235.61/                                     # Gather Info and Data
smbclient //$ip/Anonymous                                        # (/Anonymous = Folder shared by 10.10.181.239)
smbclient -U milesdyson //10.10.181.239/milesdyson               # (-U milesdyson = User)
smbclient -N -L //10.129.42.253                                  # (-N = use Anonymous use if exist {also you can use just -U Anonymous} , -L = List of shares)
```
</details>

<div align="center"><h1> Windows Commands </h1></div>
