# Rsync `PORT 873`

Banner & Manual communication

```powershell
nc -vn 127.0.0.1 873
(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0        <--- You receive this banner with the version from the server
@RSYNCD: 31.0        <--- Then you send the same info
#list                <--- Then you ask the sever to list
raidroot             <--- The server starts enumerating
USBCopy        	
NAS_Public     	
_NAS_Recycle_TOSRAID	<--- Enumeration finished
@RSYNCD: EXIT         <--- Sever closes the connection


#Now lets try to enumerate "raidroot"
nc -vn 127.0.0.1 873
(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
raidroot
@RSYNCD: AUTHREQD 7H6CqsHCPG06kRiFkKwD8g    <--- This means you need the password
``` 

![](Pasted%20image%2020241023141239.png)
###  **Enumerating Shared Folders**
### Manual Rsync Usage

Upon obtaining a **module list**, actions depend on whether authentication is needed. Without authentication, **listing** and **copying** files from a shared folder to a local directory is achieved through:

```
# Listing a shared folder
rsync -av --list-only rsync://192.168.0.123/shared_name


# Copying files from a shared folder
rsync -av rsync://192.168.0.123:8730/<shared_name> ./rsyn_shared
```
With **credentials**,
```
rsync -av --list-only rsync://username@192.168.0.123/shared_name

rsync -av rsync://username@192.168.0.123:8730/shared_name ./rsyn_shared
```
Scripts
```
nmap -sV --script "rsync-list-modules" -p <PORT> <IP>
msf> use auxiliary/scanner/rsync/modules_list

# Example with IPv6 and alternate port
rsync -av --list-only rsync://[dead:beef::250:56ff:feb9:e90a]:8730
```

----------------
## Transfer Files with RSYNC and SSH
If Rsync is configured to use SSH to transfer files, we could modify our commands to include the `-e ssh` flag, or `-e "ssh -p2222"` if a non-standard port is in use for SSH.
guide: [Use SSH to Connect to a remote Server](https://phoenixnap.com/kb/ssh-to-connect-to-remote-server-linux-or-windows) first
https://phoenixnap.com/kb/how-to-rsync-over-ssh