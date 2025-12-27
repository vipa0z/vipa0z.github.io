This section focuses on  Firewall and IPS Detection & Evasion

# Firewalls
------------
### Detecting Firewalls

- Closed port: RST flag response
- Filtered port: Challenging to determine if closed or not
- Long delay in response or fast rejection with error code 3 indicates firewall

### Firewall Evasion Techniques
- Connect Scan: `-sT`
- ACK Scan: `-sA`
- Fragmentation: `-f` or `--mtu`
- Decoy Scanning: `-D RND:5`


## NSE bypass/detection scripts

| Script               | Type     | Technique                                | Simple Description                        |
|----------------------|----------|------------------------------------------|--------------------------------------------|
| `firewall-bypass`    | Bypass   | TCP fragmentation                        | Sneak through chopped packets              |
| `ip-id`              | Detection| IPID pattern                             | See if the real host replies directly      |
| `ipidseq`            | Detection| IPID sequence                            | Check if packet numbers are predictable    |
| `traceroute`         | Detection| TTL path tracing                         | See who blocks you along the way           |
| `sniffer-detect`     | Detection| Promiscuous mode baiting                 | Detect network sniffers                    |
| `http-methods`       | Detection| HTTP verb probing                        | Spot HTTP filtering                        |
| `ftp-bounce`         | Bypass   | FTP as proxy                             | Leverage internal scan via FTP             |
| `bypass-firewalls`   | Bypass   | Packet evasion                           | Confuse the firewall                       |
| `packet-tracer`      | Detection| Packet fingerprinting                    | Watch how the target handles odd packets   |



### UDP Port Scans
- Some admins forget to filter UDP ports
- use -`sU`  and combine with source port manipulation

### Source Port Manipulation
```bash
--source-port 53
```


1. Fragment packets (-f or --mtu):
   ```
   nmap -f  --mtu 8 <target>
   ```

2. Use decoys (-D):
   ```
   nmap -D RND:10 <target>
   ```

3. Spoof source IP address (-S):
   ```
   nmap -S <spoofed_ip> <target>
   ```

4. Use a specific source port (--source-port):
Sometimes if services run on the same port you are scanning, It may bypass firewall.
   ```
   nmap --source-port 53 <target>
   ```

5. Slow down the scan (-T<0-5>):
   ```
   nmap -T2 <target>
   ```

6. Use TCP connect scan (-sT):
   ```
   nmap -sT <target>
   ```

7. Perform UDP scans (-sU):
   ```
   nmap -sU <target>
   ```

8. Use uncommon TCP flag combinations:
   ```
   nmap -sN <target>  # NULL scan
   nmap -sF <target>  # FIN scan
   nmap -sX <target>  # Xmas scan
   ```

9. Idle scan (-sI):
   ```
   nmap -sI <zombie_host> <target>
   ```

10. Use scripts to manipulate packets:
    Various NSE scripts can be used for this purpose.

## 10. Example Advanced Scan
```bash
sudo nmap 10.129.128.167 -Pn --disable-arp-ping -n -D RND:10 -sV -p- --source-port 53 -vv --dns-servers 10.129.128.167
```
#  Intrusion Prevention Systems (IPs)
-----------------------
- Use Virtual Private servers, useful incase you get IP banned 
- Fragment packets: `-f` or `--mtu`
	Most IPs dont know how to scan fragmented packets
- Decoy scanning: `-D RND:5`
	if you specify multiple fake IPs and slide your IP within them it may bypass detection.
- Specify interface: `-e <interface>` 
	specify Ips to scan from 
- DNS proxying: `--dns-server <ns>,<ns>`
	Scan target using a DNS server, abuses trust between them.
5. Slow down the scan (-T<0-5>):

##  Example 
This scan combines multiple evasion techniques for a stealthy, comprehensive scan.
```bash
sudo nmap 10.129.128.167 -Pn --disable-arp-ping -n -D RND:10 -sV -p- --source-port 53 -vv --dns-servers 10.129.128.167
```

### Detecting Firewalls

- Closed port: RST flag response
- Filtered port: Challenging to determine if closed or not
- Long delay in response or fast rejection with error code 3 indicates firewall

### Firewall Evasion Techniques
- Connect Scan: `-sT`
- ACK Scan: `-sA`
- Fragmentation: `-f` or `--mtu`
- Decoy Scanning: `-D RND:5`

### UDP Port Scans
- Some admins forget to filter UDP ports
- use -`sU`  and combine with source port manipulation

### Source Port Manipulation
```bash
--source-port 53
```


1. Fragment packets (-f or --mtu):
   ```
   nmap -f  --mtu 8 <target>
   ```

2. Use decoys (-D):
   ```
   nmap -D RND:10 <target>
   ```

3. Spoof source IP address (-S):
   ```
   nmap -S <spoofed_ip> <target>
   ```

4. Use a specific source port (--source-port):
Sometimes if services run on the same port you are scanning, It may bypass firewall.
   ```
   nmap --source-port 53 <target>
   ```

5. Slow down the scan (-T<0-5>):
   ```
   nmap -T2 <target>
   ```

6. Use TCP connect scan (-sT):
   ```
   nmap -sT <target>
   ```

7. Perform UDP scans (-sU):
   ```
   nmap -sU <target>
   ```

8. Use uncommon TCP flag combinations:
   ```
   nmap -sN <target>  # NULL scan
   nmap -sF <target>  # FIN scan
   nmap -sX <target>  # Xmas scan
   ```

9. Idle scan (-sI):
   ```
   nmap -sI <zombie_host> <target>
   ```

10. Use scripts to manipulate packets:
    Various NSE scripts can be used for this purpose.

## 10. Example Advanced Scan
```bash
sudo nmap 10.129.128.167 -Pn --disable-arp-ping -n -D RND:10 -sV -p- --source-port 53 -vv --dns-servers 10.129.128.167fping


```

