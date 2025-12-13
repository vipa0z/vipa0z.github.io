# Passive Network Credential Capture

Monitor network traffic to identify hosts, capture cleartext credentials, and extract authentication hashes from unencrypted protocols.
Passive capture is stealthy and doesn't generate malicious traffic, making it ideal for initial reconnaissance and credential harvesting.

## Quick Reference

```bash
# Wireshark GUI
sudo wireshark

# tcpdump capture to file
sudo tcpdump -i eth0 -w capture.pcap

# Pcredz - extract credentials from pcap
python3 Pcredz.py -f capture.pcap -t -v
```

## Wireshark

```bash
# Start Wireshark with sudo
sudo -E wireshark

# Start capture on specific interface
# File → Capture Options → Select interface → Start

# Common display filters
ip.addr == 10.10.10.10          # Specific IP
tcp.port == 80                   # HTTP traffic
tcp.port == 445                  # SMB traffic
http                             # All HTTP
dns                              # DNS queries
ftp                              # FTP traffic
smtp                             # Email traffic
pop                              # POP3 email
imap                             # IMAP email
ldap                             # LDAP queries
kerberos                         # Kerberos auth
ntlmssp                          # NTLM auth

# Advanced filters
http.request.method == "POST"    # HTTP POST requests
http contains "password"         # HTTP with password string
ftp.request.command == "PASS"    # FTP password commands
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN packets
tcp.stream eq 53                 # Specific TCP stream
eth.addr == 00:11:22:33:44:55   # Specific MAC address
ip.src == 10.10.10.10 && ip.dst == 10.10.10.20  # Between two IPs

# Search for credentials
# Edit → Find Packet
# Search for: "password", "passw", "user", "login", "auth"

# Follow TCP stream
# Right-click packet → Follow → TCP Stream

# Export objects
# File → Export Objects → HTTP/SMB/FTP
```

## tcpdump

```bash
# Basic capture
sudo tcpdump -i eth0

# Capture to file
sudo tcpdump -i eth0 -w capture.pcap

# Capture with verbose output
sudo tcpdump -i eth0 -v

# Capture specific host
sudo tcpdump -i eth0 host 10.10.10.10

# Capture specific port
sudo tcpdump -i eth0 port 80

# Capture HTTP traffic
sudo tcpdump -i eth0 'tcp port 80'

# Capture SMB traffic
sudo tcpdump -i eth0 'tcp port 445'

# Capture FTP traffic
sudo tcpdump -i eth0 'tcp port 21'

# Capture DNS traffic
sudo tcpdump -i eth0 'udp port 53'

# Capture between two hosts
sudo tcpdump -i eth0 'host 10.10.10.10 and host 10.10.10.20'

# Capture and display ASCII
sudo tcpdump -i eth0 -A

# Capture with packet size limit
sudo tcpdump -i eth0 -s 65535 -w capture.pcap

# Rotate capture files (100MB each)
sudo tcpdump -i eth0 -w capture.pcap -C 100

# Capture for specific duration (60 seconds)
sudo tcpdump -i eth0 -w capture.pcap -G 60

# Read from capture file
tcpdump -r capture.pcap

# Filter capture file
tcpdump -r capture.pcap 'tcp port 80'
```

## Pcredz

```bash
# Install Pcredz
git clone https://github.com/lgandx/PCredz
cd PCredz
pip3 install -r requirements.txt

# Extract credentials from pcap
python3 Pcredz.py -f capture.pcap

# Verbose output
python3 Pcredz.py -f capture.pcap -v

# Extract and display in terminal
python3 Pcredz.py -f capture.pcap -t

# Both verbose and terminal
python3 Pcredz.py -f capture.pcap -t -v

# Live capture mode
sudo python3 Pcredz.py -i eth0

# Live capture with verbose
sudo python3 Pcredz.py -i eth0 -v
```

## net-creds

```bash
# Install net-creds
git clone https://github.com/DanMcInerney/net-creds
cd net-creds
pip3 install -r requirements.txt

# Sniff live traffic
sudo python3 net-creds.py -i eth0

# Read from pcap file
python3 net-creds.py -p capture.pcap

# Filter by IP
sudo python3 net-creds.py -i eth0 -f 10.10.10.10
```

## Responder (Analyze Mode)

```bash
# Passive listening (no poisoning)
sudo responder -I eth0 -A

# Analyze mode shows:
# - LLMNR/NBT-NS requests
# - MDNS requests
# - DHCP requests
# - Active hosts
# - Requested resources
```

## Common Workflow

```bash
# Step 1: Start packet capture
sudo tcpdump -i eth0 -w capture.pcap

# Step 2: Let it run (minutes to hours)
# Monitor network activity

# Step 3: Stop capture (Ctrl+C)

# Step 4: Extract credentials
python3 Pcredz.py -f capture.pcap -t -v

# Step 5: Analyze in Wireshark
wireshark capture.pcap

# Step 6: Search for sensitive data
# Filter: http contains "password"
# Filter: ftp.request.command == "PASS"
# Filter: pop.request.command == "PASS"
```

## Wireshark Analysis Techniques

```bash
# Identify hosts
# Statistics → Endpoints → IPv4

# Protocol hierarchy
# Statistics → Protocol Hierarchy

# Conversations
# Statistics → Conversations

# HTTP requests
# Statistics → HTTP → Requests

# Export HTTP objects
# File → Export Objects → HTTP

# Find credentials in HTTP POST
# Filter: http.request.method == "POST"
# Follow TCP stream
# Look for username/password fields

# Find FTP credentials
# Filter: ftp.request.command == "USER" or ftp.request.command == "PASS"

# Find SMTP credentials
# Filter: smtp.req.command == "AUTH"

# Find POP3 credentials
# Filter: pop.request.command == "USER" or pop.request.command == "PASS"

# Find IMAP credentials
# Filter: imap.request contains "LOGIN"

# Find NTLM hashes
# Filter: ntlmssp
# Look for NTLMSSP_AUTH messages
```

## Protocol-Specific Captures

```bash
# HTTP Basic Authentication
# Filter: http.authbasic
# Credentials are base64 encoded
# Decode: echo "dXNlcjpwYXNz" | base64 -d

# FTP credentials
# Filter: ftp.request.command == "USER" or ftp.request.command == "PASS"
# Cleartext in packet

# Telnet credentials
# Filter: telnet
# Follow TCP stream
# Cleartext in stream

# SMTP authentication
# Filter: smtp.req.command == "AUTH"
# May be base64 encoded

# POP3 credentials
# Filter: pop.request.command == "USER" or pop.request.command == "PASS"
# Cleartext in packet

# IMAP credentials
# Filter: imap.request contains "LOGIN"
# Cleartext in packet

# SNMP community strings
# Filter: snmp
# Look for community string field

# LDAP bind credentials
# Filter: ldap.protocolOp == 0
# Simple bind contains cleartext password

# NTLMv2 hashes
# Filter: ntlmssp.auth.ntlmv2response
# Extract challenge and response
```

## Notes

**What Can Be Captured:**

Cleartext protocols:
- HTTP (credentials, cookies, tokens)
- FTP (username, password)
- Telnet (everything)
- SMTP (email credentials)
- POP3 (email credentials)
- IMAP (email credentials)
- LDAP (bind credentials)
- SNMP (community strings)
- DNS (queries, responses)

Authentication hashes:
- NTLMv1/v2 (challenge-response)
- Kerberos (AS-REQ, TGS-REQ)
- NTLM over HTTP
- NTLM over SMB

Other sensitive data:
- Credit card numbers
- Social security numbers
- API keys
- Session tokens
- Cookies
- Form data

**Network Discovery:**

From passive capture, identify:
- Active hosts (IP addresses)
- MAC addresses
- Hostnames (DNS, DHCP, LLMNR)
- Operating systems (TTL, TCP options)
- Services (port numbers)
- Domain names
- Network topology
- Routing information

**ARP Analysis:**

```bash
# Filter: arp
# Shows:
# - IP to MAC mappings
# - Active hosts
# - Potential ARP spoofing
```

**MDNS Analysis:**

```bash
# Filter: mdns
# Shows:
# - Service discovery
# - Hostnames
# - Device types
# - Apple devices
```

**DHCP Analysis:**

```bash
# Filter: dhcp
# Shows:
# - IP assignments
# - Hostnames
# - MAC addresses
# - DHCP server
```

**DNS Analysis:**

```bash
# Filter: dns
# Shows:
# - Domain queries
# - Internal domains
# - External domains
# - DNS servers
```

**Pcredz Capabilities:**

Extracts:
- Credit card numbers
- POP credentials
- SMTP credentials
- IMAP credentials
- SNMP community strings
- FTP credentials
- HTTP Basic/NTLM credentials
- HTTP form data
- NTLMv1/v2 hashes (SMB, HTTP, LDAP, MSSQL)
- Kerberos AS-REQ Pre-Auth (etype 23)

**Wireshark Display Filters:**

Useful filters:
```
http.request                     # All HTTP requests
http.response.code == 200        # Successful responses
http.response.code == 401        # Unauthorized
http.cookie                      # Cookies
http.authorization               # Auth headers
tcp.flags.reset == 1             # RST packets
tcp.analysis.retransmission      # Retransmissions
tcp.analysis.duplicate_ack       # Duplicate ACKs
ip.ttl < 10                      # Low TTL (routing loops)
frame.len > 1000                 # Large packets
```

**Capture Best Practices:**

1. **Positioning**:
   - Capture on network segment with target traffic
   - Use port mirroring/SPAN if possible
   - Position between clients and servers

2. **Duration**:
   - Capture during business hours
   - Longer captures = more data
   - Balance storage vs. coverage

3. **Storage**:
   - Captures can be large (GB/hour)
   - Use rotating captures
   - Compress old captures

4. **Filtering**:
   - Capture everything, filter during analysis
   - Use BPF filters for specific traffic
   - Save filtered results separately

**Legal and Ethical:**

- Only capture with authorization
- Understand privacy implications
- Secure captured data
- Follow data retention policies
- Don't capture personal data unnecessarily
- Document all activities

**Detection Avoidance:**

Passive capture is stealthy:
- No packets sent
- No ARP requests
- No DNS queries
- No connection attempts
- Hard to detect

But consider:
- Promiscuous mode may be detectable
- Physical access may be logged
- Network taps may be visible

**Common Findings:**

Typical discoveries:
- FTP credentials (very common)
- HTTP Basic Auth (common)
- Telnet sessions (rare but valuable)
- SNMP community strings (common)
- NTLMv2 hashes (common in Windows)
- Email credentials (POP3/IMAP)
- Database credentials (MySQL, MSSQL)

**Analysis Workflow:**

1. **Quick scan**:
   - Protocol hierarchy
   - Endpoints
   - Conversations

2. **Credential search**:
   - Run Pcredz
   - Search for "password"
   - Check FTP/HTTP/SMTP

3. **Hash extraction**:
   - Filter for NTLM
   - Filter for Kerberos
   - Extract challenge-response

4. **Sensitive data**:
   - Search for SSN patterns
   - Search for credit cards
   - Check form data

5. **Documentation**:
   - Save findings
   - Screenshot evidence
   - Export relevant packets

**Wireshark Tips:**

- Use coloring rules for quick identification
- Create custom columns for specific fields
- Save frequently used filters
- Use "Follow Stream" for context
- Export specific packets for sharing
- Use "Expert Info" for anomalies

**tcpdump vs Wireshark:**

- **tcpdump**:
  - Command-line
  - Lightweight
  - Good for remote capture
  - Less analysis features

- **Wireshark**:
  - GUI
  - Rich analysis features
  - Better for deep analysis
  - More resource intensive

**Performance Considerations:**

- Large captures slow down Wireshark
- Use display filters, not capture filters
- Close unused protocol dissectors
- Increase memory if needed
- Split large captures into smaller files

**Post-Capture Actions:**

Once credentials found:
1. Verify credentials
2. Test for password reuse
3. Check privilege levels
4. Document findings
5. Attempt lateral movement
6. Continue enumeration

**Common Pitfalls:**

- Capturing on wrong interface
- Not enough disk space
- Missing promiscuous mode
- Filtering too aggressively
- Not saving captures
- Losing capture files
- Not documenting findings

**Advanced Techniques:**

1. **SSL/TLS Decryption**:
   - Requires private key
   - Or SSLKEYLOGFILE
   - Decrypt HTTPS traffic

2. **VoIP Analysis**:
   - Extract phone calls
   - Analyze SIP/RTP
   - Reconstruct audio

3. **Malware Analysis**:
   - Extract malware from traffic
   - Analyze C2 communication
   - Identify IOCs

**Troubleshooting:**

Common issues:
- **No packets captured**: Check interface, permissions
- **Encrypted traffic**: Can't decrypt without keys
- **Missing credentials**: May be encrypted or not present
- **Large files**: Split or filter
- **Slow analysis**: Use filters, close dissectors
