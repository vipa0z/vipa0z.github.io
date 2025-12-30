# Firewall and IDS Evasion

Bypass firewall rules and evade intrusion detection/prevention systems during port scanning and reconnaissance.
These techniques help identify filtered ports, understand firewall behavior, and conduct stealthy scans without triggering security alerts.

## Quick Reference

```bash
# Fragment packets to bypass simple firewalls
sudo nmap -f 10.10.10.10

# Decoy scan to hide among fake IPs
sudo nmap -D RND:10 10.10.10.10

# Source port manipulation (trusted port)
sudo nmap --source-port 53 10.10.10.10

# Comprehensive stealth scan
sudo nmap -Pn --disable-arp-ping -n -D RND:10 -sV -p- --source-port 53 --dns-servers 10.10.10.10 10.10.10.10
```

## Detecting Firewalls

```bash
# Compare known open port vs filtered port
sudo nmap -p 80 --packet-trace -Pn -n --disable-arp-ping 10.10.10.10
sudo nmap -p 8080 --packet-trace -Pn -n --disable-arp-ping 10.10.10.10

# Use --reason flag to understand port states
sudo nmap --reason -p 1-1000 10.10.10.10

# Debugging with packet trace
sudo nmap --packet-trace -p 80,443 10.10.10.10
```

## Packet Fragmentation

```bash
# Fragment packets (8-byte fragments)
sudo nmap -f 10.10.10.10

# Custom MTU size
sudo nmap --mtu 16 10.10.10.10
sudo nmap --mtu 24 10.10.10.10

# Fragment with specific scan type
sudo nmap -f -sS -p- 10.10.10.10
```

## Decoy Scanning

```bash
# Random decoys (hide among fake IPs)
sudo nmap -D RND:5 10.10.10.10
sudo nmap -D RND:10 10.10.10.10

# Specific decoy IPs
sudo nmap -D 192.168.1.5,192.168.1.6,ME,192.168.1.8 10.10.10.10

# Decoy with service detection
sudo nmap -D RND:10 -sV -p 80,443 10.10.10.10
```

## Source IP Spoofing

```bash
# Spoof source IP address
sudo nmap -S 192.168.1.5 -e eth0 10.10.10.10

# Spoof with specific interface
sudo nmap -S 10.129.2.200 -e tun0 -Pn -p 445 10.129.2.28

# Combine with other evasion techniques
sudo nmap -S 192.168.1.5 -e eth0 -D RND:5 10.10.10.10
```

## Source Port Manipulation

```bash
# Use trusted source port (DNS - 53)
sudo nmap --source-port 53 10.10.10.10

# Alternative syntax
sudo nmap -g 53 10.10.10.10

# HTTP source port (80)
sudo nmap --source-port 80 10.10.10.10

# HTTPS source port (443)
sudo nmap --source-port 443 10.10.10.10

# Combine with full port scan
sudo nmap --source-port 53 -p- 10.10.10.10
```

## DNS Manipulation

```bash
# Specify custom DNS server
sudo nmap --dns-servers 8.8.8.8 10.10.10.10

# Use target's DNS server (abuse trust)
sudo nmap --dns-servers 10.10.10.10 10.10.10.10

# Disable DNS resolution
sudo nmap -n 10.10.10.10
```

## Timing and Rate Control

```bash
# Paranoid timing (slowest, maximum stealth)
sudo nmap -T0 10.10.10.10

# Sneaky timing
sudo nmap -T1 10.10.10.10

# Polite timing (less bandwidth)
sudo nmap -T2 10.10.10.10

# Custom scan delay
sudo nmap --scan-delay 5s 10.10.10.10
sudo nmap --scan-delay 1s 10.10.10.10

# Maximum scan delay
sudo nmap --max-scan-delay 10s 10.10.10.10

# Rate limiting
sudo nmap --max-rate 100 10.10.10.10
sudo nmap --min-rate 50 --max-rate 100 10.10.10.10
```

## Alternative Scan Types

```bash
# TCP connect scan (less stealthy but works without root)
nmap -sT 10.10.10.10

# TCP ACK scan (firewall rule detection)
sudo nmap -sA 10.10.10.10

# NULL scan (no flags set)
sudo nmap -sN 10.10.10.10

# FIN scan (FIN flag only)
sudo nmap -sF 10.10.10.10

# Xmas scan (FIN, PSH, URG flags)
sudo nmap -sX 10.10.10.10

# UDP scan (often less filtered)
sudo nmap -sU --top-ports 100 10.10.10.10
```

## Idle/Zombie Scan

```bash
# Find potential zombie host
nmap -O -v 192.168.1.0/24 | grep "IP ID Sequence Generation: Incremental"

# Perform idle scan
sudo nmap -sI 192.168.1.5 10.10.10.10

# Idle scan with specific ports
sudo nmap -sI 192.168.1.5 -p 80,443 10.10.10.10
```

## FTP Bounce Scan

```bash
# Exploit FTP server to scan target
sudo nmap -b ftp-server.com 10.10.10.10

# FTP bounce with specific ports
sudo nmap -p 22,25,135 -Pn -v -b 192.168.1.2 10.10.10.10
```

## MAC Address Spoofing

```bash
# Spoof specific MAC address
sudo nmap --spoof-mac 00:11:22:33:44:55 10.10.10.10

# Random MAC address
sudo nmap --spoof-mac 0 10.10.10.10

# Vendor-specific MAC (Apple)
sudo nmap --spoof-mac Apple 10.10.10.10

# Vendor-specific MAC (Dell)
sudo nmap --spoof-mac Dell 10.10.10.10
```

## Data Padding

```bash
# Append random data to packets
sudo nmap --data-length 25 10.10.10.10
sudo nmap --data-length 50 10.10.10.10

# Combine with other evasion
sudo nmap --data-length 25 -f 10.10.10.10
```

## Badsum Technique

```bash
# Send packets with bad checksums (firewall detection)
sudo nmap --badsum 10.10.10.10
```

## NSE Firewall Evasion Scripts

```bash
# Firewall bypass script
nmap --script firewall-bypass 10.10.10.10

# HTTP firewall bypass
nmap -p 80 --script http-methods,http-headers 10.10.10.10

# FTP bounce attack
nmap --script ftp-bounce 10.10.10.10

# Detect packet filtering
nmap --script firewalk 10.10.10.10
```

## Comprehensive Evasion Examples

```bash
# Maximum stealth scan
sudo nmap -sS -Pn -f -D RND:10 --source-port 53 -T2 --scan-delay 2s -p- 10.10.10.10

# Firewall detection and evasion
sudo nmap -Pn --disable-arp-ping -n -D RND:10 -sV -p- --source-port 53 -vv --dns-servers 10.10.10.10 10.10.10.10

# IDS evasion with fragmentation
sudo nmap -f --mtu 16 -D RND:5 -T1 --scan-delay 5s -p 80,443 10.10.10.10

# Trusted source port with decoys
sudo nmap --source-port 53 -D RND:10 -sS -Pn -n -p- 10.10.10.10

# UDP scan with evasion
sudo nmap -sU --source-port 53 -T2 --max-retries 1 --top-ports 100 10.10.10.10
```

## IPv6 Scanning

```bash
# IPv6 scan (often less filtered)
nmap -6 fe80::1

# IPv6 with evasion
nmap -6 -sS -Pn fe80::1
```

## Debugging and Analysis

```bash
# Packet trace (see all packets)
sudo nmap --packet-trace -p 80 10.10.10.10

# Show reason for port state
sudo nmap --reason -p 1-1000 10.10.10.10

# Verbose output
sudo nmap -vv -p 80,443 10.10.10.10

# Debug output
sudo nmap -d -p 80 10.10.10.10
```

## NSE Firewall Detection Scripts

| Script | Type | Technique | Description |
|--------|------|-----------|-------------|
| `firewall-bypass` | Bypass | TCP fragmentation | Sneak through chopped packets |
| `firewalk` | Detection | TTL manipulation | Map firewall rules |
| `ip-id` | Detection | IPID pattern | See if real host replies directly |
| `ipidseq` | Detection | IPID sequence | Check if packet numbers are predictable |
| `traceroute` | Detection | TTL path tracing | See who blocks you along the way |
| `sniffer-detect` | Detection | Promiscuous mode baiting | Detect network sniffers |
| `http-methods` | Detection | HTTP verb probing | Spot HTTP filtering |
| `ftp-bounce` | Bypass | FTP as proxy | Leverage internal scan via FTP |

## Notes

**Understanding Firewall Responses:**

- **Closed Port**: Receives RST (reset) flag response - port is reachable but no service listening
- **Filtered Port**: No response or ICMP unreachable - firewall is blocking the port
- **Open|Filtered**: No response on UDP scan - could be open or filtered
- **Long Delay**: Indicates rate limiting or firewall inspection
- **Fast Rejection with ICMP Error Code 3**: Firewall actively blocking

**Firewall Evasion Strategy:**

1. **Identify Filtering**: Use `--reason` and `--packet-trace` to understand firewall behavior
2. **Test Trusted Ports**: Try source ports 53 (DNS), 80 (HTTP), 443 (HTTPS)
3. **Fragment Packets**: Many firewalls don't reassemble fragments properly
4. **Use Decoys**: Hide your real IP among fake scanning IPs
5. **Slow Down**: Reduce scan speed to avoid rate-limiting and detection
6. **Alternative Protocols**: Try UDP if TCP is heavily filtered

**IDS/IPS Evasion Best Practices:**

- **Use VPS**: Scan from Virtual Private Servers to avoid IP bans
- **Fragment Packets**: Most IDS/IPS don't handle fragmented packets well
- **Decoy Scanning**: Slide your real IP among multiple fake IPs
- **Specify Interface**: Use `-e` to specify which interface to scan from
- **DNS Proxying**: Abuse trust relationships with `--dns-server`
- **Timing Control**: Use `-T0` or `-T1` for maximum stealth

**Source Port Selection:**

Firewalls often trust traffic from certain well-known ports:
- **Port 53 (DNS)**: Most commonly trusted
- **Port 80 (HTTP)**: Web traffic often allowed
- **Port 443 (HTTPS)**: Encrypted web traffic
- **Port 20/21 (FTP)**: File transfer ports
- **Port 25 (SMTP)**: Email traffic

**Scan Type Selection for Evasion:**

- **SYN Scan** (`-sS`): Stealthier than connect scan, requires root
- **ACK Scan** (`-sA`): Useful for mapping firewall rules (stateful vs stateless)
- **NULL/FIN/Xmas** (`-sN/-sF/-sX`): Work on Linux/Unix, bypass some firewalls
- **UDP Scan** (`-sU`): Often less filtered than TCP
- **Idle Scan** (`-sI`): Most stealthy, uses zombie host

**Performance vs Stealth Trade-offs:**

- **Fast Scans**: More likely to trigger IDS/IPS alerts
- **Slow Scans**: Less likely to be detected but take much longer
- **Fragmentation**: Adds overhead but bypasses simple firewalls
- **Decoys**: Increases network traffic but hides your real IP

**Detection Avoidance:**

- Avoid scanning during business hours
- Randomize scan order with `--randomize-hosts`
- Use different source IPs/ports for different scan phases
- Space out scans over time
- Monitor for defensive responses (port closures, IP blocks)

**Legal and Ethical Considerations:**

- Only use evasion techniques on systems you have permission to test
- Document all evasion techniques used in penetration test reports
- Be aware that evasion attempts may be logged and investigated
- Some techniques (IP spoofing, decoys) may impact other systems
