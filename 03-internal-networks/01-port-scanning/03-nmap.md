# Nmap Port Scanning

Discover open ports and running services on target systems using various scanning techniques and timing options.
This is the first active reconnaissance step after identifying live hosts, providing the foundation for service enumeration and exploitation.

## Quick Reference

```bash
# Fast comprehensive scan (most common)
sudo nmap -sS -p- -T4 --min-rate 1000 -oA scan_results 10.10.10.10

# Service version detection
sudo nmap -sV -sC -p 22,80,443 10.10.10.10

# Full aggressive scan with OS detection
sudo nmap -A -p- -T4 10.10.10.10

# Stealth scan for IDS evasion
sudo nmap -sS -T2 --scan-delay 5s -p- 10.10.10.10
```

## Host Discovery

```bash
# List targets only (no scan)
nmap 192.168.1.1-3 -sL

# Ping scan (disable port scanning)
nmap 192.168.1.1/24 -sn

# Scan network for live hosts
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

# Skip host discovery (assume host is up)
nmap 192.168.1.1-5 -Pn

# TCP SYN discovery on specific ports
nmap 192.168.1.1-5 -PS22-25,80

# TCP ACK discovery
nmap 192.168.1.1-5 -PA22-25,80

# UDP discovery
nmap 192.168.1.1-5 -PU53

# ARP discovery on local network
nmap 192.168.1.0/24 -PR

# Disable DNS resolution
nmap 192.168.1.1 -n

# Disable ARP ping
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
```

## Target Specification

```bash
# Scan specific IPs
nmap 192.168.1.1 192.168.2.1

# Scan a range
nmap 192.168.1.1-254

# Scan a domain
nmap scanme.nmap.org

# Scan using CIDR notation
nmap 192.168.1.0/24

# Scan targets from a file
nmap -iL targets.txt

# Scan random hosts
nmap -iR 100

# Exclude specific hosts
nmap --exclude 192.168.1.1 192.168.1.0/24
```

## Scan Techniques

```bash
# TCP SYN scan (default when run as root)
sudo nmap 192.168.1.1 -sS

# TCP connect scan (default for non-root)
nmap 192.168.1.1 -sT

# UDP port scan
sudo nmap 192.168.1.1 -sU

# TCP ACK scan (firewall detection)
sudo nmap 192.168.1.1 -sA

# TCP Window scan
sudo nmap 192.168.1.1 -sW

# TCP Maimon scan
sudo nmap 192.168.1.1 -sM
```

## Port Specification

```bash
# Scan specific port
nmap 192.168.1.1 -p 21

# Port range
nmap 192.168.1.1 -p 21-100

# Multiple ports and protocols
nmap 192.168.1.1 -p U:53,T:21-25,80

# All 65535 ports
nmap 192.168.1.1 -p-

# Scan by service name
nmap 192.168.1.1 -p http,https

# Fast scan (top 100 ports)
nmap 192.168.1.1 -F

# Scan top N ports
nmap 192.168.1.1 --top-ports 2000

# Show only open ports
sudo nmap 192.168.1.1 --open -sV
```

## Timing and Performance

```bash
# T0 = Paranoid (very slow, IDS evasion)
nmap -T0 10.10.10.10

# T1 = Sneaky (slow)
nmap -T1 10.10.10.10

# T2 = Polite (slower, less bandwidth)
nmap -T2 10.10.10.10

# T3 = Normal (default)
nmap -T3 10.10.10.10

# T4 = Aggressive (faster, good for LANs)
nmap -T4 10.10.10.10

# T5 = Insane (very fast, may be inaccurate)
nmap -T5 10.10.10.10

# Custom timing options
nmap --host-timeout 30m 10.10.10.10
nmap --min-rtt-timeout 50ms --max-rtt-timeout 100ms 10.10.10.10
nmap --min-hostgroup 50 --max-hostgroup 100 10.10.10.10
nmap --min-parallelism 10 --max-parallelism 50 10.10.10.10
nmap --scan-delay 1s --max-scan-delay 5s 10.10.10.10
nmap --max-retries 3 10.10.10.10
nmap --min-rate 1000 --max-rate 5000 10.10.10.10
```

## Service and Version Detection

```bash
# Detect service versions
nmap -sV 192.168.1.1

# Set version detection intensity (0-9)
nmap -sV --version-intensity 5 192.168.1.1

# Light and fast version scan
nmap -sV --version-light 192.168.1.1

# Aggressive version detection
nmap -sV --version-all 192.168.1.1

# Full aggressive scan (OS + version + scripts + traceroute)
nmap -A 192.168.1.1
```

## OS Detection

```bash
# Enable OS detection
nmap -O 192.168.1.1

# Skip OS scan if conditions not met
nmap -O --osscan-limit 192.168.1.1

# Aggressive OS guessing
nmap -O --osscan-guess 192.168.1.1

# Set max OS detection tries
nmap -O --max-os-tries 3 192.168.1.1
```

## Firewall and IDS Evasion

```bash
# Fragment packets
nmap -f 192.168.1.1

# Set custom MTU
nmap --mtu 24 192.168.1.1

# Decoy scan (hide among decoys)
nmap -D RND:10 192.168.1.1

# Spoof source IP
nmap -S 192.168.1.5 192.168.1.1

# Set source port
nmap -g 53 192.168.1.1

# Append random data to packets
nmap --data-length 25 192.168.1.1

# Defeat RST rate limiting
nmap --defeat-rst-ratelimit 192.168.1.1

# Detect forged packets (compare known open vs filtered)
nmap -p 80 --packet-trace -Pn -n --disable-arp-ping 192.168.1.1
```

## NSE Scripts

```bash
# Run default scripts
nmap -sC 192.168.1.1
nmap --script default 192.168.1.1

# Run specific script
nmap --script=banner 192.168.1.1

# Wildcard script matching
nmap --script=http* 192.168.1.1

# Multiple scripts
nmap --script=http,banner 192.168.1.1

# Exclude intrusive scripts
nmap --script "not intrusive" 192.168.1.1

# Update NSE script database
sudo nmap --script-updatedb
```

## Common NSE Script Examples

```bash
# HTTP sitemap generation
nmap -Pn --script=http-sitemap-generator scanme.nmap.org

# Banner grabbing and HTTP titles
nmap -n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000

# DNS brute force
nmap -Pn --script=dns-brute domain.com

# SMB enumeration
nmap -n -Pn -vv -O -sV --script smb-* 192.168.1.1

# WHOIS lookup
nmap --script whois* domain.com

# Vulnerability scanning
nmap --script vuln 192.168.1.1
nmap -sV --script vulners 192.168.1.1
```

## Web Application NSE Scripts

```bash
# HTTP methods enumeration
nmap -p80 --script http-methods --script-args http-methods.test-all http://target

# HTTP headers
nmap -p80 --script http-headers http://target

# Authentication testing
nmap -p80 --script http-auth,http-auth-finder,http-auth-guess http://target

# Directory enumeration
nmap -p80 --script http-enum http://target

# Config backup detection
nmap -p80 --script http-config-backup http://target

# User directory enumeration
nmap -p80 --script http-userdir-enum http://target

# Virtual host discovery
nmap -p80 --script http-vhosts,http-iis-short-name-brute http://target

# XSS and CSRF detection
nmap -p80 --script http-dombased-xss,http-xssed,http-stored-xss,http-csrf 192.168.1.1

# SQL injection detection
nmap -p80 --script http-sql-injection scanme.nmap.org

# Output escaping issues
nmap -p80 --script http-unsafe-output-escaping scanme.nmap.org
```

## Advanced NSE Script Usage

```bash
# FTP brute force with custom wordlists
nmap --script-args "userdb=users.txt,passdb=passlist.txt" -p21 ftp.target.com --script ftp-brute

# SMB enumeration with credentials
nmap -p445 --script smb-enum-users,smb-enum-shares --script-args smbuser=admin,smbpass=password 192.168.1.100

# HTTP form brute force
nmap -p80 --script http-form-brute --script-args http-form-brute.hostname=target.com,http-form-brute.path=/login,http-form-brute.uservar=username,http-form-brute.passvar=password,http-form-brute.failmsg="invalid login" 192.168.1.1

# CVE-specific vulnerability checks
nmap -p80 --script http-vuln-cve2015-1635 192.168.1.1
nmap -p80 --script http-vuln-cve2017-5638 192.168.1.1
nmap -p80 --script http-vuln-cve2017-1001000 192.168.1.1
```

## Output Options

```bash
# Normal output
nmap -oN scan.txt 192.168.1.1

# XML output
nmap -oX scan.xml 192.168.1.1

# Grepable output
nmap -oG scan.gnmap 192.168.1.1

# All formats (creates .nmap, .xml, .gnmap)
nmap -oA scan_results 192.168.1.1

# Append to existing file
nmap --append-output -oN scan.txt 192.168.1.1

# Output to screen
nmap -oG - 192.168.1.1
nmap -oN - 192.168.1.1
nmap -oX - 192.168.1.1

# Convert XML to HTML report
xsltproc scan.xml -o scan.html
```

## Output Analysis and Filtering

```bash
# Show only open ports from grepable output
grep "open" scan.gnmap

# Extract service names from grepable output
egrep -v "^#|Status: Up" scan.gnmap | cut -d ' ' -f4- | tr ',' '\n' | \
sed -e 's/^[ \t]*//' | awk -F '/' '{print $7}' | grep -v "^$" | sort | uniq -c

# Show scan progress during execution
nmap --stats-every=5s 192.168.1.1
```

## Common Workflow Examples

```bash
# Initial fast scan to find open ports
sudo nmap -sS -p- --min-rate 1000 -T4 10.10.10.10 -oA initial_scan

# Detailed scan on discovered ports
sudo nmap -sV -sC -A -p 22,80,443,445,3389 10.10.10.10 -oA detailed_scan

# UDP scan on common ports
sudo nmap -sU --top-ports 20 10.10.10.10 -oA udp_scan

# Stealth scan for IDS evasion
sudo nmap -sS -T2 -f --scan-delay 5s -p- 10.10.10.10 -oA stealth_scan
```

## NSE Script Management

```bash
# Find NSE scripts location
ls /usr/share/nmap/scripts/

# Find all scripts for a specific service
locate -r '\.nse$' | xargs grep categories | grep smb

# Find default/version scripts for a service
locate -r '\.nse$' | xargs grep categories | grep 'default\|version' | grep smb

# Find script by name pattern
find / -type f -name ftp* 2>/dev/null | grep scripts
```

## Notes

**Always run Nmap as root** for full functionality. By default, Nmap scans the top 1000 TCP ports with SYN scan (`-sS`) when run as root. Without root privileges, it falls back to TCP connect scan (`-sT`) which is less stealthy and requires completing the full TCP handshake.

**OS Detection via TTL values:**
- TTL 64: Linux/macOS
- TTL 128: Windows
- TTL 255: Network devices (routers, switches)

**Scan optimization tips:**
- Use `-oA` to save all output formats for later analysis
- Combine `-sV` and `-A` for comprehensive service and OS fingerprinting
- Use `--reason` flag to understand why ports are marked as open/closed/filtered
- Closed ports respond with RST; filtered ports typically don't respond (firewall)
- Reducing scan time helps evade IDS detection
- Increasing speed may trigger security alerts

**Performance considerations:**
- `--min-rate` sets minimum packets per second (faster scans)
- `--max-retries` limits probe retransmissions (faster but less accurate)
- `-T4` is recommended for most LAN scans
- `-T2` or lower for stealth and IDS evasion
- Fragment packets (`-f`) and decoys (`-D`) help evade firewalls

**Additional resources:**
- [StationX Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)
- [Awesome Nmap Grep](https://github.com/leonjza/awesome-nmap-grep)
