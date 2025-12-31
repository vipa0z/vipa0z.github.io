# Network Sweeps and Host Discovery

Identify live hosts on a network before performing detailed port scans.
This initial reconnaissance phase helps map the network and identify active targets for further enumeration.

## Quick Reference

```bash
# Nmap ping sweep (ICMP + ARP)
sudo nmap -sn 192.168.1.0/24 -oA live_hosts

# Fping for fast ICMP sweep
fping -asgq 172.16.5.0/23

# PowerShell ping sweep with hostnames
1..254 | % {"172.16.5.$($_): $(Test-Connection -Count 1 -ComputerName 172.16.5.$($_) -Quiet)"}
```

## Nmap Host Discovery

```bash
# ICMP echo requests (disable ARP)
sudo nmap -sn -PE --disable-arp-ping 10.129.2.0/24 -oA nmap/hosts | grep for | cut -d" " -f5

# ARP scanning (local network only)
sudo nmap -PR -sn 192.168.1.0/24

# Skip host discovery, assume all hosts are up
sudo nmap -Pn 192.168.1.1-254

# TCP SYN discovery on specific ports
sudo nmap -PS22-25,80,443 -sn 192.168.1.0/24

# TCP ACK discovery
sudo nmap -PA22-25,80,443 -sn 192.168.1.0/24

# UDP discovery
sudo nmap -PU53,161 -sn 192.168.1.0/24

# Disable DNS resolution (faster)
sudo nmap -sn -n 192.168.1.0/24
```

## Fping - Fast ICMP Sweeps

```bash
# Basic ping sweep
fping -asgq 172.16.5.0/23

# Ping sweep with output
fping -a -g 192.168.1.0/24

# Ping specific hosts from file
fping -a -f targets.txt

# Set timeout and retry count
fping -t 500 -r 2 -asgq 10.10.10.0/24
```

## Bash One-Liners

```bash
# Linux/macOS ping sweep
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done

# Extract only IP addresses
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" | cut -d" " -f4 | tr -d ":" &); done
```

## Windows CMD Ping Sweep

```cmd
# Basic ping sweep
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# Save results to file
for /L %i in (1 1 254) do @ping 172.16.5.%i -n 1 -w 100 | find "Reply" >> live_hosts.txt
```

## PowerShell Ping Sweeps

```powershell
# Basic ping sweep (quiet output)
1..254 | % {"172.16.5.$($_): $(Test-Connection -Count 1 -ComputerName 172.16.5.$($_) -Quiet)"}

# Show hostname and IP
1..254 | % {"172.16.210.$($_): $(Test-Connection -Count 1 -ComputerName 172.16.210.$($_) -Quiet)"}

# Filter only responding hosts
1..254 | % {If (Test-Connection -Count 1 -ComputerName 172.16.5.$_ -Quiet) {"172.16.5.$_"}}

# Parallel execution (faster)
1..254 | ForEach-Object -Parallel {
    If (Test-Connection -Count 1 -ComputerName "172.16.5.$_" -Quiet) {
        "172.16.5.$_"
    }
} -ThrottleLimit 50
```

## RustScan Network Sweep

```bash
# Scan entire subnet for open ports
rustscan -a 192.168.1.0/24 --ulimit 5000 -- -sV -sC -oA nmap/subnet_scan

# Fast port discovery only (skip nmap)
rustscan -a 192.168.1.0/24 -n

# Increase batch size for faster scanning
rustscan -a 192.168.1.0/24 -b 1000 -n
```

## Common Workflows

```bash
# Step 1: Fast ICMP sweep to find live hosts
fping -asgq 172.16.5.0/23 > live_hosts.txt

# Step 2: Nmap ping scan with multiple techniques
sudo nmap -sn -PS22,80,443 -PA80,443 -PE 172.16.5.0/23 -oA nmap/host_discovery

# Step 3: Extract live IPs for port scanning
grep "Host is up" nmap/host_discovery.nmap | cut -d" " -f2 > targets.txt

# Step 4: Port scan discovered hosts
sudo nmap -sS -p- -iL targets.txt -oA nmap/port_scan
```

## Notes

**Best Practices:**

- **Prefer ping scanning from compromised hosts** - More reliable as you're scanning from inside the network
- **Do ICMP/ARP first** - Faster and provides cleaner results for initial discovery
- **In defensive/filtered environments** - Avoid relying only on ICMP; use `-PR` (ARP) or `-Pn` (skip host discovery)

**Host Discovery Techniques:**

1. **ICMP Echo Requests** (`-PE`) - Traditional ping, often blocked by firewalls
2. **ARP Scanning** (`-PR`) - Most reliable on local networks, cannot be blocked
3. **TCP SYN Ping** (`-PS`) - Sends SYN packets to specific ports (22, 80, 443 common)
4. **TCP ACK Ping** (`-PA`) - Useful for bypassing stateless firewalls
5. **UDP Ping** (`-PU`) - Sends UDP packets to specific ports (53, 161 common)

**Performance Considerations:**

- **Fping** is fastest for simple ICMP sweeps
- **Nmap** provides more flexibility and multiple discovery techniques
- **PowerShell** parallel execution significantly speeds up Windows-based sweeps
- **RustScan** excels at fast subnet-wide port discovery

**Firewall Evasion:**

- Use multiple discovery techniques simultaneously (`-PS -PA -PE`)
- Try different port combinations for TCP/UDP pings
- ARP scanning cannot be blocked on local networks
- Consider using `-Pn` to skip host discovery if all hosts are known to be up

**Output Management:**

- Always save results with `-oA` for multiple output formats
- Use `grep` and `cut` to extract clean IP lists for further scanning
- Maintain separate files for different scan phases (discovery, port scan, service detection)

**TTL-Based OS Fingerprinting:**

During host discovery, observe TTL values in responses:
- TTL 64: Linux/macOS
- TTL 128: Windows
- TTL 255: Network devices (routers, switches)
