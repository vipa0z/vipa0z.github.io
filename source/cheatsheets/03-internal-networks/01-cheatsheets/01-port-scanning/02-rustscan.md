# RustScan

Lightning-fast port scanner written in Rust that integrates seamlessly with Nmap for comprehensive enumeration.
Use RustScan for rapid initial port discovery, then pipe results to Nmap for detailed service detection and vulnerability scanning.

## Quick Reference

```bash
# Fast scan with Nmap integration
rustscan -a 10.10.10.10 -- -sC -sV

# Port discovery only (no Nmap)
rustscan -a 10.10.10.10 -n

# Full port scan with Nmap scripts
rustscan -a 10.10.10.10 -p 1-65535 -- -sC -sV -oA full_scan
```

## Basic Usage

```bash
# Scan top 5000 TCP ports
rustscan -a 192.168.1.1

# Scan specific target
rustscan -a 10.10.10.10

# Scan hostname
rustscan -a example.com
```

## Specific Port Scanning

```bash
# Single port
rustscan -a 10.10.10.10 -p 22

# Multiple ports
rustscan -a 10.10.10.10 -p 21,22,80,443

# Port range
rustscan -a 10.10.10.10 -p 1-1000

# All ports
rustscan -a 10.10.10.10 -p 1-65535
```

## Nmap Integration

```bash
# Pass options to Nmap (most common usage)
rustscan -a 10.10.10.10 -- -sC -sV

# Aggressive scan with OS detection
rustscan -a 10.10.10.10 -- -A

# Full port scan with Nmap scripts
rustscan -a 192.168.1.100 -- -sC -sV -oN scan.txt

# Vulnerability scanning
rustscan -a 10.10.10.10 -- --script vuln

# Custom Nmap script arguments
rustscan -a 10.10.10.10 -- --script http-enum --script-args http-enum.basepath=/admin

# Save Nmap output in all formats
rustscan -a 10.10.10.10 -- -sC -sV -oA results
```

## Speed and Performance

```bash
# Increase batch size (ports scanned at once)
rustscan -a 10.10.10.10 -b 1500

# Set timeout in milliseconds
rustscan -a 10.10.10.10 -t 2000

# Combine batch size and timeout
rustscan -a 10.0.0.5 -b 3000 -t 1500

# Specify number of threads
rustscan -a 10.10.10.10 -u 5000

# Maximum speed (use with caution)
rustscan -a 10.10.10.10 -b 5000 -t 1000 -u 10000
```

## Scan All Ports

```bash
# Full 65535 port scan
rustscan -a 10.10.10.10 -p 1-65535

# Full port scan with Nmap integration
rustscan -a 10.10.10.10 -p 1-65535 -- -sC -sV

# Alternative syntax
rustscan -a 10.10.10.10 -r 1-65535
```

## Output Options

```bash
# Skip Nmap, just list open ports
rustscan -a 192.168.1.1 -r 1-65535 -n

# Greppable output (ports only)
rustscan -a 10.10.10.10 -g

# Pipe greppable output to other commands
rustscan -a 10.10.10.10 -r 1-1000 -g | xargs -I {} echo "Port {} open!"

# Save Nmap results to file
rustscan -a 10.10.10.10 -- -sC -sV -oN results.txt
```

## Stealth and IDS Evasion

```bash
# Slower scan to avoid detection
rustscan -a 10.10.10.10 -t 5000 -b 100 -- -sC -sV

# Combine with Nmap stealth options
rustscan -a 10.10.10.10 -t 3000 -b 100 -- -sS -Pn

# Very slow scan for maximum stealth
rustscan -a 10.10.10.10 -t 10000 -b 50 -- -T2 -sS
```

## Multiple Targets

```bash
# Scan multiple IPs
rustscan -a 10.10.10.10,10.10.10.11,10.10.10.12

# Scan from file
rustscan -f targets.txt -- -sC -sV

# Scan subnet
rustscan -a 192.168.1.0/24 -- -sC -sV
```

## Common Scan Recipes

```bash
# Fast initial discovery
rustscan -a 10.10.10.10 -n

# Standard enumeration scan
rustscan -a 10.10.10.10 -- -sC -sV

# Full comprehensive scan
rustscan -a 10.10.10.10 -p 1-65535 -- -sC -sV -oA full-scan

# Stealth scan
rustscan -a 10.10.10.10 -t 3000 -b 100 -- -sS -Pn

# Vulnerability assessment
rustscan -a 10.10.10.10 -- --script vuln -oA vuln-scan

# Web application scan
rustscan -a 10.10.10.10 -p 80,443,8080,8443 -- --script http-enum,http-headers,http-methods

# SMB enumeration
rustscan -a 10.10.10.10 -p 139,445 -- --script smb-enum-shares,smb-enum-users,smb-os-discovery
```

## Workflow Integration

```bash
# Step 1: Fast port discovery with RustScan
rustscan -a 10.10.10.10 -n > open_ports.txt

# Step 2: Extract ports and format for Nmap
ports=$(cat open_ports.txt | grep -oP '\d+' | tr '\n' ',' | sed 's/,$//')

# Step 3: Detailed Nmap scan on discovered ports
nmap -sC -sV -p $ports 10.10.10.10 -oA detailed_scan

# Alternative: Let RustScan handle it automatically
rustscan -a 10.10.10.10 -- -sC -sV -oA scan_results
```

## Option Reference

| Option | Description |
|--------|-------------|
| `-a` | Target IP/hostname |
| `-p` | Ports to scan (comma-separated) |
| `-r` | Port range |
| `-t` | Timeout in milliseconds |
| `-b` | Batch size (ports scanned at once) |
| `-u` | Number of threads |
| `--` | Pass options to Nmap |
| `-n` | Skip Nmap integration |
| `-g` | Greppable output (ports only) |
| `-f` | Read targets from file |

## Notes

**Important Limitation:**

RustScan finds initial ports quickly, but in testing, it can break Nmap results when used with the `--` pass-through. For critical scans:

1. Use RustScan with `-n` flag to skip Nmap
2. Manually take the discovered ports
3. Run a separate Nmap scan with those ports

```bash
# Recommended workflow for accuracy
rustscan -a 10.10.10.10 -n
# Note the open ports, then:
nmap -sC -sV -p 22,80,443 10.10.10.10
```

**Performance Tuning:**

- **Batch Size** (`-b`): Number of ports scanned simultaneously
  - Default: 4500
  - Increase for faster scans on stable networks
  - Decrease if experiencing packet loss or timeouts

- **Timeout** (`-t`): Milliseconds to wait for port response
  - Default: 1500ms
  - Increase for slow/unstable networks
  - Decrease for fast local networks

- **Threads** (`-u`): Number of concurrent threads
  - Default: 5000
  - May need to increase ulimit: `ulimit -n 10000`

**When to Use RustScan:**

- Initial rapid port discovery on large networks
- Time-sensitive assessments requiring fast results
- Scanning multiple hosts simultaneously
- When you need to quickly identify open ports before detailed enumeration

**When to Use Nmap Directly:**

- Detailed service version detection
- Running complex NSE scripts
- Stealth scanning with specific timing
- When accuracy is more important than speed
- UDP scanning (RustScan is TCP-only)

**Best Practices:**

- Always verify RustScan results with a follow-up Nmap scan
- Use `-n` flag for port discovery, then run Nmap separately
- Adjust batch size and timeout based on network conditions
- Save results with Nmap's `-oA` flag for multiple output formats
- Consider network stability before using maximum speed settings

**Advantages:**

- Extremely fast port scanning (written in Rust)
- Seamless Nmap integration
- Adaptive scanning (adjusts to network conditions)
- Modern, actively maintained tool
- Cross-platform support

**Limitations:**

- TCP scanning only (no UDP support)
- May produce inconsistent results when piping directly to Nmap
- Requires higher ulimit for maximum performance
- Less mature than Nmap for edge cases
