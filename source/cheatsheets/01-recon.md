### Resources
### Modern Recon for Red Teams and Pentesters | Jason Haddix

### Toc

[02:10](https://www.youtube.com/watch?v=B1YcflQRvOI&t=130s) – Recon as a Non-Linear Process
[03:45](https://www.youtube.com/watch?v=B1YcflQRvOI&t=225s) – Why Apex Domains Matter in Attacks
[05:10](https://www.youtube.com/watch?v=B1YcflQRvOI&t=310s) – Finding Infrastructure via ASNs
[07:20](https://www.youtube.com/watch?v=B1YcflQRvOI&t=440s) – Using BGP & IP Ranges to Expand Scope
[09:50](https://www.youtube.com/watch?v=B1YcflQRvOI&t=590s) – Identifying Cloud vs On-Prem Assets
[11:45](https://www.youtube.com/watch?v=B1YcflQRvOI&t=705s) – DNS & WHOIS Techniques for Asset Discovery
[13:45](https://www.youtube.com/watch?v=B1YcflQRvOI&t=825s) – Discovering Hidden Domains via Tenant Data
[16:10](https://www.youtube.com/watch?v=B1YcflQRvOI&t=970s) – Port Scanning Strategy & Tooling Choices
[18:50](https://www.youtube.com/watch?v=B1YcflQRvOI&t=1130s) – Fast Recon with Nmap, Nuclei & Shodan
[21:40](https://www.youtube.com/watch?v=B1YcflQRvOI&t=1300s) – Passive Recon Using Shodan & APIs
[25:00](https://www.youtube.com/watch?v=B1YcflQRvOI&t=1500s) – Acquisition-Based Recon (M&A = New Targets)
[28:40](https://www.youtube.com/watch?v=B1YcflQRvOI&t=1720s) – SSL Certificate Intelligence & Cloud Enumeration
[32:10](https://www.youtube.com/watch?v=B1YcflQRvOI&t=1930s) – Tracking New Assets with Certificate Monitoring
[35:30](https://www.youtube.com/watch?v=B1YcflQRvOI&t=2130s) – Subdomain Enumeration at Scale
[39:10](https://www.youtube.com/watch?v=B1YcflQRvOI&t=2350s) – SubFinder, Beebot & Recon Toolchains
[42:30](https://www.youtube.com/watch?v=B1YcflQRvOI&t=2550s) – Advanced Enumeration & Automation Tips
[46:20](https://www.youtube.com/watch?v=B1YcflQRvOI&t=2780s) – Final Takeaways & Practical Workflow Summary

<iframe width="560" height="315" src="https://www.youtube.com/embed/B1YcflQRvOI" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>



## Passive Recon

Leverage tools that utilize these(like amass passive mode):
1. crt.sh
2. wayback machine
3. amass -passive
4. google dorking
5. github dorking
6. shodan, censys



##  Active recon
 
#### port scanning
after retrieving the list of IPs of a specific host(through ASN Recon/`nslookup <host>`):
- go back to [16:10](https://www.youtube.com/watch?v=B1YcflQRvOI&t=970s) – Port Scanning Strategy & Tooling Choices


#### Fuzzing
Fuzzing involves sending malformed or unexpected data to an application to find vulnerabilities, hidden files, directories, or parameters.



#### Subdomain & VHost Fuzzing

##### Subdomain Fuzzing
Find subdomains (e.g., `admin.example.com`).
```bash
ffuf -u https://FUZZ.example.com/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

##### VHost Fuzzing
Find virtual hosts by fuzzing the `Host` header.
**Gobuster:**
```bash
gobuster vhost -u "http://target.com" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

**FFUF:**
```bash
ffuf -u http://target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.target.com" -fs [size_to_filter]
```

---

##### Directory & File Fuzzing

###### Recursive Directory Fuzzing
**Feroxbuster:**
```bash
feroxbuster -u http://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt --depth 3
```

**Gobuster:**
```bash
gobuster dir -u http://target.com/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -r
```

**FFUF:**
```bash
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -recursion -recursion-depth 1 -e .php -v
```

#### API Recon:
1. Look for Documentation, utilize WBM to investigate deprecatted API versions (/api/v1 ---> /api/v2)
2. if Docs not present, Utilize kiterunner to discover endpoints.
[kiterunner usage guide](https://github.com/assetnote/kiterunner?tab=readme-ov-file#usage)
3. reference [API Passive Recon](../../02-APIs/01-passive%20recon.md) and [Active Recon](../../02-APIs/01-passive%20recon.md) sections.

#### Page & Extension Fuzzing
Find files with specific extensions (e.g., `index.php`, `backup.zip`).
```bash
ffuf -u http://target.com/indexFUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt
```

**Fuzzing for files in root:**
```bash
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt
```

---

####  Parameter Fuzzing



#####   [Arjun](https://github.com/s0md3v/Arjun)

```

# methods: Arjun looks for GET method parameters by default. All available methods are: GET/POST/JSON/XML
-m POST

arjun -u https://api.example.com/endpoint -t 10 -oJ result.json  
arjun -u https://api.example.com/endpoint -t 10 -oJ result.json

# specify threads: -t
-t 

# add delays: -d
-d 2

# set timeouts for requests: -T
-T 10

# bypass ratelimits: --stable
--stable
 # stable sets the number of threads to 1 and introduces a random delay of 6 to 12 seconds between requests.

# set custom ratelimits: You can specify requests/sec with --ratelimit.
--ratelimit 2

# include API data(keys/authtokens): --include <data> 
--include 'api_key =xxxxx' or --include '{"api_key":"xxxxx"}'

# wordlists 
-w /path/to/wordlist.txt

#specific injection points: 
#Arjun can detect parameters in a specified location when using JSON or XML method parameters by default. All available methods are: GET/POST/JSON/XML

arjun -u https://api.example.com/endpoint -m JSON --include='{"root":{"a":"b",$arjun$}}'


# query chunk size: 
By default, Arjun includes 500 parameters in the request which can sometimes exceed the maximum URL length limit for some servers. You can handle such cases with the -c option by specifying the number of parameters to be sent at once.

arjun -u https://api.example.com/endpoint -c 250

--disable-redirects: 

# casing styles:
--casing foo_bar

# headers:
Option: --headers

You can simply add custom headers from command line separated by \n as follows:

arjun -u https://api.example.com/endpoint --headers "Accept-Language: en-US\nCookie: null"

Using the --headers option without any argument will open your text editor (default is 'nano') and you can simply paste your HTTP headers there and press Ctrl + S to save.
```


#### Parameter Value Fuzzing
Fuzz values for known parameters (e.g., ID=FUZZ).

**Generate Wordlist:**
```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

**Fuzz:**
```bash
ffuf -u http://target.com/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w ids.txt -fs [size]
```

---



### DNS Recon

# DNS Enumeration (Port 53)

Enumerate DNS servers to discover subdomains, perform zone transfers, and identify misconfigurations.
DNS reconnaissance is critical for mapping an organization's external and internal infrastructure before deeper attacks.


```bash
# Zone transfer attempt
dig axfr domain.com @10.10.10.10

# Subdomain brute force
dnsenum --dnsserver 10.10.10.10 --enum -p 0 -s 0 -f /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt domain.com

# DNS reconnaissance
dnsrecon -d domain.com -n 10.10.10.10
```

## Zone Transfer

```bash
# Using dig
dig axfr domain.com @10.10.10.10

# Query any records
dig any domain.com @10.10.10.10

# Using nslookup
nslookup
> server 10.10.10.10
> ls -d company.local

# Using host
host -l domain.com 10.10.10.10
```

## DNSRecon

```bash
# General enumeration (includes zone transfer)
dnsrecon -d domain.com -n 10.10.10.10

# Subdomain brute force
dnsrecon -d domain.com -n 10.10.10.10 -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt

# Zone transfer
dnsrecon -d domain.com -n 10.10.10.10 -t axfr

# Reverse lookup
dnsrecon -r 10.10.10.0/24 -n 10.10.10.10
```

## DNSenum

```bash
# Comprehensive DNS enumeration
dnsenum --dnsserver 10.10.10.10 --enum -p 0 -s 0 -o output.txt -f /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt domain.com

# With threading
dnsenum --dnsserver 10.10.10.10 --enum -p 0 -s 0 --threads 90 -f /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt domain.com

# Zone transfer only
dnsenum --noreverse --nocolor domain.com
```

## Fierce

```bash
# Basic DNS scan
fierce --domain domain.com --dns-server 10.10.10.10

# With custom wordlist
fierce --domain company.local --dns-server 10.10.10.10 --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Subdomain discovery
fierce --domain domain.com
```

## Subbrute

```bash
# Create resolver file
echo '10.10.10.10' > resolvers.txt

# Subdomain brute force
python3 subbrute.py domain.com -s names.txt -r resolvers.txt

# Alternative syntax
./subbrute domain.com -s ./names.txt -r ./resolvers.txt
```

## Nmap NSE Scripts

```bash
# DNS zone transfer
nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=domain.com 10.10.10.10

# DNS brute force
nmap -p 53 --script dns-brute --script-args dns-brute.domain=domain.com 10.10.10.10

# DNS enumeration
nmap -p 53 --script dns-nsid,dns-service-discovery,dns-recursion,dns-cache-snoop 10.10.10.10

# Check for recursion
nmap -p 53 --script dns-recursion 10.10.10.10
```

## Subdomain Enumeration (Passive)

```bash
# Subfinder
subfinder -d domain.com -v

# Amass
amass enum -d domain.com

# Assetfinder
assetfinder --subs-only domain.com

# Findomain
findomain -t domain.com
```

## DNS Spoofing (MITM)

### Ettercap DNS Spoofing

```bash
# Edit DNS spoof file
cat /etc/ettercap/etter.dns
domain.com      A   192.168.1.100
*.domain.com    A   192.168.1.100

# Start Ettercap
ettercap -T -q -i eth0 -M arp:remote /target_ip/ /gateway_ip/

# Enable dns_spoof plugin via GUI:
# Plugins > Manage Plugins > dns_spoof
```

### Bettercap DNS Spoofing

```bash
# Start bettercap
bettercap -iface eth0

# Enable ARP spoofing
set arp.spoof.targets 192.168.1.100
arp.spoof on

# Enable DNS spoofing
set dns.spoof.domains domain.com
set dns.spoof.address 192.168.1.200
dns.spoof on
```

## SOA Record Enumeration

```bash
# Query SOA record
dig soa domain.com

# Detailed SOA information
dig soa domain.com @10.10.10.10

# Using host
host -t soa domain.com
```

## Reverse DNS Lookup

```bash
# Single IP
dig -x 10.10.10.10

# Using host
host 10.10.10.10

# Subnet reverse lookup
dnsrecon -r 10.10.10.0/24 -n 10.10.10.10
```

## Common Workflow

```bash
# Step 1: Attempt zone transfer
dig axfr domain.com @10.10.10.10

# Step 2: If zone transfer fails, enumerate SOA
dig soa domain.com @10.10.10.10

# Step 3: Brute force subdomains
dnsenum --dnsserver 10.10.10.10 -f /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt domain.com

# Step 4: Passive subdomain enumeration
subfinder -d domain.com -v

# Step 5: Add discovered subdomains to /etc/hosts
echo "10.10.10.10 subdomain.domain.com" >> /etc/hosts

# Step 6: Attempt zone transfer on discovered subdomains
dig axfr subdomain.domain.com @10.10.10.10
```

## Notes

**DNS Zone Transfer Vulnerability:**

A DNS zone transfer (AXFR) allows a secondary DNS server to copy the entire zone file from the primary server. If misconfigured to allow transfers from any IP (`allow-transfer { any; };`), attackers can dump the entire DNS namespace, revealing:
- All subdomains
- Internal hostnames
- IP addresses
- Network structure

**Critical DNS Misconfigurations:**

| Option | Description | Risk |
|--------|-------------|------|
| `allow-query` | Defines who can send requests | If set to `any`, anyone can query |
| `allow-recursion` | Defines who can send recursive requests | Enables DNS amplification attacks |
| `allow-transfer` | Defines who can perform zone transfers | Exposes entire DNS namespace |
| `zone-statistics` | Collects statistical data | Information disclosure |

**DNS Record Types:**

- **A**: IPv4 address
- **AAAA**: IPv6 address
- **CNAME**: Canonical name (alias)
- **MX**: Mail exchange server
- **NS**: Name server
- **PTR**: Pointer (reverse DNS)
- **SOA**: Start of authority
- **TXT**: Text records (often contain SPF, DKIM, verification tokens)

**SOA Record Components:**

1. **Primary nameserver**: Authoritative nameserver for the zone
2. **Responsible person**: Email address of domain administrator (@ replaced by .)
3. **Serial number**: Version number of zone file
4. **Refresh**: How often secondary servers check for updates
5. **Retry**: How long to wait before retrying failed refresh
6. **Expire**: When secondary servers stop answering queries
7. **Minimum TTL**: Default TTL for records

**Subdomain Takeover:**

Occurs when a subdomain CNAME points to an external service that no longer exists:
```
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

If `anotherdomain.com` expires and someone else registers it, they control `sub.target.com`. Common vulnerable services:
- AWS S3 buckets
- GitHub Pages
- Heroku apps
- Azure websites
- Shopify stores

**DNS Spoofing Attack Flow:**

1. Attacker performs ARP poisoning to become MITM
2. Victim sends DNS query
3. Attacker responds faster than legitimate DNS server
4. Victim receives fake DNS response pointing to attacker's IP
5. Victim connects to attacker-controlled server

**Best Practices for Testing:**

- Always test zone transfers first (quick and high-value)
- Use multiple subdomain wordlists (small, medium, large)
- Combine active and passive enumeration
- Check for wildcard DNS records
- Test for DNS cache poisoning vulnerabilities
- Verify discovered subdomains are actually reachable
- Document all discovered subdomains and IPs

**Common Wordlists:**

- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- `/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt`
- `/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt`
- `/usr/share/wordlists/amass/subdomains.txt`

**Tools Comparison:**

- **DNSRecon**: Comprehensive, supports multiple record types
- **DNSenum**: Fast, good for brute forcing
- **Fierce**: Specialized for corporate networks
- **Subfinder**: Best for passive enumeration
- **Amass**: Most comprehensive, combines multiple techniques
- **Subbrute**: Fast brute forcing with custom resolvers

**Troubleshooting:**

- If zone transfer fails, try different DNS servers
- Some DNS servers rate-limit queries
- Use `--threads` carefully to avoid detection
- Check if DNS server allows recursion
- Verify DNS server is actually authoritative for the domain
