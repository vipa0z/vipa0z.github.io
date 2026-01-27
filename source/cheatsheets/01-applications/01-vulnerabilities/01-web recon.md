### Passive Recon

Leverage tools that utilize these(like amass passive mode):
1. crt.sh
2. wayback machine
3. amass -passive
4. google dorking
5. github dorking
6. shodan, censys


### Active recon
 
#### port scanning
after retrieving the list of IPs of a specific host(through ASN Recon/`nslookup <host>`):
- go back to [16:10](https://www.youtube.com/watch?v=B1YcflQRvOI&t=970s) – Port Scanning Strategy & Tooling Choices


#### Fuzzing
Fuzzing involves sending malformed or unexpected data to an application to find vulnerabilities, hidden files, directories, or parameters.

---

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

### Tools:

[Arjun](https://github.com/s0md3v/Arjun)

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
```
specific injection points: 
Arjun can detect parameters in a specified location when using JSON or XML method parameters by default. All available methods are: GET/POST/JSON/XML

arjun -u https://api.example.com/endpoint -m JSON --include='{"root":{"a":"b",$arjun$}}'

# query chunk size: By default, Arjun includes 500 parameters in the request which can sometimes exceed the maximum URL length limit for some servers. You can handle such cases with the -c option by specifying the number of parameters to be sent at once.

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

