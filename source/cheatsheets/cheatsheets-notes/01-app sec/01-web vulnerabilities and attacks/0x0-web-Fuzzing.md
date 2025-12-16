
Fuzzing involves sending malformed or unexpected data to an application to find vulnerabilities, hidden files, directories, or parameters.



## Subdomain & VHost Fuzzing

### Subdomain Fuzzing
Find subdomains (e.g., `admin.example.com`).
```bash
ffuf -u https://FUZZ.example.com/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### VHost Fuzzing
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

## Directory & File Fuzzing

### Recursive Directory Fuzzing
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

### Page & Extension Fuzzing
Find files with specific extensions (e.g., `index.php`, `backup.zip`).
```bash
ffuf -u http://target.com/indexFUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt
```

**Fuzzing for files in root:**
```bash
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt
```

---

## Parameter Fuzzing

### GET Parameter Names
Find hidden GET parameters (e.g., `?debug=1`).
```bash
ffuf -u "http://target.com/page.php?FUZZ=1" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs [size]
```

### POST Parameter Names
Find hidden POST parameters.
```bash
ffuf -u http://target.com/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs [size]
```

### Value Fuzzing
Fuzz values for known parameters (e.g., IDs).

**Generate Wordlist:**
```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

**Fuzz:**
```bash
ffuf -u http://target.com/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w ids.txt -fs [size]
```

---

## Common Wordlists (SecLists)
txt`
-   **Subdomains**: `/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- **subdomains - JHADDIX-ALL (updated but very long)**: `/usr/share/wordlists/seclists/Discovery/DNS/jhaddix-all.txt`
-   **Directories**: `/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
-   **Parameters**: `/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt`
-   **Extensions**: `/usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt`
