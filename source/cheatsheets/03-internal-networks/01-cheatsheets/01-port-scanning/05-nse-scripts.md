# Nmap NSE Scripts

Leverage Nmap Scripting Engine (NSE) for automated service enumeration, vulnerability detection, and exploitation.
NSE scripts provide deep service-specific reconnaissance beyond basic port scanning and version detection.

## Quick Reference

```bash
# Run default safe scripts
nmap -sC 10.10.10.10

# Run all scripts for specific service
nmap -p 445 --script "smb-*" 10.10.10.10

# Vulnerability scanning
nmap --script vuln 10.10.10.10

# Update NSE database
sudo nmap --script-updatedb
```

## Script Management

```bash
# Update NSE script database
sudo nmap --script-updatedb

# List all NSE scripts
ls /usr/share/nmap/scripts/

# Find scripts for specific service
locate -r '\.nse$' | xargs grep categories | grep smb

# Find default/version scripts for service
locate -r '\.nse$' | xargs grep categories | grep 'default\|version' | grep smb

# Search for specific script
find / -type f -name ftp* 2>/dev/null | grep scripts

# View script documentation
nmap --script-help http-enum
```

## Authentication and Identity Services

### LDAP (389, 636)

```bash
# Comprehensive LDAP enumeration
nmap -p 389,636 --script=ldap* 10.10.10.10

# LDAP without brute force
nmap --script "(ldap*) and not brute" -p 389 10.10.10.10

# LDAP search and root DSE
nmap -p 636 --script=ldap-search,ldap-rootdse 10.10.10.10

# LDAP with authentication
nmap -p 389 --script ldap-search --script-args ldap.username=admin,ldap.password=pass 10.10.10.10
```

### Kerberos (88)

```bash
# Enumerate Kerberos users
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" 10.10.10.10

# Kerberos service information
nmap -p 88 --script=krb5-info 10.10.10.10

# Kerberos with user list
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=users.txt 10.10.10.10
```

### SMB (139, 445)

```bash
# Comprehensive SMB enumeration
nmap -p 139,445 --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb2-capabilities,smb2-security-mode 10.10.10.10

# SMB vulnerability scanning
nmap --script smb-vuln* -p 445 10.10.10.10

# SMB null session
nmap -p 445 --script=smb-null-session 10.10.10.10

# SMB with credentials
nmap -p 445 --script smb-enum-shares --script-args smbuser=admin,smbpass=password 10.10.10.10

# Specific SMB vulnerabilities
nmap -p 445 --script smb-vuln-ms17-010 10.10.10.10
nmap -p 445 --script smb-vuln-ms08-067 10.10.10.10
```

### RDP (3389)

```bash
# RDP encryption enumeration
nmap -p 3389 --script=rdp-enum-encryption 10.10.10.10

# RDP vulnerability (MS12-020)
nmap -p 3389 --script=rdp-vuln-ms12-020 10.10.10.10

# RDP NTLM information disclosure
nmap -p 3389 --script=rdp-ntlm-info 10.10.10.10
```

### WinRM (5985, 5986)

```bash
# WinRM enumeration
nmap -p 5985,5986 --script=http-windows-enum 10.10.10.10

# WinRM user enumeration
nmap -p 5985,5986 --script=winrm-enum-users 10.10.10.10
```

## Network Services

### FTP (21)

```bash
# FTP enumeration and vulnerability detection
nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie 10.10.10.10

# FTP brute force
nmap -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

### SSH (22)

```bash
# SSH enumeration
nmap -p 22 --script=ssh-hostkey,ssh-auth-methods,sshv1,ssh2-enum-algos 10.10.10.10

# SSH brute force
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

### Telnet (23)

```bash
# Telnet encryption and NTLM info
nmap -p 23 --script=telnet-encryption,telnet-ntlm-info 10.10.10.10
```

### SMTP (25, 465, 587)

```bash
# SMTP enumeration
nmap -p 25,465,587 --script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-ntlm-info 10.10.10.10

# SMTP user enumeration
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} 10.10.10.10
```

### DNS (53)

```bash
# DNS zone transfer
nmap -p 53 --script=dns-zone-transfer --script-args dns-zone-transfer.domain=example.com 10.10.10.10

# DNS enumeration
nmap -p 53 --script=dns-nsid,dns-service-discovery,dns-recursion,dns-cache-snoop,dns-random-srcport 10.10.10.10

# DNS brute force
nmap -p 53 --script dns-brute --script-args dns-brute.domain=example.com 10.10.10.10
```

### TFTP (69)

```bash
# TFTP enumeration
nmap -sU -p 69 --script=tftp-enum 10.10.10.10
```

### POP3 (110, 995)

```bash
# POP3 capabilities
nmap -p 110,995 --script=pop3-capabilities 10.10.10.10

# POP3 brute force
nmap -p 110 --script pop3-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

### IMAP (143, 993)

```bash
# IMAP capabilities
nmap -p 143,993 --script=imap-capabilities 10.10.10.10

# IMAP brute force
nmap -p 143 --script imap-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

### SNMP (161, 162)

```bash
# SNMP enumeration
nmap -sU -p 161,162 --script=snmp-info,snmp-interfaces,snmp-processes,snmp-win32-services,snmp-sysdescr 10.10.10.10

# SNMP brute force
nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=communities.txt 10.10.10.10
```

### R-Services (512, 513, 514)

```bash
# RPC information
nmap -p 512,513,514 --script=rpcinfo 10.10.10.10
```

### IPMI (623)

```bash
# IPMI version and cipher zero vulnerability
nmap -p 623 --script=ipmi-version,ipmi-cipher-zero 10.10.10.10
```

### RSync (873)

```bash
# RSync module listing
nmap -p 873 --script=rsync-list-modules 10.10.10.10
```

### MSSQL (1433, 1434, 2433)

```bash
# MSSQL enumeration
nmap -p 1433,1434,2433 --script=ms-sql-info,ms-sql-empty-password,ms-sql-config 10.10.10.10

# MSSQL hash dumping
nmap -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=sa,mssql.password=password 10.10.10.10

# MSSQL brute force
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

### Oracle TNS (1521)

```bash
# Oracle TNS version
nmap -p 1521 --script=oracle-tns-version 10.10.10.10

# Oracle SID brute force
nmap -p 1521 --script oracle-sid-brute 10.10.10.10
```

### NFS (2049)

```bash
# NFS enumeration
nmap -p 2049 --script=nfs-ls,nfs-statfs,nfs-showmount,nfs-acls 10.10.10.10
```

### MySQL (3306)

```bash
# MySQL enumeration
nmap -p 3306 --script=mysql-info,mysql-users,mysql-databases,mysql-empty-password 10.10.10.10

# MySQL hash dumping
nmap -p 3306 --script mysql-dump-hashes --script-args username=root,password=password 10.10.10.10

# MySQL brute force
nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

### PostgreSQL (5432, 5433)

```bash
# PostgreSQL enumeration
nmap -p 5432 --script=pgsql-brute,pgsql-databases,pgsql-users 10.10.10.10

# PostgreSQL information
nmap -p 5433 --script=pgsql-info 10.10.10.10
```

### NetBIOS (137, 138)

```bash
# NetBIOS enumeration
nmap -p 137,138 --script=nbstat,smb-os-discovery,smb-enum-shares,smb-enum-users 10.10.10.10
```

### VNC (5900)

```bash
# VNC information
nmap -p 5900 --script=vnc-info,vnc-title 10.10.10.10

# VNC brute force
nmap -p 5900 --script vnc-brute --script-args passdb=passwords.txt 10.10.10.10
```

### Redis (6379)

```bash
# Redis information
nmap -p 6379 --script=redis-info 10.10.10.10

# Redis brute force
nmap -p 6379 --script redis-brute 10.10.10.10
```

### Elasticsearch (9200)

```bash
# Elasticsearch enumeration
nmap -p 9200 --script=http-elasticsearch-head,http-title,http-methods,http-headers 10.10.10.10
```

### Memcached (11211)

```bash
# Memcached information
nmap -p 11211 --script=memcached-info 10.10.10.10
```

### RPCBind (111)

```bash
# RPC information
nmap -sU -sT -p 111 --script=rpcinfo 10.10.10.10
```

### SIP (5060)

```bash
# SIP methods and user enumeration
nmap -sU -p 5060 --script=sip-methods,sip-enum-users 10.10.10.10
```

### MQTT (1883)

```bash
# MQTT enumeration
nmap -p 1883 --script=mqtt-subscribe,mqtt-connect 10.10.10.10
```

### RMI (1099)

```bash
# RMI registry dump
nmap -p 1099 --script=rmi-dumpregistry,rmi-vuln-classloader 10.10.10.10
```

### NTP (123)

```bash
# NTP information and monlist
nmap -sU -p 123 --script=ntp-info,ntp-monlist 10.10.10.10
```

### Docker (2375)

```bash
# Docker version
nmap -p 2375 --script=docker-version 10.10.10.10
```

### RabbitMQ (5672)

```bash
# RabbitMQ information
nmap -p 5672 --script=rabbitmq-info 10.10.10.10
```

### Jenkins (8080)

```bash
# Jenkins enumeration
nmap -p 8080 --script=http-jenkins-info,http-headers,http-title 10.10.10.10
```

### AJP (8009)

```bash
# AJP methods and headers
nmap -p 8009 --script=ajp-methods,ajp-headers,ajp-auth 10.10.10.10
```

### Kubernetes (6443)

```bash
# Kubernetes API information
nmap -p 6443 --script=http-kubernetes-info,http-headers,http-title 10.10.10.10
```

### CouchDB (5984)

```bash
# CouchDB information
nmap -p 5984 --script=http-couchdb-info,http-title,http-headers 10.10.10.10
```

### VMware (902, 903, 443)

```bash
# VMware version detection
nmap -p 902,903,443 --script=vmware-version 10.10.10.10
```

### TeamViewer (5938)

```bash
# TeamViewer information
nmap -p 5938 --script=teamviewer-info 10.10.10.10
```

### Bacula (9101)

```bash
# Bacula information
nmap -p 9101 --script=bacula-info 10.10.10.10
```

### X11 (6000)

```bash
# X11 access check
nmap -p 6000 --script=x11-access 10.10.10.10
```

## Web Services

### HTTP/HTTPS (80, 443, 8080, 8443)

```bash
# Comprehensive web enumeration
nmap -p 80,443,8080,8443 --script=http-title,http-methods,http-enum,http-headers,http-server-header,http-auth-finder 10.10.10.10

# Web vulnerability scanning
nmap -p 80,443 --script=http-vuln* 10.10.10.10

# Directory enumeration
nmap -p 80 --script http-enum 10.10.10.10

# HTTP methods
nmap -p 80 --script http-methods --script-args http-methods.test-all 10.10.10.10

# Authentication finder
nmap -p 80 --script http-auth-finder 10.10.10.10

# Config backup detection
nmap -p 80 --script http-config-backup 10.10.10.10

# User directory enumeration
nmap -p 80 --script http-userdir-enum 10.10.10.10

# Virtual host discovery
nmap -p 80 --script http-vhosts,http-iis-short-name-brute 10.10.10.10

# XSS and CSRF detection
nmap -p 80 --script http-dombased-xss,http-xssed,http-stored-xss,http-csrf 10.10.10.10

# SQL injection detection
nmap -p 80 --script http-sql-injection 10.10.10.10

# WordPress enumeration
nmap -p 80 --script http-wordpress-enum 10.10.10.10

# Drupal enumeration
nmap -p 80 --script http-drupal-enum 10.10.10.10

# PHP version detection
nmap -p 80 --script http-php-version 10.10.10.10

# ASP.NET debug detection
nmap -p 80 --script http-aspnet-debug 10.10.10.10
```

### WebDAV (80, 443, 8080)

```bash
# WebDAV scanning
nmap -p 80,443,8080 --script=http-webdav-scan 10.10.10.10
```

### Tomcat (8080, 8443)

```bash
# Tomcat manager and user enumeration
nmap -p 8080,8443 --script=http-tomcat-manager,http-tomcat-users 10.10.10.10
```

### Apache Hadoop (50070)

```bash
# Hadoop information
nmap -p 50070 --script=http-hadoop-info 10.10.10.10
```

### Zookeeper (2181)

```bash
# Zookeeper information
nmap -p 2181 --script=zookeeper-info 10.10.10.10
```

### Kafka (9092)

```bash
# Kafka information
nmap -p 9092 --script=kafka-info 10.10.10.10
```

### Varnish (6081)

```bash
# Varnish headers
nmap -p 6081 --script=http-headers,http-title 10.10.10.10
```

## Vulnerability Scanning

```bash
# All vulnerability scripts
nmap --script vuln 10.10.10.10

# Specific vulnerability categories
nmap --script "vuln and safe" 10.10.10.10

# SMB vulnerabilities
nmap -p 445 --script smb-vuln* 10.10.10.10

# HTTP vulnerabilities
nmap -p 80,443 --script http-vuln* 10.10.10.10

# Specific CVEs
nmap -p 80 --script http-vuln-cve2015-1635 10.10.10.10
nmap -p 80 --script http-vuln-cve2017-5638 10.10.10.10
nmap -p 445 --script smb-vuln-ms17-010 10.10.10.10
```

## Brute Force Scripts

```bash
# Brute force multiple services
nmap -p 21,22,23,25,80,110,143,443,3306,5432,6379,8080 --script brute 10.10.10.10

# FTP brute force
nmap -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10

# SSH brute force
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10

# HTTP form brute force
nmap -p 80 --script http-form-brute --script-args http-form-brute.path=/login,http-form-brute.uservar=username,http-form-brute.passvar=password 10.10.10.10

# SMB brute force
nmap -p 445 --script smb-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

## Script Categories

```bash
# Run all default scripts
nmap -sC 10.10.10.10
nmap --script default 10.10.10.10

# Run safe scripts only
nmap --script safe 10.10.10.10

# Run discovery scripts
nmap --script discovery 10.10.10.10

# Exclude intrusive scripts
nmap --script "not intrusive" 10.10.10.10

# Run specific category
nmap --script auth 10.10.10.10
nmap --script broadcast 10.10.10.10
nmap --script brute 10.10.10.10
nmap --script default 10.10.10.10
nmap --script discovery 10.10.10.10
nmap --script dos 10.10.10.10
nmap --script exploit 10.10.10.10
nmap --script external 10.10.10.10
nmap --script fuzzer 10.10.10.10
nmap --script intrusive 10.10.10.10
nmap --script malware 10.10.10.10
nmap --script safe 10.10.10.10
nmap --script version 10.10.10.10
nmap --script vuln 10.10.10.10
```

## Script Arguments

```bash
# Pass arguments to scripts
nmap --script http-enum --script-args http-enum.basepath=/admin 10.10.10.10

# Multiple arguments
nmap --script smb-enum-shares --script-args smbuser=admin,smbpass=password 10.10.10.10

# Brute force with custom wordlists
nmap --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10

# Set timeout
nmap --script http-enum --script-args http.timeout=10s 10.10.10.10
```

## Common Automation

```bash
# Default scripts and version detection
nmap -sC -sV 10.10.10.10

# Safe and default scripts
nmap --script "default,safe" 10.10.10.10

# All scripts except brute force
nmap --script "all and not brute" 10.10.10.10

# Service-specific comprehensive scan
nmap -p 445 --script "smb-* and not brute" 10.10.10.10
```

## Notes

**Script Categories:**

- **auth**: Authentication-related scripts
- **broadcast**: Network broadcast/multicast discovery
- **brute**: Brute force password attacks
- **default**: Default safe scripts (run with `-sC`)
- **discovery**: Service and host discovery
- **dos**: Denial of service scripts (use with caution)
- **exploit**: Exploitation scripts
- **external**: Scripts that contact external resources
- **fuzzer**: Fuzzing scripts
- **intrusive**: Scripts that may crash services
- **malware**: Malware detection
- **safe**: Scripts unlikely to crash services or trigger alerts
- **version**: Version detection enhancement
- **vuln**: Vulnerability detection

**Script Locations:**

- Linux: `/usr/share/nmap/scripts/`
- Windows: `C:\Program Files\Nmap\scripts\`
- macOS: `/usr/local/share/nmap/scripts/`

**Finding Scripts:**

```bash
# List all scripts
ls /usr/share/nmap/scripts/

# Search for service-specific scripts
ls /usr/share/nmap/scripts/ | grep smb

# Find scripts by category
grep -r "categories.*auth" /usr/share/nmap/scripts/

# View script documentation
nmap --script-help <script-name>
```

**Script Performance:**

- Default scripts (`-sC`) are generally safe and fast
- Brute force scripts can be very slow
- Vulnerability scripts may trigger IDS/IPS alerts
- Use `--script-timeout` to limit script execution time

**Best Practices:**

- Always update NSE database before important scans: `sudo nmap --script-updatedb`
- Test scripts in lab environment before production use
- Use `--script-help` to understand script behavior
- Combine scripts with service version detection (`-sV`)
- Save results with `-oA` for later analysis
- Be cautious with `dos`, `exploit`, and `intrusive` categories

**Common Workflows:**

```bash
# Initial enumeration
nmap -sC -sV -p- 10.10.10.10

# Service-specific deep dive
nmap -p 445 --script "smb-* and not brute" 10.10.10.10

# Vulnerability assessment
nmap --script "vuln and safe" -sV 10.10.10.10

# Comprehensive scan
nmap -sC -sV --script "default,safe,vuln" -p- 10.10.10.10
```

**Script Arguments:**

Many scripts accept arguments to customize behavior:
- Wordlists for brute force
- Credentials for authenticated scans
- Timeouts and retry counts
- Specific paths or parameters to test

**Troubleshooting:**

- If scripts don't run, check script database is updated
- Verify script exists: `ls /usr/share/nmap/scripts/ | grep <script>`
- Check script syntax: `nmap --script-help <script>`
- Increase verbosity: `-vv` or `--script-trace`
- Check for script errors in output

**Security Considerations:**

- Some scripts are intrusive and may crash services
- Brute force scripts generate significant traffic
- Exploit scripts should only be used with authorization
- External scripts may leak information about your scan
- Always obtain proper authorization before scanning
