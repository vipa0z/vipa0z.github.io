

## Retrieving password policy SMB_
Check for anonymouse SMB access and query domain infornmation
```shell-session
$ rpcclient -U "" -N 172.16.5.5
rpcclient $> querydominfo
Domain:		BLACKWOOD
Total Users:	3650
Total Groups:	0
Total Aliases:	37
```

 CHECK PASSWORD POLICY
```
rpcclient $> getdompwinfo
```

enum4linux-ng
```shell-session
 $ enum4linux-ng -P 172.16.5.5 -oA ilfreight
```
view results
```shell-session
$ cat ilfreight.json 
```


 CHECK FOR ANONYMOUS ACCESS NETEXEC)
 ```
$ nxc -u "anonymous" -p ""
```

attempt SMB null session from windows
```cmd-session
 net use \\DC01\ipc$ "" /u:""
```

## LDAP ANONYMOUS BIND
With an LDAP anonymous bind, we can use LDAP-specific enumeration tools
`windapsearch.py`, `ldapsearch`, `ad-ldapdomaindump.py`

ldapsearch is a bit manual and requires knowing the right syntax. here's an example:
```shell-session
$ ldapsearch <-h or -H> 172.16.5.5 -x -b "DC=BLACKWOOD,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

ldap authenticated:
```shell
ldapsearch -h 172.16.5.5 -x -D "CN=svc_ldap,OU=Service Accounts,DC=BLACKWOOD,DC=LOCAL" -w 'P@ssw0rd!' -b "DC=BLACKWOOD,DC=LOCAL" -s sub "(objectClass=*)" sAMAccountName

sAMAccountName: jsmith
dn: CN=Jane Doe,OU=Admins,DC=BLACKWOOD,DC=LOCAL
sAMAccountName: jdoe
```

| Option                             | Meaning                                                                                     |
| ---------------------------------- | ------------------------------------------------------------------------------------------- |
| `-h 172.16.5.5`                    | Connect to LDAP server at this IP                                                           |
| `-x`                               | Use **simple bind** (username + password, not SASL)                                         |
| `-D "CN=...,OU=...,DC=...,DC=..."` | **Bind DN** (the full distinguished name of the account you're authenticating with)         |
| `-w 'P@ssw0rd!'`                   | **Password** for the bind account (wrap in single quotes if it contains special characters) |
| `-b "DC=..."`                      | **Base DN** for the search                                                                  |
| `-s sub`                           | Search scope: subtree                                                                       |
| `"(objectClass=*)"`                | Match all objects (can be more specific like `(sAMAccountName=jsmith)`)                     |
| `sAMAccountName`                   | Return only this attribute (optional — omit to get everything)                              |
## using net.exe to check password policy
```cmd
 net accounts
 
 Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
```

with powerview
```powershell-session
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy
```
powerview revealed that password complexity is enabled (`PasswordComplexity=1`).

### Complexity
Password complexity is enabled, meaning that a user must choose a password with 3/4 of the following: an uppercase letter, lowercase letter, number, special character (`Password1` or `Welcome1` would satisfy the "complexity" requirement here, but are still clearly weak passwords).

The default password policy when a new domain is created is as follows, and there have been plenty of organizations that never changed this policy:

| Policy                                      | Default Value |
| ------------------------------------------- | ------------- |
| Enforce password history                    | 24 days       |
| Maximum password age                        | 42 days       |
| Minimum password age                        | 1 day         |
| Minimum password length                     | 7             |
| Password must meet complexity requirements  | Enabled       |
| Store passwords using reversible encryption | Disabled      |
| Account lockout duration                    | Not set       |
| Account lockout threshold                   | 0             |
| Reset account lockout counter after         | Not set       |