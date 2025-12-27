

## Credentialed user enumeration (unrestricted)
```shell-session
$ sudo nxc smb 172.16.5.5 -u vipa0z -p Academy_student_AD! --users
```

We can also use CME to target other hosts. Let's check out what appears to be a file server to see what users are logged in currently.
```shell-session
$ sudo nxc smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```
### Enumerating privileged users, groups, admins

We have several options with Windapsearch to perform standard enumeration (dumping users, computers, and groups) and more detailed enumeration. The `--da` (enumerate domain admins group members ) option and the `-PU` ( find privileged users) options. The `-PU` option is interesting because it will perform a recursive search for users with nested group membership.

```shell-session
$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@blackwood.local 
```

### privileged users
```shell-session
 python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@blackwood.local -p Klmcargo2 -PU
 
[+] Using DN: CN=Enterprise Admins,CN=Users,DC=BLACKWOOD,DC=LOCAL
[+]     Found 3 nested users for group Enterprise Admins:

```

You'll notice that it performed mutations against common elevated group names in different languages. This output gives an example of the dangers of nested group membership, and this will become more evident when we work with BloodHound graphics to visualize this.

## bloodhound
```shell-session
$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d blackwood.local -c all 

zip -r ilfreight_bh.zip *.json
```

`sudo neo4j start`
`bloodhound`
- `user == neo4j` / `pass ==attacker-password!`.
![[bh-analysis.webp]]

## Credentialed from windows (NATIVE)
#### Load ActiveDirectory Module

```powershell-session
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module
```

Now that our modules are loaded, let's begin. First up, we'll enumerate some basic information about the domain with the [Get-ADDomain](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-addomain?view=windowsserver2022-ps) cmdlet.
```powershell
PS C:\htb> Get-ADDomain

ChildDomains                       : {LOGISTICS.BLACKWOOD.local}
ComputersContainer                 : CN=Computers,DC=BLACKWOOD,DC=LOCAL
DeletedObjectsContainer            : CN=Deleted Objects,DC=BLACKWOOD,DC=LOCAL
DistinguishedName                  : DC=BLACKWOOD,DC=LOCAL
DNSRoot                            : blackwood.local
DomainControllersContainer         : OU=Domain Controllers,DC=BLACKWOOD,DC=LOCAL
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-3842939050-3880317879-2865463114
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=BLACKWOOD,DC=LOCAL
Forest                             : blackwood.local
InfrastructureMaster               : DC01.blackwood.local
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {cn={DDBB8574-E94E-4525-8C9D-ABABE31223D0},cn=policies,cn=system,DC=BLACKWOOD,
                                     DC=LOCAL, CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=INLAN
                                     EFREIGHT,DC=LOCAL}
LostAndFoundContainer              : CN=LostAndFound,DC=BLACKWOOD,DC=LOCAL
ManagedBy                          :
Name                               : BLACKWOOD
NetBIOSName                        : BLACKWOOD
ObjectClass                        : domainDNS
ObjectGUID                         : 71e4ecd1-a9f6-4f55-8a0b-e8c398fb547a
ParentDomain                       :
PDCEmulator                        : DC01.blackwood.local
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=BLACKWOOD,DC=LOCAL
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {DC01.blackwood.local}
RIDMaster                          : DC01.blackwood.local
SubordinateReferences              : {DC=LOGISTICS,DC=BLACKWOOD,DC=LOCAL,
                                     DC=ForestDnsZones,DC=BLACKWOOD,DC=LOCAL,
                                     DC=DomainDnsZones,DC=BLACKWOOD,DC=LOCAL,
                                     CN=Configuration,DC=BLACKWOOD,DC=LOCAL}
SystemsContainer                   : CN=System,DC=BLACKWOOD,DC=LOCAL
UsersContainer                     : CN=Users,DC=BLACKWOOD,DC=LOCAL
```

#### Get-ADUser
[We will be filtering for accounts with the `ServicePrincipalName` property populated. This will get us a listing of accounts that may be susceptible to a Kerberoasting attack,
```powershell-session
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

DistinguishedName    : CN=adfs,OU=Service Accounts,OU=Corp,DC=BLACKWOOD,DC=LOCAL
Enabled              : True
GivenName            : Sharepoint
Name                 : adfs
ObjectClass          : user
ObjectGUID           : 49b53bea-4bc4-4a68-b694-b806d9809e95
SamAccountName       : adfs
```

### trusts
domain trust relationships using the [Get-ADTrust](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps) cmdlet
```powershell-session
PS C:\htb> Get-ADTrust -Filter *

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=LOGISTICS.BLACKWOOD.local,CN=System,DC=BLACKWOOD,DC=LOCAL
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : LOGISTICS.BLACKWOOD.LOCAL
```

#### Group Enumeration

```powershell-session
PS C:\htb> Get-ADGroup -Filter * | select name
```

#### Detailed Group Info
```powershell-session
 Get-ADGroup -Identity "Backup Operators"

DistinguishedName : CN=Backup Operators,CN=Builtin,DC=BLACKWOOD,DC=LOCAL
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Backup Operators
ObjectClass       : group
ObjectGUID        : 6276d85d-9c39-4b7c-8449-cad37e8abc38
SamAccountName    : Backup Operators
SID               : S-1-5-32-551
```
Now that we know more about the group, let's get a member listing using the [Get-ADGroupMember](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember?view=windowsserver2022-ps) cmdlet.

### list group members
```powershell-session
Get-ADGroupMember -Identity "Backup Operators"

distinguishedName : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=BLACKWOOD,DC=LOCAL
name              : BACKUPAGENT
objectClass       : user
objectGUID        : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName    : backupagent
SID               : S-1-5-21-3842939050-3880317879-2865463114-5220
```


## users and AD  enumeration with blocked `--users` flag
some techniques to enumerate AD if nornal methods dont work:
`nxc with --rid-brute`

for user enumeration and bloodhound:
`add a computer accoount to the domain with impacket`
now this domain account will be able to query the domain list since they are allowed to transfer Sids and other stuff to work properly. 
```
add-computer.py -computer-name 'vipa0z$' -computer-pass 'BAngo3241!' -dc-host <ip or dn=> haze.htb or dc01.haze.htb or 10.10.156.4>  -domain-netbios <haze> <'haze/paul.taylor:password121'>
```