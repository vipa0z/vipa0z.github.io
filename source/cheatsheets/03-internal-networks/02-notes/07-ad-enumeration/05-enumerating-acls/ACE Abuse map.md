
## ACE Abuse map
![[ACL_attacks_graphic 1.webp]]

- `ForceChangePassword` abused with `Set-DomainUserPassword`
- `Add Members` abused with `Add-DomainGroupMember`
- `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `GenericWrite` abused with `Set-DomainObject`
- `WriteOwner` abused with `Set-DomainObjectOwner`
- `WriteDACL` abused with `Add-DomainObjectACL`
- `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `Addself` abused with `Add-DomainGroupMember

## Experiments

get all rights for user (native)
```powershell-session
PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```
get ACL for users where the prinicapal is wley
```powershell-session
 foreach($line in [System.IO.File]::ReadLines("C:\Users\vipa0z\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'BLACKWOOD\\wley'}}
```





### Interesting articles:
https://www.synacktiv.com/en/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory#part_2

https://www.praetorian.com/blog/how-to-exploit-active-directory-acl-attack-paths-through-ldap-relaying-attacks/



OGs/general:
https://redfoxsec.com/blog/abusing-acl-misconfigurations/

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces

### tools
cheatsheet:
https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-acl-ace/

`dacledit.py`
`bloodyAD`
`powerview`
`bloodhound`