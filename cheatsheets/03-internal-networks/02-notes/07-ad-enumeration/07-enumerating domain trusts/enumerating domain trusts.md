![[Pasted image 20250727231028.png]]
## Enumerating Trust Relationships
```powershell-session
Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *
```
Checking for Existing Trusts using Get-DomainTrust
```powershell-session
> Get-DomainTrust 

SourceName      : blackwood.local
TargetName      : LOGISTICS.BLACKWOOD.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM
```

PowerView can be used to perform a domain trust mapping and provide information such as the type of trust (parent/child, external, forest) and the direction of the trust (one-way or bidirectional). This information is beneficial once a foothold is obtained, and we plan to compromise the environment further.

```powershell-session
PS C:\htb> Get-DomainTrustMapping

SourceName      : blackwood.local
TargetName      : LOGISTICS.BLACKWOOD.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : blackwood.local
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM
```

#### Checking Users in the Child Domain using Get-DomainUser
From here, we could begin performing enumeration across the trusts. For example, we could look at all users in the child domain:

```powershell-session
PS C:\htb> Get-DomainUser -Domain LOGISTICS.BLACKWOOD.local | select SamAccountName

samaccountname
--------------
vipa0z_adm
Administrator
```

windows native method:
`` Using netdom to query domain controllers``
```
C:\htb> netdom query /domain:blackwood.local dc
List of domain controllers with accounts in the domain:

DC01
The command completed successfully.
```

`#### Using netdom to query workstations and servers`
```cmd
C:\htb> netdom query /domain:blackwood.local workstation
List of workstations with accounts in the domain:

MS01
MX01      ( Workstation or Server )

SQL01      ( Workstation or Server )
ILF-XRG      ( Workstation or Server )
MAINLON      ( Workstation or Server )
CISERVER      ( Workstation or Server )
INDEX-DEV-LON      ( Workstation or Server )
...SNIP...
```
We can also use BloodHound to visualize these trust relationships by using the `Map Domain Trusts` pre-built query. Here we can easily see that two bidirectional trusts exist.
![[Pasted image 20250727231705.png]]
