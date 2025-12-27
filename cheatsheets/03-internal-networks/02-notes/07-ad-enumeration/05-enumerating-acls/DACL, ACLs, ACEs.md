
Attackers utilize ACE entries to either further access or establish persistence. These can be great for us as penetration testers as many organizations are unaware of the ACEs applied to each object or the impact that these can have if applied incorrectly. They cannot be detected by vulnerability scanning tools, and often go unchecked for many years, especially in large and complex environments. During an assessment where the client has taken care of all of the "low hanging fruit" AD flaws/misconfigurations, ACL abuse can be a great way for us to move
Permissions to abuse:
![](Pasted%20image%2020250214191550.png)

![](Pasted%20image%2020250201173103.png)
[GenericWrite](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericwrite) - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set).

Over a group means we could add ourselves or another security principal to a given group. Finally,
if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.

[GenericAll](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall) - this grants us full control over a target object. 

If we have this access over a computer object and the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.
![](ACL_attacks_graphic.webp)
see that a user we have control over (or can potentially take over) has the rights to read the password for a Group Managed Service Account (gMSA) through the [ReadGMSAPassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#readgmsapassword) edge. In this case, there are tools such as [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) that we could use, along with other methods, to obtain the password for the service account in question. Other times we may come across extended rights such as [Unexpire-Password](https://learn.microsoft.com/en-us/windows/win32/adschema/r-unexpire-password) or [Reanimate-Tombstones](https://learn.microsoft.com/en-us/windows/win32/adschema/r-reanimate-tombstones) using PowerView and have to do a bit of research to figure out how to exploit these for our benefit. It's worth familiarizing yourself with all of the [BloodHound edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) and as many Active Directory [Extended Rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) as possible as you never know when you may encounter a less common one during an assessment.


```powershell-session
> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

`user ACL`
```powershell-session
 $sid2 = Convert-NameToSid damundsen
 
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

`GROUP ACLs`
```powershell-session
PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

```powershell-session
> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```
#### Viewing Potential Attack Paths through BloodHound

![image](https://academy.hackthebox.com/storage/modules/143/wley_path.png)

Finally, we can use the pre-built queries in BloodHound to confirm that the `adunn` user has DCSync rights.

#### Viewing Pre-Build queries through BloodHound

![image](https://academy.hackthebox.com/storage/modules/143/adunn_dcsync.png)


`Abusing genericAll to add ourselves to domain admins group`
```
Net group “domain admins” ct059 /add /domain
```
