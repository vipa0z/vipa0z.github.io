

Both attackers and defenders often overlook misconfigured `discretionary access control lists` (`DACLs`) within an Active Directory environment. For attackers, abusing misconfigured `DACLs` can allow not only horizontal and vertical privilege escalation and lateral movement within an AD environment, but can also lead to a complete compromise of the domain.

`DACL Attacks I` covers common attacks against misconfigured DACLs within an Active Directory environment. We will first understand DACLs and Security Descriptors, their internal structure and various members, and how they work. Then, we will learn about Access Control Entries (ACEs) and their implications within a DACL, and we will go over the interpretation of some access mask bits that interest us. We will also identify abusable object-specific and validated writes access rights.

Subsequently, we will then start enumerating DACLs from Windows and Linux and abusing/attacking misconfigured ones. By carrying out these attacks, we will gain access to privileged resources, escalate privileges horizontally and vertically, and move laterally across the target Active Directory network.

Within the Windows security ecosystem, `tokens` and `security descriptors` are the two main variables of the object security equation. While `tokens` identify the security context of a process or a thread, `security descriptors` contain the security information associated with an object. To achieve the `Confidentiality` pillar of the `CIA` triad, many operating systems and directory services utilize `access control lists` (`ACLs`), "a mechanism that implements access control for a system resource by enumerating the system entities that are permitted to access the resource and stating, either implicitly or explicitly, the access modes granted to each entity", according to [RFC4949](https://datatracker.ietf.org/doc/html/rfc4949).

Remember that access control policies dictate what types of access are permitted, under what circumstances, and by whom. The four general categories of access control policies are `Discretionary access control` (`DAC`), `Mandatory access control` (`MAC`), `Role-based access control` (`RBAC`), and `Attribute-based access control` (`ABAC`).

`DAC`, the traditional method of implementing access control, controls access based on the requestor's identity and access rules stating what requestors are (or are not) allowed to do. It is `discretionary` because an entity might have access rights that permit it, by its own volition, to enable another entity to access some resource; this is in contrast to `MAC`, in which the entity having access to a resource may not, just by its own volition, enable another entity to access that resource. Windows is an example of a `DAC` operating system, which utilizes `Discretionary access control lists` (`DACLs`).

The image below shows the `DACL`/`ACL` for the user account `forend` in `Active Directory Users and Computers` (`ADUC`). Each item under `Permission entries` makes up the `DACL` for the user account. In contrast, the individual entries (such as `Full Control` or `Change Password`) are `Access Control Entries` (`ACEs`) showing the access rights granted over this user object to various users and groups.

![Sample_ACL.png](https://academy.hackthebox.com/storage/modules/219/Sample_ACL.png)

`DACLs` are part of the bigger picture of `security descriptors`. Let us review security descriptors to understand them better and their roles within the access control model.

## Security Descriptors

In Windows, every object (also known as [securable objects](https://learn.microsoft.com/en-us/windows/win32/secauthz/securable-objects)) has a `security descriptor` data structure that specifies who can perform what actions on the object. The `security descriptor` is a binary data structure that, although it can vary in length and exact contents, can contain six main fields:

- `Revision Number`: The `SRM` (`Security Reference Monitor`) version of the security model used to create the descriptor.
- `Control Flags`: Optional modifiers that define the behavior/characteristics of the security descriptor.
- `Owner SID`: The object's owner `SID`.
- `Group SID`: The object's primary group `SID`. Only the [Windows POSIX](https://en.wikipedia.org/wiki/Microsoft_POSIX_subsystem) subsystem utilized this member (before being [discontinued](https://social.technet.microsoft.com/wiki/contents/articles/10224.posix-and-unix-support-in-windows.aspx)), and most AD environments now ignore it.
- `Discretionary access control list` (`DACL`): Specifies who has what access to the object - throughout the `DACL Attacks` mini-modules, our primary focus will be abusing and attacking these.
- `System access control list` (`SACL`): Specifies which operations by which users should be logged in the security audit log and the explicit integrity level of an object.

Internally, Windows represents a `security descriptor` via the [SECURITY_DESCRIPTOR struct](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor):

Code: cpp

```cpp
typedef struct _SECURITY_DESCRIPTOR {
  BYTE                        Revision;
  BYTE                        Sbz1;
  SECURITY_DESCRIPTOR_CONTROL Control;
  PSID                        Owner;
  PSID                        Group;
  PACL                        Sacl;
  PACL                        Dacl;
} SECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;
```

A `security descriptor` can be one of two forms, [absolute or self-relative](https://learn.microsoft.com/en-us/windows/win32/secauthz/absolute-and-self-relative-security-descriptors); `absolute security descriptors` contain pointers to the information (i.e., not the actual information itself), as in the `SECURITY_DESCRIPTOR` struct above, and these are the ones that we will encounter when interacting with Windows objects, whether AD ones or not.

`Self-relative security descriptors` are not very different: instead of storing pointers, they store the actual data of a `security descriptor` in a contiguous memory block. These are meant to store a security descriptor on a disk or transmit it over the wire.

Four of the seven members of the `SECURITY_DESCRIPTOR` struct matter to us for the exploitation of `DACLs`; therefore, we will review them to understand what they are.

#### Control

The `Control` member is of type [SECURITY_DESCRIPTOR_CONTROL](https://learn.microsoft.com/en-gb/windows/win32/secauthz/security-descriptor-control), a 16-bit set of bit flags that qualify the meaning of a `security descriptor` or its components. The value of `Control`, when retrieved with the function [GetSecurityDescriptorControl](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptorcontrol), can include a combination of 13 bits flags:

|Flag|Hexadecimal Representation|
|:--|:-:|
|[SE_DACL_AUTO_INHERIT_REQ](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_DACL_AUTO_INHERIT_REQ)|`0x0100`|
|[SE_DACL_AUTO_INHERITED](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_DACL_AUTO_INHERITED)|`0x0400`|
|[SE_DACL_DEFAULTED](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_DACL_DEFAULTED)|`0x0008`|
|[SE_DACL_PRESENT](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_DACL_PRESENT)|`0x0004`|
|[SE_DACL_PROTECTED](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_DACL_PROTECTED)|`0x1000`|
|[SE_GROUP_DEFAULTED](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_GROUP_DEFAULTED)|`0x0002`|
|[SE_OWNER_DEFAULTED](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_OWNER_DEFAULTED)|`0x0001`|
|[SE_SACL_AUTO_INHERIT_REQ](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_SACL_AUTO_INHERIT_REQ)|`0x0200`|
|[SE_SACL_AUTO_INHERITED](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_SACL_AUTO_INHERITED)|`0x0800`|
|[SE_SACL_DEFAULTED](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_SACL_DEFAULTED)|`0x0008`|
|[SE_SACL_PRESENT](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_SACL_PRESENT)|`0x0010`|
|[SE_SACL_PROTECTED](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_SACL_PROTECTED)|`0x2000`|
|[SE_SELF_RELATIVE](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_SELF_RELATIVE)|`0x8000`|

These binary flags can be added to represent any combinations. For example, if the value of `Control` is `0x8014`, it signifies the presence of the `SE_DACL_PRESENT`, `SE_SACL_PRESENT`, and `SE_SELF_RELATIVE` flags.

One important flag for us to know about is [SE_DACL_PRESENT](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor#SE_DACL_PRESENT):

|Flag|Meaning|
|:--|---|
|`SE_DACL_PRESENT`|Indicates a `security descriptor` that has a `DACL`. If not set, or if set and the `DACL` is `NULL`, the `security descriptor` allows full access to everyone. An `empty DACL` permits access to no one.|

#### Owner

The `Owner` and `Group` members contain a pointer to the `Security Identifier` (`SID`) of the object's owner and primary group, respectively. Object owners are always granted full control of the `security descriptor`, as they are granted the access rights `RIGHT_WRITE_DAC` (`WriteDacl`) and `RIGHT_READ_CONTROL` (`ReadControl`) implicitly.

#### Sacl and Dacl

In Windows, `SACL` (`System access control list`) and `DACL` (`Discretionary access control lists`) are the two types of `access control lists` (`ACLs`), each consisting of a `header` and zero or more `access control entries` (`ACEs`). (Throughout security literature, when the term `ACL` is used, it usually refers to `DACL`, especially for Windows systems.)

A [SACL](https://learn.microsoft.com/en-gb/windows/win32/ad/retrieving-an-objectampaposs-sacl) contains `ACEs` that dictate the types of access attempts that generate audit records in the `security event log` of a domain controller; therefore, a `SACL` allows administrators to log access attempts to `securable objects`. There are two types of `ACEs` within a `SACL`, `system audit` `ACEs` and `system audit-object` `ACEs`.

While a `DACL` holds `ACEs` that dictate what principals have control rights over a specific object. Internally within Windows, a `DACL` consists of an [ACL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl) followed by an ordered list of zero or more `ACEs` (the same applies to `SACLs`). Below is the struct definition of an `ACL` (recognizing these struct definitions will help us later on when viewing a `security descriptor` from the kernel's point of view):

Code: cpp

```cpp
typedef struct _ACL {
  BYTE AclRevision;
  BYTE Sbz1;
  WORD AclSize;
  WORD AceCount;
  WORD Sbz2;
} ACL;
```

## Generic and Object-specific ACEs

An [ACE](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/access-control-entry) contains a set of user rights and a `SID` that identifies a principal for whom the rights are allowed, denied, or audited. Below is the structure of a `generic ACE`:

![ACE_Structure.png](https://academy.hackthebox.com/storage/modules/219/ACE_Structure.png)

Windows represents an `ACE` internally via the struct [ACE_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header):

Code: cpp

```cpp
typedef struct _ACE_HEADER {
  BYTE AceType;
  BYTE AceFlags;
  WORD AceSize;
} ACE_HEADER;
```

In a `DACL`, there can be nine types of `ACEs`, each having the struct `ACE_HEADER` as a member, in addition to the [Mask](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask) member (which is of type [ACCESS_MASK](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask) and defines the standard, specific, and generic rights) and `SidStart` (which holds the first 32 bits of the trustee's `SID`):

- [Access Allowed](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace)
- [Access Denied](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_denied_ace)
- [Access Allowed Object](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace)
- [Access Denied Object](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_denied_object_ace)
- [Access Allowed Callback](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_callback_ace)
- [Access Denied Callback](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_denied_callback_ace)
- [Access Allowed Object Callback](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_callback_object_ace)
- [Conditional Claims](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-addconditionalace)

Four main types of `ACEs` are important for us to understand:

|ACE|Implication|
|:--|:--|
|[ACCESS_ALLOWED_ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace)|`Allows` a particular security principal (user or group) to access an `Active Directory object`, such as a user account or group. An `Access Allowed ACE` specifies which permissions the security principal can perform on the object, such as read, write, or modify.|
|[ACCESS_ALLOWED_OBJECT_ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace)|A specific type of `Access Allowed ACE` that is applied to an object and `grants access` to the object itself and any child objects it contains. An `Access Allowed Object ACE` can grant a security principal the necessary permissions to access an object and its child objects without applying separate `ACEs` to each child object.|
|[ACCESS_DENIED_ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_denied_ace)|`Denies` a particular security principal access to an `Active Directory object`, such as a user account or group. An `Access Denied ACE` specifies which permissions the security principal is not allowed to perform on the object, such as read, write, or modify.|
|[ACCESS_DENIED_OBJECT_ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_denied_object_ace)|A specific type of `Access Denied ACE` that is applied to an object and `restricts` access to the object itself and any child objects it contains. An `Access Denied Object ACE` prevents a security principal from accessing an object and its child objects without having to apply separate `ACEs` to each child object.|

As you may have noticed, some `ACEs` include the keyword `Object`, these are [object-specific ACEs](https://learn.microsoft.com/en-us/windows/win32/secauthz/object-specific-aces) used only within `Active Directory`. In addition to the members of `generic ACEs` structure, `object-specific ACEs` contain the members:

- `ObjectType`: A `GUID` containing a type of `child object`, a `property set` or `property`, an `extended right`, or a `validated write`.
- `InheritedObjectType`: Specifies the type of `child object` that can `inherit` the `ACE`.
- `Flags`: Indicates whether the members `ObjectType` and `InheritedObjectType` are present via a set of bit flags.

# Viewing DACLs of AD Objects Manually

After a brief understanding of the fields of a `security descriptor` and before we start auditing and enumerating `DACLs` with automated tools, let us inspect them manually for both AD and non-AD objects (specifcally, `processes`).

## Using dsacls

[dsacls](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771151\(v=ws.11\)) (the command-line equivalent to the `Security` tab in the `Properties` dialog box of `ADUC`) is a native Windows binary that can display and change `ACEs`/`permissions` in `ACLs` of AD objects. Let us view the `ACLs` for the user `Yolanda` within the domain `blackwood.local`:

#### Using dsacls to view the ACLs of Yolanda

```powershell-session
PS C:\Users\Administrator> dsacls.exe "cn=Yolanda,cn=users,dc=Blackwood,dc=local"

Owner: BLACKWOOD\Domain Admins
Group: BLACKWOOD\Domain Admins

Access list:
Allow BLACKWOOD\Domain Admins     FULL CONTROL
Allow BUILTIN\Account Operators       FULL CONTROL
Allow NT AUTHORITY\Authenticated Users
                                      SPECIAL ACCESS
                                      READ PERMISSONS
Allow NT AUTHORITY\SELF               SPECIAL ACCESS
                                      READ PERMISSONS
                                      LIST CONTENTS
                                      READ PROPERTY
                                      LIST OBJECT
Allow NT AUTHORITY\SYSTEM             FULL CONTROL
Allow BUILTIN\Pre-Windows 2000 Compatible Access
                                      SPECIAL ACCESS   <Inherited from parent>
                                      READ PERMISSONS
                                      LIST CONTENTS
                                      READ PROPERTY
                                      LIST OBJECT
Allow BLACKWOOD\luna              SPECIAL ACCESS   <Inherited from parent>
                                      WRITE PERMISSIONS
<SNIP>
```

We can be more specific by fetching out the permissions that other users have against `Yolanda`; for example, let us enumerate the permissions that `Pedro` only has over `Yolanda`:

#### Using dsacls to view the Permissions Pedro has over Yolanda

```powershell-session
PS C:\Users\Administrator> dsacls.exe "cn=Yolanda,cn=users,dc=Blackwood,dc=local" | Select-String "Pedro"

Allow BLACKWOOD\pedro             Reset Password
```

## Using PowerShell with DirectoryServices and ActiveDirectorySecurity

Now, we will do the same as above but with `PowerShell`. The [DirectorySearcher](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher?view=dotnet-plat-ext-7.0) class within the `.NET` [System.DirectoryServices](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices?view=dotnet-plat-ext-7.0) namespace contains the [SecurityMasks](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher.securitymasks?view=dotnet-plat-ext-7.0#system-directoryservices-directorysearcher-securitymasks) property that will allow us to access the `DACL` of the object's `security descriptor`. First, we need to get the `security descriptor` of the AD object `Yolanda` as a binary blob:

```powershell-session
PS C:\Users\Administrator> $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher('(samaccountname=Yolanda)')
PS C:\Users\Administrator> $directorySearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner
PS C:\Users\Administrator> $binarySecurityDescriptor = $directorySearcher.FindOne().Properties.ntsecuritydescriptor[0]
PS C:\Users\Administrator> Write-Host -NoNewline $binarySecurityDescriptor

1 0 4 140 44 7 0 0 0 0 0 0 0 0 0 0 20 0 0 0 4 0 24 7 42 0 0 0 5 0 56 0 0 1 0 0 1 0 0 
```

Now that we have the `security descriptor` for `Yolanda` as a binary blob, we need to parse it using the function [SetSecurityDescriptorBinaryForm](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setsecuritydescriptorbinaryform?) from the class [ActiveDirectorySecurity](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurity?view=windowsdesktop-8.0). Then we can view all of the `ACEs` of `Yolanda`:

```powershell-session
PS C:\Users\Administrator> $parsedSecurityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
PS C:\Users\Administrator> $parsedSecurityDescriptor.SetSecurityDescriptorBinaryForm($binarySecurityDescriptor)
PS C:\Users\Administrator> $parsedSecurityDescriptor.Access


ActiveDirectoryRights : GenericRead
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SELF
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : ReadControl
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\Authenticated Users
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : GenericAll
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SYSTEM
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

<SNIP>
```

We can also be more specific and fetch out the permissions that `Pedro` only has over `Yolanda`:

#### Using PowerShell to view the Permissions Pedro has over Yolanda

```powershell-session
PS C:\Users\Administrator> $parsedSecurityDescriptor.Access | Where-Object {$_.IdentityReference -like '*Pedro*'}


ActiveDirectoryRights : ExtendedRight
InheritanceType       : None
ObjectType            : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BLACKWOOD\pedro
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None
```

# Viewing DACLs of Processes

## Local Kernel Debugging

To view the `DACL` of the process `explorer.exe` internally, we need to deference the `SecurityDescriptor` pointer within the `ObjectHeader` member of `explorer.exe` (which can be done with `local kernel debugging` and [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg)). This will enable us to examine how the Windows kernel sees a `security descriptor`:

Code: dbgcmd

```dbgcmd
lkd> !sd 0xffffd08f`3b15a12f & -10

->Revision: 0x1
->Sbz1    : 0x0
->Control : 0x8814
            SE_DACL_PRESENT
            SE_SACL_PRESENT
            SE_SACL_AUTO_INHERITED
            SE_SELF_RELATIVE
->Owner   : S-1-5-21-1220085036-3517073048-2454771104-1008
->Group   : S-1-5-21-1220085036-3517073048-2454771104-513
->Dacl    : 
->Dacl    : ->AclRevision: 0x2
->Dacl    : ->Sbz1       : 0x0
->Dacl    : ->AclSize    : 0x5c
->Dacl    : ->AceCount   : 0x3
->Dacl    : ->Sbz2       : 0x0
->Dacl    : ->Ace[0]: ->AceType: ACCESS_ALLOWED_ACE_TYPE
->Dacl    : ->Ace[0]: ->AceFlags: 0x0
->Dacl    : ->Ace[0]: ->AceSize: 0x24
->Dacl    : ->Ace[0]: ->Mask : 0x001fffff
->Dacl    : ->Ace[0]: ->SID: S-1-5-21-1220085036-3517073048-2454771104-1008

->Dacl    : ->Ace[1]: ->AceType: ACCESS_ALLOWED_ACE_TYPE
->Dacl    : ->Ace[1]: ->AceFlags: 0x0
->Dacl    : ->Ace[1]: ->AceSize: 0x14
->Dacl    : ->Ace[1]: ->Mask : 0x001fffff
->Dacl    : ->Ace[1]: ->SID: S-1-5-18

->Dacl    : ->Ace[2]: ->AceType: ACCESS_ALLOWED_ACE_TYPE
->Dacl    : ->Ace[2]: ->AceFlags: 0x0
->Dacl    : ->Ace[2]: ->AceSize: 0x1c
->Dacl    : ->Ace[2]: ->Mask : 0x00121411
->Dacl    : ->Ace[2]: ->SID: S-1-5-5-0-191017

->Sacl    : 
->Sacl    : ->AclRevision: 0x2
->Sacl    : ->Sbz1       : 0x0
->Sacl    : ->AclSize    : 0x1c
->Sacl    : ->AceCount   : 0x1
->Sacl    : ->Sbz2       : 0x0
->Sacl    : ->Ace[0]: ->AceType: SYSTEM_MANDATORY_LABEL_ACE_TYPE
->Sacl    : ->Ace[0]: ->AceFlags: 0x0
->Sacl    : ->Ace[0]: ->AceSize: 0x14
->Sacl    : ->Ace[0]: ->Mask : 0x00000003
->Sacl    : ->Ace[0]: ->SID: S-1-16-8192
```

## Using AccessChk

[AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) is part of the [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/) suite that enables viewing the specific `access rights` granted to users or groups. For example, to view the `security descriptor` of the process `explorer.exe`, we can use the `-l` parameter:

Code: powershell

```powershell
PS C:\Users\Admin\Downloads\AccessChk> .\accesschk64.exe -p "explorer.exe" -l

Accesschk v6.15 - Reports effective permissions for securable objects
Copyright (C) 2006-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

[8992] explorer.exe
  DESCRIPTOR FLAGS:
      [SE_DACL_PRESENT]
      [SE_SACL_PRESENT]
      [SE_SACL_AUTO_INHERITED]
      [SE_SELF_RELATIVE]
  OWNER: 3L1T3\Admin
  LABEL: Medium Mandatory Level
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
        SYSTEM_MANDATORY_LABEL_NO_READ_UP
  [0] ACCESS_ALLOWED_ACE_TYPE: 3L1T3\Admin
        PROCESS_ALL_ACCESS
  [1] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
        PROCESS_ALL_ACCESS
  [2] ACCESS_ALLOWED_ACE_TYPE: 3L1T3\Admin-S-1-5-5-0-191017
        PROCESS_QUERY_INFORMATION
        PROCESS_QUERY_LIMITED_INFORMATION
        PROCESS_TERMINATE
        PROCESS_VM_READ
        SYNCHRONIZE
        READ_CONTROL
```

`DACLs`, as per our explanation, consist of an `ACL` data structure followed by an ordered list of zero or more `ACE` data structures. The only difference between the `DACLs` of AD objects and normal objects is the value that members such as `Mask` can have.

https://academy.hackthebox.com/course/preview/dacl-attacks-i-
DACLs Overview PREVIEW
- DACLs Enumeration
- Targeted Kerberoasting
- AddMembers
- Password Abuse
- Granting Rights and Ownership
- Shadow Credentials https://github.com/eladshamir/Whisker
- Logon Scripts
- SPN Jacking
- sAMAccountName Spoofing
- Introduction to GPOs
- GPO Attacks
- Detection and Mitigation Strategies for DACL Attacks
# Coming Next

After having a brief understanding of `security descriptors` and `DACLs`, we will go over how to enumerate and audit `DACLs` of objects within an AD environment using automated tools such as `dacledit.py`, `PowerView`, and `BloodHound`.

## Sections

- DACLs Overview PREVIEW
- DACLs Enumeration
- Targeted Kerberoasting
- AddMembers
- Password Abuse
- Granting Rights and Ownership
- Skills Assessment


Within the complex landscape of Windows security, understanding which types of Discretionary Access Control Lists (DACLs) can be abused is vital for both defenders and attackers. DACLs are an essential component of security descriptors, which dictate principals' permissions and access rights to system objects. This module will explore several attack techniques that exploit vulnerabilities related to DACLs, enabling students to understand better how DACL configurations can be abused.

Building on the foundational knowledge established in [DACL Attacks I](https://academy.hackthebox.com/module/details/219), this module covers more DACL abuse, continuing to explore techniques that exploit DACL misconfigurations, providing students with an understanding of how attackers leverage these vulnerabilities to compromise system security.

In this module, we will cover:

- `Shadow Credential Attacks`: These techniques utilize DACLs to add alternate credentials in the `msDS-KeyCredentialLink` attribute in Windows Active Directory to gain control over user or computer accounts.
- `Logon Scripts`: We examine how attackers can exploit DACLs governing logon scripts to execute arbitrary commands across multiple user sessions.
- `SPN Jacking`: This section explores the manipulation of Service Principal Names (SPNs) enabled by improper DACL configurations, which can lead to dangerous impersonation attacks within a domain.
- `GPO Understanding and Abuse`: Students will learn about the critical role of Group Policy Objects (GPOs) and how their DACL misconfigurations can lead to different attacks.
- `sAMAccountName Spoofing`: This topic addresses how DACL manipulation can allow attackers to change sAMAccountName attributes, impersonating domain controllers to escalate their privileges.

Other DACL attacks that were not covered on DACL I & II are included within other modules such as [Kerberos Attacks](https://academy.hackthebox.com/module/details/25), [Active Directory Enumeration and Attacks](https://academy.hackthebox.com/module/details/143), [Active Directory BloodHound](https://academy.hackthebox.com/module/details/69), etc.

As threats evolve and new attack vectors emerge, we are committed to continuously updating this module with the latest information and techniques related to DACL attacks. This commitment ensures that our content remains relevant and provides cutting-edge knowledge to counteract emerging security challenges in cybersecurity effectively.

## Coming Next

Our next step is to apply the concepts of DACL exploitation techniques through hands-on exercises. We will guide you in enumerating and abusing DACLs using Linux and Windows. This practical application will reinforce your theoretical understanding and equip you with the necessary skills to identify and mitigate DACL misconfigurations in real-world scenarios.