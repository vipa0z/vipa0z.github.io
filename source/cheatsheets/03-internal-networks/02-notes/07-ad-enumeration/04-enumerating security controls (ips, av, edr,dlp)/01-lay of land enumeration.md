## Am I Alone?

When landing on a host for the first time, one important thing is to check and see if you are the only one logged in. If you start taking actions from a host someone else is on, there is the potential for them to notice you. If a popup window launches or a user is logged out of their session, they may report these actions or change their password, and we could lose our foothold.

#### Using qwinsta

```powershell-session
PS C:\htb> qwinsta

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
>console           forend                    1  Active
 rdp-tcp                                 65536  Listen
```

Now that we have a solid feel for the state of our host, we can enumerate the network settings for our host and identify any potential domain machines or services we may want to target next.

## Network Information

| **Networking Commands**              | **Description**                                                                                                  |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `arp -a`                             | Lists all known hosts stored in the arp table.                                                                   |
| `ipconfig /all`                      | Prints out adapter settings for the host. We can figure out the network segment from here.                       |
| `route print`                        | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| `netsh advfirewall show allprofiles` | Displays the status of the host's firewall. We can determine if it is active and filtering traffic.              |

Commands such as `ipconfig /all` and `systeminfo` show us some basic networking configurations. Two more important commands provide us with a ton of valuable data and could help us further our access. `arp -a` and `route print` will show us what hosts the box we are on is aware of and what networks are known to the host. Any networks that appear in the routing table are potential avenues for lateral movement because they are accessed enough that a route was added, or it has administratively been set there so that the host knows how to access resources on the domain. These two commands can be especially helpful in the discovery phase of a black box assessment where we have to limit our scanning

#### Using arp -a

```powershell-session
PS C:\htb> arp -a

Interface: 172.16.5.25 --- 0x8
  Internet Address      Physical Address      Type
  172.16.5.5            00-50-56-b9-08-26     dynamic
  172.16.5.130          00-50-56-b9-f0-e1     dynamic
  172.16.5.240          00-50-56-b9-9d-66     dynamic
  224.0.0.22            01-00-5e-00-00-16     static

  255.255.255.255       ff-ff-ff-ff-ff-ff     static
```

#### Viewing the Routing Table

```powershell-session
PS C:\htb> route print

===========================================================================
Interface List
  8...00 50 56 b9 9d d9 ......vmxnet3 Ethernet Adapter #2
 12...00 50 56 b9 de 92 ......vmxnet3 Ethernet Adapter

<SNIP>
```

Using `arp -a` and `route print` will not only benefit in enumerating AD environments, but will also assist us in identifying opportunities to pivot to different network segments in any environment. These are commands we should consider using on each engagement to assist our clients in understanding where an attacker may attempt to go following initial compromise.

---

## Windows Management Instrumentation (WMI)

[Windows Management Instrumentation (WMI)](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi) is a scripting engine that is widely used within Windows enterprise environments to retrieve information and run administrative tasks on local and remote hosts. For our usage, we will create a WMI report on domain users, groups, processes, and other information from our host and other domain hosts.

#### Quick WMI checks

| **Command**                                                                          | **Description**                                                                                        |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`                              | Prints the patch level and description of the Hotfixes applied                                         |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic host information to include any attributes within the list                              |
| `wmic process list /format:list`                                                     | A listing of all processes on host                                                                     |
| `wmic ntdomain list /format:list`                                                    | Displays information about the Domain and Domain Controllers                                           |
| `wmic useraccount list /format:list`                                                 | Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list`                                                       | Information about all local groups                                                                     |
| `wmic sysaccount list /format:list`                                                  | Dumps information about any system accounts that are being used as service accounts.                   |

Below we can see information about the domain and the child domain, and the external forest that our current domain has a trust with. This [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4) has some useful commands for querying host and domain info using wmic.

Living Off the Land

```powershell-session
PS C:\htb> wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress

Caption          Description      DnsForestName           DomainControllerAddress  DomainName
MS01  MS01
BLACKWOOD    BLACKWOOD    blackwood.local     \\172.16.5.5             BLACKWOOD
LOGISTICS        LOGISTICS        blackwood.local     \\172.16.5.240           LOGISTICS
FREIGHTLOGISTIC  FREIGHTLOGISTIC  FREIGHTLOGISTICS.LOCAL  \\172.16.5.238           FREIGHTLOGISTIC
```

WMI is a vast topic, and it would be impossible to touch on everything it is capable of in one part of a section. For more information about WMI and its capabilities, check out the official [WMI documentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/using-wmi).

---

## Net Commands

[Net](https://docs.microsoft.com/en-us/windows/win32/winsock/net-exe-2) commands can be beneficial to us when attempting to enumerate information from the domain. These commands can be used to query the local host and remote hosts, much like the capabilities provided by WMI. We can list information such as:

- Local and domain users
- Groups
- Hosts
- Specific users in groups
- Domain Controllers
- Password requirements

We'll cover a few examples below. Keep in mind that `net.exe` commands are typically monitored by EDR solutions and can quickly give up our location if our assessment has an evasive component. Some organizations will even configure their monitoring tools to throw alerts if certain commands are run by users in specific OUs, such as a Marketing Associate's account running commands such as `whoami`, and `net localgroup administrators`, etc. This could be an obvious red flag to anyone monitoring the network heavily.

#### Table of Useful Net Commands

| **Command**                                        | **Description**                                                                                                              |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `net accounts`                                     | Information about password requirements                                                                                      |
| `net accounts /domain`                             | Password and lockout policy                                                                                                  |
| `net group /domain`                                | Information about domain groups                                                                                              |
| `net group "Domain Admins" /domain`                | List users with domain admin privileges                                                                                      |
| `net group "domain computers" /domain`             | List of PCs connected to the domain                                                                                          |
| `net group "Domain Controllers" /domain`           | List PC accounts of domains controllers                                                                                      |
| `net group <domain_group_name> /domain`            | User that belongs to the group                                                                                               |
| `net groups /domain`                               | List of domain groups                                                                                                        |
| `net localgroup`                                   | All available groups                                                                                                         |
| `net localgroup administrators /domain`            | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |
| `net localgroup Administrators`                    | Information about a group (admins)                                                                                           |
| `net localgroup administrators [username] /add`    | Add user to administrators                                                                                                   |
| `net share`                                        | Check current shares                                                                                                         |
| `net user <ACCOUNT_NAME> /domain`                  | Get information about a user within the domain                                                                               |
| `net user /domain`                                 | List all users of the domain                                                                                                 |
| `net user %username%`                              | Information about the current user                                                                                           |
| `net use x: \computer\share`                       | Mount the share locally                                                                                                      |
| `net view`                                         | Get a list of computers                                                                                                      |
| `net view /all /domain[:domainname]`               | Shares on the domains                                                                                                        |
| `net view \computer /ALL`                          | List shares of a computer                                                                                                    |
| <br><br><br><br><br><br><br><br>`net view /domain` | List of PCs of the domain                                                                                                    |

#### Listing Domain Groups

Living Off the Land

```powershell-session
PS C:\htb> net group /domain

The request will be processed at a domain controller for domain blackwood.local.

Group Accounts for \\DC01.blackwood.local
-------------------------------------------------------------------------------
*$H25000-1RTRKC5S507F
*Accounting
*Barracuda_all_access
*Barracuda_facebook_access
*Barracuda_parked_sites
*Barracuda_youtube_exempt
*Billing
*Billing_users
*Calendar Access
*CEO
*CFO
*Cloneable Domain Controllers
*Collaboration_users
*Communications_users
*Compliance Management
*Computer Group Management
*Contractors
*CTO

<SNIP>
```

We can see above the `net group` command provided us with a list of groups within the domain.

#### Information about a Domain User

```powershell-session
PS C:\htb> net user /domain wrouse

The request will be processed at a domain controller for domain blackwood.local.

User name                    wrouse
Full Name                    Christopher Davis
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/27/2021 10:38:01 AM
Password expires             Never
Password changeable          10/28/2021 10:38:01 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *File Share G Drive   *File Share H Drive
                             *Warehouse            *Printer Access
                             *Domain Users         *VPN Users
                             *Shared Calendar Read
The command completed successfully.
```

#### Net Commands Trick

If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.

#### Running Net1 Command

![image](https://academy.hackthebox.com/storage/modules/143/net1userreal.png)

---

## Dsquery

[Dsquery](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11)>) is a helpful command-line tool that can be utilized to find Active Directory objects. The queries we run with this tool can be easily replicated with tools like BloodHound and PowerView, but we may not always have those tools at our disposal, as discussed at the beginning of the section. But, it is a likely tool that domain sysadmins are utilizing in their environment. With that in mind, `dsquery` will exist on any host with the `Active Directory Domain Services Role` installed, and the `dsquery` DLL exists on all modern Windows systems by default now and can be found at `C:\Windows\System32\dsquery.dll`.

#### Dsquery DLL

All we need is elevated privileges on a host or the ability to run an instance of Command Prompt or PowerShell from a `SYSTEM` context. Below, we will show the basic search function with `dsquery` and a few helpful search filters.

## FInding admin users with dsquery and ldap filters

with the help of claude

```
dsquery * "CN=Betty Ross,OU=IT Admins,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL" -attr *
```

#### OID match strings

OIDs are rules used to match bit values with attributes, as seen above. For LDAP and AD, there are three main matching rules:

1. `1.2.840.113556.1.4.803`

When using this rule as we did in the example above, we are saying the bit value must match completely to meet the search requirements. Great for matching a singular attribute.

2. `1.2.840.113556.1.4.804`

When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches. This works in the case of an object having multiple attributes set.

3. `1.2.840.113556.1.4.1941`

This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.

#### User Search

```powershell-session
PS C:\htb> dsquery user

"CN=Administrator,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Guest,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=lab_adm,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=krbtgt,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Htb Student,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Annie Vazquez,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Paul Falcon,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Fae Anthony,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Walter Dillard,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Louis Bradford,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Sonya Gage,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Alba Sanchez,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Daniel Branch,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Christopher Cruz,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Nicole Johnson,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Mary Holliday,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Michael Shoemaker,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Arlene Slater,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=Kelsey Prentiss,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
```

#### Computer Search

Living Off the Land

```powershell-session
PS C:\htb> dsquery computer

"CN=DC01,OU=Domain Controllers,DC=BLACKWOOD,DC=LOCAL"
"CN=MS01,OU=Web Servers,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=MX01,OU=Mail,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=SQL01,OU=SQL Servers,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=ILF-XRG,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=MAINLON,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=CISERVER,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=INDEX-DEV-LON,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=SQL-0253,OU=SQL Servers,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=NYC-0615,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=NYC-0616,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=NYC-0617,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=NYC-0618,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=NYC-0619,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=NYC-0620,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=NYC-0621,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=NYC-0622,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=NYC-0623,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=LON-0455,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=LON-0456,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=LON-0457,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
"CN=LON-0458,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=BLACKWOOD,DC=LOCAL"
```

We can use a [dsquery wildcard search](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232(v=ws.11)>) to view all objects in an OU, for example.

#### Wildcard Search

Living Off the Land

```powershell-session
PS C:\htb> dsquery * "CN=Users,DC=BLACKWOOD,DC=LOCAL"

"CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=krbtgt,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Domain Computers,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Domain Controllers,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Schema Admins,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Enterprise Admins,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Cert Publishers,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Domain Admins,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Domain Users,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Domain Guests,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Group Policy Creator Owners,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=RAS and IAS Servers,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Allowed RODC Password Replication Group,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Denied RODC Password Replication Group,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Read-only Domain Controllers,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Enterprise Read-only Domain Controllers,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Cloneable Domain Controllers,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Protected Users,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Key Admins,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Enterprise Key Admins,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=DnsAdmins,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=DnsUpdateProxy,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=certsvc,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=Jessica Ramsey,CN=Users,DC=BLACKWOOD,DC=LOCAL"
"CN=svc_vmwaresso,CN=Users,DC=BLACKWOOD,DC=LOCAL"

<SNIP>
```

We can, of course, combine `dsquery` with LDAP search filters of our choosing. The below looks for users with the `PASSWD_NOTREQD` flag set in the `userAccountControl` attribute.

#### Users With Specific Attributes Set (PASSWD_NOTREQD)

Living Off the Land

```powershell-session
PS> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

  distinguishedName                                                                              userAccountControl
  CN=Guest,CN=Users,DC=BLACKWOOD,DC=LOCAL                                                    66082
  CN=Marion Lowe,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL      66080
  CN=Yolanda Groce,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL    66080
  CN=Eileen Hamilton,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=BLACKWOOD,DC=LOCAL    66080
  CN=Jessica Ramsey,CN=Users,DC=BLACKWOOD,DC=LOCAL                                           546
  CN=NAGIOSAGENT,OU=Service Accounts,OU=Corp,DC=BLACKWOOD,DC=LOCAL                           544
  CN=LOGISTICS$,CN=Users,DC=BLACKWOOD,DC=LOCAL                                               2080
  CN=FREIGHTLOGISTIC$,CN=Users,DC=BLACKWOOD,DC=LOCAL                                         2080
```

The below search filter looks for all Domain Controllers in the current domain, limiting to five results.

#### Searching for Domain Controllers

Living Off the Land

```powershell-session
PS> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

 sAMAccountName
 DC01$
```

### LDAP Filtering Explained

You will notice in the queries above that we are using strings such as `userAccountControl:1.2.840.113556.1.4.803:=8192`. These strings are common LDAP queries that can be used with several different tools too, including AD PowerShell, ldapsearch, and many others. Let's break them down quickly:

`userAccountControl:1.2.840.113556.1.4.803:` Specifies that we are looking at the [User Account Control (UAC) attributes](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) for an object. This portion can change to include three different values we will explain below when searching for information in AD (also known as [Object Identifiers (OIDs)](https://ldap.com/ldap-oid-reference-guide/).  
`=8192` represents the decimal bitmask we want to match in this search. This decimal number corresponds to a corresponding UAC Attribute flag that determines if an attribute like `password is not required` or `account is locked` is set. These values can compound and make multiple different bit entries. Below is a quick list of potential values.

#### UAC Values

![text](https://academy.hackthebox.com/storage/modules/143/UAC-values.png)

#### OID match strings

OIDs are rules used to match bit values with attributes, as seen above. For LDAP and AD, there are three main matching rules:

1. `1.2.840.113556.1.4.803`

When using this rule as we did in the example above, we are saying the bit value must match completely to meet the search requirements. Great for matching a singular attribute.

2. `1.2.840.113556.1.4.804`

When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches. This works in the case of an object having multiple attributes set.

3. `1.2.840.113556.1.4.1941`

This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.

#### Logical Operators

When building out search strings, we can utilize logical operators to combine values for the search. The operators `&` `|` and `!` are used for this purpose. For example we can combine multiple [search criteria](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax) with the `& (and)` operator like so:  
`(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))`

The above example sets the first criteria that the object must be a user and combines it with searching for a UAC bit value of 64 (Password Can't Change). A user with that attribute set would match the filter. You can take this even further and combine multiple attributes like `(&(1) (2) (3))`. The `!` (not) and `|` (or) operators can work similarly. For example, our filter above can be modified as follows:  
`(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))`

This would search for any user object that does `NOT` have the Password Can't Change attribute set. When thinking about users, groups, and other objects in AD, our ability to search with LDAP queries is pretty extensive.

A lot can be done with UAC filters, operators, and attribute matching with OID rules. For now, this general explanation should be sufficient to cover this module. For more information and a deeper dive into using this type of filter searching, see the [Active Directory LDAP](https://academy.hackthebox.com/course/preview/active-directory-ldap) module.

---

We have now used our foothold to perform credentialed enumeration with tools on Linux and Windows attack hosts and using built-in tools and validated host and domain information. We have proven that we can access internal hosts, password spraying, and LLMNR/NBT-NS poisoning works and that we can utilize tools that already reside on the hosts to perform our actions. Now we will take it a step further and tackle a TTP every AD pentester should have in their toolbelt, `Kerberoasting`.

look for disabled accounts

```
wmic useraccount list /format:list | Select-String -Pattern "Name|Disabled|Status"
```

### Check existence of GPP files

## Group Policy Preferences (GPP) Passwords

When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to. These files can include those used to:

- Map drives (drives.xml)
- Create local users
- Create printer config files (printers.xml)
- Creating and updating services (services.xml)
- Creating scheduled tasks (scheduledtasks.xml)
- Changing local admin passwords.

These files can contain an array of configuration data and defined passwords. The `cpassword` attribute value is AES-256 bit encrypted, but Microsoft [published the AES private key on MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN), which can be used to decrypt the password. Any domain user can read these files as they are stored on the SYSVOL share, and all authenticated users in a domain, by default, have read access to this domain controller share.

This was patched in 2014 [MS14-025 Vulnerability in GPP could allow elevation of privilege](https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30), to prevent administrators from setting passwords using GPP. The patch does not remove existing Groups.xml files with passwords from SYSVOL. If you delete the GPP policy instead of unlinking it from the OU, the cached copy on the local computer remains.

The XML looks like the following:

#### Viewing Groups.xml

![image](https://academy.hackthebox.com/storage/modules/143/GPP.png)

GPP passwords can be located by searching or manually browsing the SYSVOL

```shell-session
$ nxc smb -L | grep gpp
```

If you retrieve the cpassword value more manually, the `gpp-decrypt` utility can be used to decrypt the password as follows:

```
$ gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```

#### Decrypting the Password with gpp-decrypt

card: how to view logged on users?::using nxc `--loggedon-users`

card: how do you read all shares fast?:: using cme module with ` -Mc spider_plus` `spider_plus` will dig through each readable share on the host and list all readable files.

How do you get password Policy for a domain?:: cme `--pass-pol`

what other tools can be used to enumerate samba shares?:: smbmap
