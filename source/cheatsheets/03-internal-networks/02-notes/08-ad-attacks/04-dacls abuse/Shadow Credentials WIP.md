[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) refers to an Active Directory attack that abuses the [msDS-KeyCredentialLink](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c) attribute of a victim user. This attribute stores public keys that can be used for authentication via PKINIT. In BloodHound, the `AddKeyCredentialLink` edge indicates that one user has write permissions over another user's `msDS-KeyCredentialLink` attribute, allowing them to take control of that user.

![Diagram showing a connection between two users, wwhite@blackwood.locall and jpinkman@blackwood.locall, labeled "AddKeyCredentialLink."](https://academy.hackthebox.com/storage/modules/308/img/PtC_2.png)

We can use [pywhisker](https://github.com/ShutdownRepo/pywhisker) to perform this attack from a Linux system. The command below generates an `X.509 certificate` and writes the `public key` to the victim user's `msDS-KeyCredentialLink` attribute:

```shell-session
$ pywhisker --dc-ip 10.129.234.109 -d blackwood.local -u wwhite -p 'package5shores_topher1' --target jpinkman --action add
```

we can see that a `PFX (PKCS12)` file was created (`eFUVVTPf.pfx`), and the password is shown. We will use this file with `gettgtpkinit.py` to acquire a TGT as the victim:

```shell-session
$ python3 gettgtpkinit.py -cert-pfx ../eFUVVTPf.pfx -pfx-pass 'bmRH4LK7UwPrAOfvIx6W' -dc-ip 10.129.234.109 blackwood.local/jpinkman /tmp/jpinkman.ccache
```

With the TGT obtained, we may once again `pass the ticket`:

Pass the Certificate

```shell-session
$ export KRB5CCNAME=/tmp/jpinkman.ccache
$ klist
```

In this case, we discovered that the victim user is a member of the `Remote Management Users` group, which permits them to connect to the machine via `WinRM`.

```shell-session
$ evil-winrm -i dc01.blackwood.local -r blackwood.local
```

## No PKINIT?

In certain environments, an attacker may be able to obtain a certificate but be unable to use it for pre-authentication as specific victims (e.g., a domain controller machine account) due to the KDC not supporting the appropriate EKU. The tool [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/) was created for such situations. It can be used to authenticate against LDAPS using a certificate and perform various attacks (e.g., changing passwords or granting DCSync rights). This attack is outside the scope of this module but is worth reading about [here](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html).
