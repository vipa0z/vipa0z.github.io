- The NTLM Authentication Protocol PREVIEW
- The NTLM Relay Attack
- NTLM Relay over SMB Attacks
- NTLMRelayx Use Cases
- NTLM Cross-protocol Relay Attacks
- Farming Hashes
- Authentication Coercion
- Advanced NTLM Relay Attacks Targeting Kerberos
- Advanced NTLM Relay Attacks Targeting AD CS
- Skills Assessment 

 NTLM relay is a powerful offensive technique attackers use to compromise Active Directory environments, allowing them to perform horizontal and vertical privilege escalation and move laterally across Active Directory networks, most importantly, without requiring an NTLM password hash or cleartext credentials for an account in the domain.

In this module, we will first understand the NTLM authentication protocol and the session security SSPI provides for NTLM sessions. Then, we will deep dive into the NTLM Relay attack and its phases, covering the many techniques and tools attackers use in each phase. Afterward, we will learn about and perform various NTLM post-relay attacks, starting with basic same-protocol relaying and mounting attacks such as SAM dumping. Then, we will move to advanced cross-protocol relay attacks and mounting attacks such as computer account creation and privilege escalation. Subsequently, we will learn about farming hashes and the paramount technique of authentication coercion, covering various tools. Armed with the power of authentication coercion, we will subsequently abuse the NTLM relay attack to conduct advanced attacks against Kerberos and ADCS, including RBCD abuse, Shadow Credentials, and ESC8/ESC11.
# The NTLM Authentication Protocol

---

During our engagements with Active Directory networks, we will encounter different authentication protocols hosts use, with Kerberos being the most common. However, another protocol, `NTLM`, is still widely used, despite its known vulnerabilities and cryptographic weaknesses. Understanding how `NTLM` works internally is crucial to attacking it effectively and increasing the likelihood of a successful engagement.

# NTLM

---

[NT Lan Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c50a85f0-5940-42d8-9e82-ed206902e919) (`NTLM`/[MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4)) is the name of a family of security protocols, consisting of `LM`, `NTLMv1`, and `NTLMv2`, used by application protocols on various Windows-based networks to authenticate remote users and optionally provide session security when requested by the application. The `NTLM` security protocols are all embedded protocols, meaning that although `NTLM` has messages and a state machine like other protocols, it does not have a network protocol stack layer. This nature of `NTLM` allows any protocol with a defined layer in the network stack (such as `SMB`, `HTTP`(`S`), and `LDAP`(`S`)) to utilize it. For the application protocol using it, `NTLMv2` provides three primary operations:

1. Authentication.
2. Message integrity, known as message `signing` in the `NTLM` terminology.
3. Message confidentiality, known as message `sealing` in the `NTLM` terminology.

`NTLM` is a challenge-response protocol that uses `nonces`, pseudo-random numbers generated for one-time use, as a defensive mechanism against replaying attacks. Although each protocol has two variants, `connection-oriented` and `connectionless`, we will primarily only be concerned about the former (refer to [Overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c50a85f0-5940-42d8-9e82-ed206902e919) in `MS-NLMP` to know the differences between the two).

Unlike normal protocol implementations, `NTLM` is best implemented as a function library that can be called by application protocols rather than as a layer in a network protocol stack. [Security Support Provider Interface](https://learn.microsoft.com/en-us/windows/win32/rpc/sspi-architectural-overview) (`SSPI`), the foundation of Windows authentication, is an API that allows connected applications to call one of several security providers to establish authenticated connections and to exchange data securely over those connections. A [security support provider](https://learn.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps-) (`SSP`) is a dynamic-link library (`DLL`) responsible for implementing the `SSPI` by exposing one or more security packages to applications; each security package provides mappings between an application's `SSPI` function calls and an actual security model's functions. These security packages support various security protocols, including [NTLM](https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm).

[NTLM SSP](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/security-support-provider-interface-architecture#BKMK_NTLMSSP) (located at `%Windir%\System32\msv1_0.dll`) is a binary messaging protocol utilized by `SSPI` to facilitate `NTLM` challenge-response authentication and to negotiate options for integrity and confidentiality. The `NTLM SSP` encompasses both the `NTLM` and `NTLMv2` authentication protocols. In this section, we will understand the details of the `NTLM` protocol's internal workings and state messages rather than discussing how `NTLM SSP` provides them to applications or transfers `NTLM` messages within a network.

Both domain-joined and workgroup computers can utilize `NTLM` for authentication; however, we will focus on the former because we will attack AD environments. While reading the rest of the section, always keep in mind the following:

- The `NTLM` version used on hosts, whether `NTLMv1` or `NTLMv2`, is [configured out-of-band](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level) before authentication.
- Using a secure mechanism, the client and server/DC share a secret key (the user's password's hash) before authentication.
- Neither plaintext credentials nor the shared secret key are sent over the wire.

## Authentication Workflow

The `NTLM` authentication workflow for domain-joined computers starts with the client exchanging implementation-specific application protocol messages with the server (where the desired service is), indicating that it wants to authenticate. Subsequently, the client and server exchange three `NTLM`-specific messages during authentication (embedded in application protocol messages):

1. [NEGOTIATE_MESSAGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2) (also known as `Type 1` message)
2. [CHALLENGE_MESSAGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786) (also known as `Type 2` message)
3. [AUTHENTICATE_MESSAGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce) (also known as `Type 3` message)

Once it receives the `AUTHENTICATE_MESSAGE`, and because it does not possess the client's secret key, the server delegates the verification of the user's identity to a DC (a procedure known as [Pass-through authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/70697480-f285-4836-9ca7-7bb52f18c6af)) by invoking [NetrLogonSamLogonWithFlags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/d17f1077-de4b-4fcd-8867-39068cb789f5), which contains [NETLOGON_NETWORK_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/e17b03b8-c1d2-43a1-98db-cf8d05b9c6a8), a data structure populated with the various fields that the DC requires to verify the user. If authentication is successful, the DC returns a [NETLOGON_VALIDATION_SAM_INFO4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/bccfdba9-0c38-485e-b751-d4de1935781d) data structure to the server, and the server establishes an authenticated session with the client; otherwise, the DC returns an error, and the server might return an error message to the client, or, it can simply terminate the connection.

The diagram below is [NTLM's pass-through authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/5bfd942e-7da5-494d-a640-f269a0e3cc5d):

![Domain-joined_Computers_NTLM_Authentication.png](https://academy.hackthebox.com/storage/modules/232/Domain-joined_Computers_NTLM_Authentication.png)

The only difference for workgroup authentication is that the server verifies the user's identity instead of delegating it to the DC:

![Workgroup_Computers_NTLM_Authentication.png](https://academy.hackthebox.com/storage/modules/232/Workgroup_Computers_NTLM_Authentication.png)

We will review the three main `NTLM` messages to understand what gets sent within them.

## NTLM Messages

Each `NTLM` message is variable-length, containing a fixed-length header and a variable-sized message payload. The header always starts with the `Signature` and `MessageType` fields, and depending on the latter, messages can have additional message-dependent fixed-length fields. A variable-length message payload follows these fields.

![NTLM_Message_Fields.png](https://academy.hackthebox.com/storage/modules/232/NTLM_Message_Fields.png)

|Field|Meaning|
|:--|:--|
|`Signature`|An 8-byte NULL-terminated ASCII string always set to [`N`, `T`, `L`, `M`, `S`, `S`, `P`, `\0`].|
|`MessageType`|A 4-byte unsigned integer always set to either `0x00000001` (`NtLmNegotiate`) to indicate that the `NTLM` message is a `NEGOTIATE_MESSAGE` or `0x00000002` (`NtLmChallenge`) to indicate that the `NTLM` message is a `CHALLENGE_MESSAGE` or `0x00000003` (`NtLmAuthenticate`) to indicate that the `NTLM` message is an `AUTHENTICATE_MESSAGE`.|
|`MessageDependentFields`|A variable-length field that contains the `NTLM` message contents.|
|`payload`|A variable-length field that contains a message-dependent number of individual payload messages, referenced by byte offsets in `MessageDependentFields`.|

### NEGOTIATE_MESSAGE

The [NEGOTIATE_MESSAGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2) is the first `NTLM`-specific message, sent by the client indicating that it wants to authenticate to the server and specifying its supported/requested `NTLM` options. It contains four message-dependent fixed-length fields. One important field to know about is `NegotiateFlags`; this 4-bytes field, present in all three `NTLM` messages and not exclusive to `NEGOTIATE_MESSAGE`, is a [NEGOTIATE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832) structure consisting of 32 1-bit flags that allow indicating which `NTLM` capabilities are supported/requested by the sender.

### CHALLENGE_MESSAGE

The [CHALLENGE_MESSAGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786) is the second `NTLM`-specific message, sent by the server to the client to state the `NTLM` options it can support and challenge the client to prove its identity. It contains six message-dependent fixed-length fields, two important to know about, `NegotiateFlags` and `ServerChallenge`. `NegotiateFlags` holds the flags the server has chosen from the options offered/requested by the client in `NegotiateFlags` of the `NEGOTIATE_MESSAGE`. At the same time, `ServerChallenge` is a 64-bit `nonce` that holds the `NTLM` challenge generated by the server.

Some tools, such as [NTLM Challenger](https://github.com/nopfor/ntlm_challenger), [ntlm-info](https://gitlab.com/Zer1t0/ntlm-info), [NTLMRecon](https://github.com/praetorian-inc/NTLMRecon), and [DumpNTLMInfo.py](https://github.com/fortra/impacket/blob/impacket_0_11_0/examples/DumpNTLMInfo.py) perform reconnaissance against endpoints/hosts that accept `NTLM` authentication by parsing the information returned within the `CHALLENGE_MESSAGE` (review its other fields to know why this is possible):

```shell-session
$ python3 examples/DumpNTLMInfo.py 172.16.117.3

Impacket v0.12.0.dev1+20230803.144057.e2092339 - Copyright 2023 Fortra

[+] SMBv1 Enabled   : False
[+] Prefered Dialect: SMB 3.0
[+] Server Security : SIGNING_ENABLED | SIGNING_REQUIRED
[+] Max Read Size   : 8.0 MB (8388608 bytes)
[+] Max Write Size  : 8.0 MB (8388608 bytes)
[+] Current Time    : 2023-08-14 17:39:26.822236+00:00
[+] Name            : DC01
[+] Domain          : BLACKWOOD
[+] DNS Tree Name   : blackwood.local
[+] DNS Domain Name : blackwood.local
[+] DNS Host Name   : DC01.blackwood.local
[+] OS              : Windows NT 10.0 Build 17763
[+] Null Session    : True
```

### AUTHENTICATE_MESSAGE

The [AUTHENTICATE_MESSAGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce) is the third and last `NTLM`-specific message, sent by the client to the server to prove its possession of the shared secret key. It contains nine message-dependent fixed-length fields, two important to know about, `LmChallengeResponseFields` and `NtChallengeResponseFields`. For the pseudocode provided by `MS-NLMP`, we will also refer to the relevant implementation of [impacket's NTLM](https://github.com/fortra/impacket/blob/master/impacket/ntlm.py).

#### NTLMv1 Response Calculation

If `NTLMSSP_NEGOTIATE_LM_KEY` (the `G` bit in [NEGOTIATE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832)) was agreed upon by the server and client in `NegotiateFlags`, then, if `NTLMv1` is used, `LmChallengeResponseFields` contains a [LM_RESPONSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/e3fee6d1-0d93-4020-84ab-ca4dc5405fc9) structure, otherwise, if `NTLMv2` is used, `LmChallengeResponseFields` will contain a [LMv2_RESPONSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/8659238f-f5a9-44ad-8ee7-f37d3a172e56) structure. `LM_RESPONSE` contains one field, which is `Response`, a 24-byte array of [unsigned char](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/050baef1-f978-4851-a3c7-ad701a90e54a) that contains the client's `LmChallengeResponse`. While for `LMv2_RESPONSE`, it contains two fields, `Response` and `ChallengeFromClient`; `Response` is a 16-byte array of unsigned char that contains the clients `LM` `challenge-response`, while `ChallengeFromClient` is an 8-byte array of unsigned char that contains a challenge generated by the client. To compute the `Response` field of `LM_RESPONSE` or `LMv2_RESPONSE`, `MS-NLMP` provides [pseudocode](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/1b72429a-d8b8-4a04-bc82-1eedc980b87a).

For [NTLMv1 authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5), [NTOWFv1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/780943e9-42e6-4dbe-aa87-1dce828ba82a#gt_7a2805fa-1dcd-4b4e-a8e4-2a2bcc8651e9) (used only by `NTLMv1` and implemented in the [compute_nthash](https://github.com/fortra/impacket/blob/9a8d27034eab20d23802730d0c69bf99356d8af1/impacket/ntlm.py#L759-L769) function), is an `NT LAN Manager` (`NT`) one-way function that creates a hash based on the user's password to generate a principal's security key: instead of using the user's plaintext password, the resultant hash of this function gets used in computing the response. [LMOWFv1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/780943e9-42e6-4dbe-aa87-1dce828ba82a#gt_fd74ef50-cb97-4acd-b537-4941bdd9e064) (implemented in the [compute_lmhash](https://github.com/fortra/impacket/blob/9a8d27034eab20d23802730d0c69bf99356d8af1/impacket/ntlm.py#L742C1-L747) function), used only by `LM` and `NTLMv1`, is an `NT LAN Manager` (`LM`) one-way function that also creates a hash based on the user's password to generate a principal's security key. The client uses these two functions to calculate the response it returns to the server; the [pseudocode](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5) for the response calculation is implemented in the function [computeResponseNTLMv1](https://github.com/fortra/impacket/blob/9a8d27034eab20d23802730d0c69bf99356d8af1/impacket/ntlm.py#L717-L740).

For `NtChallengeResponseFields`, if `NTLMv1` is used, `NtChallengeResponse` will contain an [NTLM_RESPONSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b88739c6-1266-49f7-9d22-b13923bd8d66) structure, otherwise, if `NTLMv2` is used, then `NtChallengeResponse` will contain a [NTLMv2_RESPONSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d43e2224-6fc3-449d-9f37-b90b55a29c80) structure; `NTLM_RESPONSE` contains one field, which is `Response`, a 24-byte array of unsigned char that contains the client's `NtChallengeResponse`. For `NTLMv2_RESPONSE`, it contains two fields, `Response` and a [NTLMv2_CLIENT_CHALLENGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b) structure; `Response` is a 16-byte array of unsigned char that contains the client's `NtChallengeResponse`, while `NTLMv2_CLIENT_CHALLENGE` is a variable-length byte array that contains eight fixed-length variables, including `ChallengeFromClient`. If we were to capture an `NTLMv1` hash using `Responder` (a powerful tool we will learn about in the next section), it will display it using the format `User::HostName:LmChallengeResponse:NtChallengeResponse:ServerChallenge`:

```shell-session
[SMB] NTLMv1 Client   : 172.19.117.36
[SMB] NTLMv1 Username : Support1
[SMB] NTLMv1 Hash     : Support1::WIN-OLMHXGAP0V2:e2dL3196O8f55fB6:Q49S19A2937J6XC3CKA418EI4958OHB9:xF2K324O5L6Q7V8C
```

#### NTLMv2 Response Calculation

For the response calculation of [NTLMv2 authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3), [NTOWFv2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/780943e9-42e6-4dbe-aa87-1dce828ba82a#gt_ba118c39-b391-4232-aafa-a876ee1e9265) and [LMOWFv2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/780943e9-42e6-4dbe-aa87-1dce828ba82a#gt_a043ea96-e876-4259-be4b-aa8d2335fdfe) (both are version-dependent and only used by `NTLMv2`, they are implemented in the functions [LMOWFv2](https://github.com/fortra/impacket/blob/9a8d27034eab20d23802730d0c69bf99356d8af1/impacket/ntlm.py#L896C1-L897) and [NTOWFv2](https://github.com/fortra/impacket/blob/9a8d27034eab20d23802730d0c69bf99356d8af1/impacket/ntlm.py#L889C1-L894), respectively) are the one-way functions used to create a hash based on the user's password to generate a principal's security key. With these two functions, the client calculates the response it returns to the server as described in [pseudocode](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3) (implemented in the function [computeResponseNTLMv2](https://github.com/fortra/impacket/blob/9a8d27034eab20d23802730d0c69bf99356d8af1/impacket/ntlm.py#L900-L937)). If we were to capture an `NTLMv2` hash using `Responder`, it will display it using the format `User::Domain:ServerChallenge:Response:NTLMv2_CLIENT_CHALLENGE`:

```shell-session
[SMB] NTLMv2-SSP Client   : 172.19.117.55
[SMB] NTLMv2-SSP Username : BLACKWOOD\Support2
[SMB] NTLMv2-SSP Hash     : Support2::BLACKWOOD:e2d2339638fc5fd6:D4979A923DD76BC3CFA418E94958E2B0:010100000000000000E0550D97CCD901509F9CE743AB58760000000002000800350034005800360001001E00570049004E002D00390038004B005100480054005300390048004200550004003400570049004E002D00390038004B00510048005400530039004800420055002E0035003400580036002E004C004F00430041004C000300140035003400580036002E004C004F00430041004C000500140035003400580036002E004C004F00430041004C000700080000E0550D97CCD901060004000200000008003000300000000000000000000000004000002DB95E9E27F0AD66CAA477372F555B500CFEA9C5A231FC68F0DA4FABFF76607E0A001000000000000000000000000000000000000900240063006900660073002F003100370032002E00310036002E003100310037002E00330030000000000000000000
```

# NTLM Session Security

---

If the client and server negotiate it, [session security](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d1c86e81-eb66-47fd-8a6f-970050121347) provides [message integrity](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/131b0062-7958-460e-bca5-c7a9f9086652) (`signing`) and [message confidentiality](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/115f9c7d-bc30-4262-ae96-254555c14ea6) (`sealing`). The `NTLM` protocol itself does not provide session security; instead, [SSPI](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/0776e9c8-1d92-488f-9219-10765d11c6b7) provides it. `NTLMv1`, supplanted by `NTLMv2`, does not support `sealing` but only `signing`; therefore, [Microsoft](https://support.microsoft.com/en-au/topic/security-guidance-for-ntlmv1-and-lm-network-authentication-da2168b6-4a31-0088-fb03-f081acde6e73) strongly recommends against its usage (and the deprecated `LM` authentication protocol also).

## Message Signing and Sealing

`Message signing` provides message integrity and helps against relay attacks; it is a critical security feature designed to enhance the security of messages sent between the client and server during `NTLM` communications. When `session signing` is negotiated, the client and server negotiate a `session key` to sign all messages exchanged. The `session key` is generated using a combination of the client's and server's challenge messages and the user's password hash. Once the session key is established, all messages between the client and server are signed using a `MAC`. The `MAC` is generated by applying a cryptographic algorithm to the message and the session key. The server can verify the `MAC` by using the same algorithm as the message and the session key and comparing the result to the `MAC` provided by the client. Although an adversary might be eavesdropping, they don't possess the user's password hash since it is never transmitted over the wire, and therefore cannot sign messages. Based on the blog post [The Basics of SMB Signing (covering both SMB1 and SMB2)](https://learn.microsoft.com/en-us/archive/blogs/josebda/the-basics-of-smb-signing-covering-both-smb1-and-smb2), we can know the default `SMB signing` settings for hosts in the network depending on the SMB version they are running. Except for `SMB1`, which has three possible settings, `Required`, `Enabled`, or `Disabled`, `SMB2` and `SMB3` only have `Required` or `Not Required`:

|**Host**|**Default Signing Setting**|
|---|---|
|`SMB1 Client`|`Enabled`|
|`SMB1 Server`|`Disabled`|
|`SMB2 & SMB3 Clients`|`Not Required`|
|`SMB2 & SMB3 Servers`|`Not Required`|
|`Domain Controllers`|`Required`|

Due to the ever-lasting abuse of the default SMB signing settings by adversaries, [Microsoft](https://blogs.windows.com/windows-insider/2023/06/02/announcing-windows-11-insider-preview-build-25381/) released an update to enforce SMB `signing` on Windows 11 Insider editions (and later on for major releases). Microsoft decided, for a better security stature, to finally let go of the legacy behavior where Windows 10 and 11 required SMB `signing` by default only when connecting to shares named `SYSVOL` and `NETLOGON` and where DCs required SMB `signing` when any client connected to them. Ned Pyle, a Principal Program Manager at Microsoft, wrote the following regretful statement in the post [SMB signing required by default in Windows Insider](https://techcommunity.microsoft.com/t5/storage-at-microsoft/smb-signing-required-by-default-in-windows-insider/ba-p/3831704):

"SMB encryption is far more secure than signing, but environments still run legacy systems that don't support SMB 3.0 and later. If I could time travel to the 1990s, SMB signing would've always been on and we'd have introduced SMB encryption much sooner; sadly, I was both in high school and not in charge. We'll continue to push out more secure SMB defaults and many new SMB security options in the coming years; I know they can be painful for application compatibility and Windows has a legacy of ensuring ease of use, but security cannot be left to chance."

`Message sealing` provides message confidentiality by implementing a symmetric-key encryption mechanism; it ensures that the content of the messages exchanged between the client and server remains secure and that adversaries cannot read or tamper with them. In the context of `NTLM`, `sealing` also implies `signing` because every `sealed` message is also `signed`.

## Extended Protection for Authentication (EPA)

`Extended Protection for Authentication` (`EPA`), based on [RFC 5056](https://datatracker.ietf.org/doc/html/rfc5056), is a feature introduced in Windows Server 2008 and later versions that enhance the security of `NTLM` authentication. When `EPA` is enabled, the client and server establish a secure channel using a `channel binding token` (`CBT`). The `CBT` binds the authentication to the specific channel characteristics, such as the IP address and port, preventing the authentication from replaying on a different channel. `EPA` is designed to work with SMB and HTTP protocols, providing additional security for applications and services that rely on `NTLM` authentication; however, it requires the client and server to support it to establish a secure channel.
