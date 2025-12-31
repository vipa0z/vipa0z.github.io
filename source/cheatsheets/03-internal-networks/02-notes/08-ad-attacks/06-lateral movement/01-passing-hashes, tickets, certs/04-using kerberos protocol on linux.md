## Kerberos on Linux

Windows and Linux use the same process to request a Ticket Granting Ticket (TGT) and Service Ticket (TGS). However, how they store the ticket information may vary depending on the Linux distribution and implementation.
As attackers, we may have several uses for a keytab file. The first thing we can do is impersonate a user using `kinit`.

## Ccache files (sessions)
Linux machines store Kerberos tickets as [ccache files](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) in the `/tmp` directory. By default, the location of the Kerberos ticket is stored in the environment variable `KRB5CCNAME`. This variable can identify if Kerberos tickets are being used or if the default location for storing Kerberos tickets is changed 
A credential cache or [ccache](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) file holds Kerberos credentials while they remain valid and, generally, while the user's session lasts. Once a user authenticates to the domain, a ccache file is created that stores the ticket information. The path to this file is placed in the `KRB5CCNAME` environment variable. This variable is used by tools that support Kerberos authentication to find the Kerberos data.

These [ccache files](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) are protected by specific read/write permissions, but a user with elevated privileges or root privileges could easily gain access to these tickets.
## keytabs (tickets)
#### a Linux domain-joined machine needs a ticket. The ticket is represented as a 
keytab file located by default at `/etc/krb5.keytab` and can only be read by the root user. If we gain access to this ticket, we can impersonate the computer account LINUX01$.BLACKWOOD.HTB

A [keytab](https://kb.iu.edu/d/aumh) is a file containing pairs of Kerberos principals and encrypted keys (which are derived from the Kerberos password). You can use a keytab file to authenticate to various remote systems using Kerberos without entering a password
[Keytab](https://kb.iu.edu/d/aumh) files commonly allow scripts to authenticate automatically using Kerberos without requiring human interaction or access to a password stored in a plain text file. For example, a script can use a keytab file to access files stored in the Windows share folder.

### What is Constrained Delegation?

**Constrained Delegation** is a security feature in Active Directory (AD) that allows you to specify which services an account (typically a service account) can impersonate a user to access on behalf of the user. This feature is used to control and limit the scope of delegation, reducing security risks.

#### Key Points:

1. **Impersonation Context**:
    
    - Delegation allows a service to impersonate a user and access other services on behalf of the user.
    - Example: A web application impersonates a user to retrieve data from a back-end database.

