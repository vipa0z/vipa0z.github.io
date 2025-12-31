## DNS Scanning

```
dnsRecon ip
```

### DNS ZONE TRANSF LOCALLY

`/etc/hosts`
`ip ilf.htb`

`echo 'ip' > resolvers.txt`
subrute -s names.txt -r resolvers.txt
-> new subdomain name server
`dig axfr new.ilf.htb @ip`
you try to find subdomains with subtree
u then add the entries to /etc/hosts
u then dig them dig axfr ns1.ilfr.htb

## DNS Zones

- A DNS zone is a portion of the DNS namespace that a specific organization or administrator manages. Since DNS comprises multiple DNS zones, DNS servers utilize DNS zone transfers to copy a portion of their database to another DNS server.
- An attacker could leverage this DNS zone transfer vulnerability to learn more about the target organization's DNS namespace, increasing the attack surface. For exploitation, we can use the `dig` utility with DNS query type `AXFR` option to dump the entire DNS namespaces from a vulnerable DNS server:

```shell-session
$ dig AXFR @ns1.blackwood.com blackwood.com
```

Tools like [Fierce](https://github.com/mschwager/fierce) can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer:

```shell-session
$ fierce --domain zonetransfer.me
```

---

## Domain and subdomain takeovers

`Domain takeover` is registering a non-existent domain name to gain control over another domain. If attackers find an expired domain, they can claim that domain to perform further attacks such as hosting malicious content on a website or sending a phishing email leveraging the claimed domain.
`basically any subdomain is considered as domain` therefore it can be called domain takeover aswell as subdomain takeover

Domain takeover is also possible with Attacks called `subdomain takeover`. A DNS's canonical name (`CNAME`) record is used to map different domains to a parent domain. Many organizations use third-party services like AWS, GitHub, Akamai, Fastly, and other content delivery networks (CDNs) to host their content. In this case, they usually create a subdomain and make it point to those services. For example,

```shell-session
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

The domain name (e.g., `sub.target.com`) uses a CNAME record to another domain (e.g., `anotherdomain.com`). Suppose the `anotherdomain.com` expires and is available for anyone to claim the domain since the `target.com`'s DNS server has the `CNAME` record. In that case, anyone who registers `anotherdomain.com` will have complete control over `sub.target.com` until the DNS record is updated.

#### Subdomain Enumeration

```shell-session
# ./subfinder -d Blackwood.com -v
```

#### Subbrute

**resolvers** — think of them like different public DNS servers (Google, Cloudflare, OpenDNS, etc.).
add hosts entries for the resolvers

```
ip ns.ilfright.htb
```

```shell-session
$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
$ cd subbrute
$ echo "ns1.blackwood.com" > ./resolvers.txt
```

now point to the domain name which will be bruteforced against the resolver server (name server)

```
[★]$ python3 subbrute.py blackwood.com -s ./names.txt -r ./resolvers.tx
File not found: ./resolvers.tx
┌─[eu-academy-6]─[10.10.15.254]─[
```

```
./subbrute Blackwood.com -s ./names.txt -r ./resolvers.tx
```

use `/etc/hosts` and add entry for every subdomain u find

# DNS SPOOFING (MITM)

Ettercap’s DNS spoof plugin listens for DNS requests on the network and replies **faster** than the real DNS server with **fake responses**, pointing victims to attacker-controlled IPs (spoofed DNS responses). It typically works in combination with **ARP poisoning** to become a man-in-the-middle.

DNS spoofing is also referred to as DNS Cache Poisoning. This attack involves altering legitimate DNS records with false information so that they can be used to redirect online traffic to a fraudulent website.

### LOCAL

From a local network perspective, an attacker can also perform DNS Cache Poisoning using MITM tools like [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

To exploit the DNS cache poisoning via `Ettercap`, we should first edit the `/etc/ettercap/etter.dns` file to map the target domain name (e.g., `Blackwood.com`) that they want to spoof and the attacker's IP address (e.g., `192.168.225.110`) that they want to redirect a user to:

```shell-session
# cat /etc/ettercap/etter.dns

Blackwood.com      A   192.168.225.110
*.Blackwood.com    A   192.168.225.110
```

Next, start the `Ettercap` tool and scan for live hosts within the network by navigating to `Hosts > Scan for Hosts`. Once completed, add the target IP address (e.g., `192.168.152.129`) to Target1 and add a default gateway IP (e.g., `192.168.152.2`) to Target2.

![Ettercap interface showing host list with IP and MAC addresses. Highlighted entry: IP 192.168.152.129, MAC 00:0C:29:A7:9D:13. Options to delete or add host to targets.](https://academy.hackthebox.com/storage/modules/116/target.png)

Activate `dns_spoof` attack by navigating to `Plugins > Manage Plugins`. This sends the target machine with fake DNS responses that will resolve `Blackwood.com` to IP address `192.168.225.110`:

![Ettercap plugins list showing dns_spoof version 1.3, highlighted. Info: Sends spoofed DNS replies. Host 192.168.152.129 added to TARGET1.](https://academy.hackthebox.com/storage/modules/116/etter_plug.png)

After a successful DNS spoof attack, if a victim user coming from the target machine `192.168.152.129` visits the `Blackwood.com` domain on a web browser, they will be redirected to a `Fake page` that is hosted on IP address `192.168.225.110`:

![Browser window displaying URL 'http://Blackwood.com/' with text 'Fake page' on a blank webpage](https://academy.hackthebox.com/storage/modules/116/etter_site.png)

In addition, a ping coming from the target IP address `192.168.152.129` to `Blackwood.com` should be resolved to `192.168.225.110` as well:

Attacking DNS

```cmd-session
C:\>ping Blackwood.com

Pinging Blackwood.com [192.168.225.110] with 32 bytes of data:
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
```

---

## BAD SETTINGS

| **Option**        | **Description**                                                                |
| ----------------- | ------------------------------------------------------------------------------ |
| `allow-query`     | Defines which hosts are allowed to send requests to the DNS server.            |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| `allow-transfer`  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| `zone-statistics` | Collects statistical data of zones.                                            |

Zone Files

- There must be precisely one `SOA` record and at least one `NS` record

- If the administrator used a subnet for the `allow-transfer` option for testing purposes or as a workaround solution or set it to `any`, everyone would query the entire zone file at the DNS server. In addition, other zones can be queried, which may even show internal IP addresses and hostnames.

SOA records
contains administrative details about the zone. Here's what an SOA record typically includes:

1. Primary nameserver: The authoritative nameserver for the zone.
2. Responsible person: Email address of the domain administrator (with @ replaced by .).
3. example:

```shell-session
dig soa <DN>
;; AUTHORITY SECTION:
Blackwood.com.      900     IN      SOA     ns-161.awsdns-20.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400
```

bruteforcing to find subdomains using dns server

```title:find-sub-dnsenum
└──╼ [★]$ dnsenum --dnsserver 10.129.247.54 --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt --threads 90 dev.blackwood.com
```
