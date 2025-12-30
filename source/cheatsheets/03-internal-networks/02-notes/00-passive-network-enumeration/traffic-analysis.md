
## Identifying Hosts

First, let's take some time to listen to the network and see what's going on. e can use `Wireshark` and `TCPDump` to "put our ear to the wire" 

```shell-session
 $ sudo -E wireshark
```
notice some [ARP](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) requests and replies, [MDNS](https://en.wikipedia.org/wiki/Multicast_DNS), and other basic [layer two](https://www.juniper.net/documentation/us/en/software/junos/multicast-l2/topics/topic-map/layer-2-understanding.html) packets in the broadcast domain
- ARP packets make us aware of the hosts: xxxx, xxxxx, x.x.x.x
- MDNS makes us aware of the Server hosts. like: WEB0.ACAD
## tcpdump
We can also use tcpdump to save a capture to a .pcap file, transfer it to another host, and open it in Wireshark.
```shell-session
sudo tcpdump -i ens224 
```
## Responder in view mode

```bash
sudo responder -I ens224 -A 
```
## Wireshark

| Wireshark filter                                  | Description                                                                                                                                                                          |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ip.addr == 56.48.210.13`                         | Filters packets with a specific IP address                                                                                                                                           |
| `tcp.port == 80`                                  | Filters packets by port (HTTP in this case).                                                                                                                                         |
| `http`                                            | Filters for HTTP traffic.                                                                                                                                                            |
| `dns`                                             | Filters DNS traffic, which is useful to monitor domain name resolution.                                                                                                              |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0`        | Filters SYN packets (used in TCP handshakes), useful for detecting scanning or connection attempts.                                                                                  |
| `icmp`                                            | Filters ICMP packets (used for Ping), which can be useful for reconnaissance or network issues.                                                                                      |
| `http.request.method == "POST"`                   | Filters for HTTP POST requests. In the case that POST requests are sent over unencrypted HTTP, it may be the case that passwords or other sensitive information is contained within. |
| `tcp.stream eq 53`                                | Filters for a specific TCP stream. Helps track a conversation between two hosts.                                                                                                     |
| `eth.addr == 00:11:22:33:44:55`                   | Filters packets from/to a specific MAC address.                                                                                                                                      |
| `ip.src == 192.168.24.3 && ip.dst == 56.48.210.3` | Filters traffic between two specific IP addresses. Helps track communication between specific hosts.                                                                                 |
it's possible to locate packets that contain specific bytes or strings. One way to do this is by using a display filter such as `http contains "passw"`. Alternatively, you can navigate to `Edit > Find Packet` and enter the desired search query manually. For example, you might search for packets containing the string `"passw"`:

![Network packet capture showing HTTP requests with details. Highlighted POST request includes HTML form data with username and password fields.](https://academy.hackthebox.com/storage/modules/308/img/Net_3.png)

It's worth familiarizing yourself with the syntax of Wireshark's filtering engine, especially if you ever need to perform network traffic analysis.
## Pcredz

[Pcredz](https://github.com/lgandx/PCredz) is a tool that can be used to extract credentials from live traffic or network packet captures. Specifically, it supports extracting the following information:

- Credit card numbers
- POP credentials
- SMTP credentials
- IMAP credentials
- SNMP community strings
- FTP credentials
- Credentials from HTTP NTLM/Basic headers, as well as HTTP Forms
- NTLMv1/v2 hashes from various traffic including DCE-RPC, SMBv1/2, LDAP, MSSQL, and HTTP
- Kerberos (AS-REQ Pre-Auth etype 23) hashes
```shell-session
$ ./Pcredz -f demo.pcapng -t -v
```
## Password sniffing
- [ ] [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](https://www.netminer.com/en/product/netminer.php),

## Honeypot detection

- [ ] look for weird hostnames, non standard  `host` multicast IP, and untypical usage of LLMNR and NB-NS ( they're typically used at the same time for legit requests) 
- [ ] read more about it later.