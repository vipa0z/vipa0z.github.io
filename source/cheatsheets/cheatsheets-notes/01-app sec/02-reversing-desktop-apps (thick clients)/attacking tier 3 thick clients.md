
notes:
port changed from 8000 to 1337
some creds
## Initial enum
opening up the up trying to login yields a connection error, 
- run wireshark and look for traffic on port 1337 or  `8000`. nothing
- ill check DNS 
```
tcp dump -i any udp port 53


08:13:07.184166 eth0  Out IP 192.168.233.128.48311 > 192.168.233.2.domain: 37231+ AAAA? server.fatty.htb. (34)
```
Notice how our machine is broadcasting A records to our network (it's looking for a host ip with the name 0f server.fatty.htb)

i'll add the host entry and set it to our local ip so i can intercept the request and try a few things (like viewing the request body).
set hostname to 127.0.0.1 so we 
```
127.0.0.1       server.fatty.htb fatty.htb
```

now ill check the connections again with wireshark and tcpdump

```
 sudo tcpdump -i any  port 8000/1337
```
```
┌──(kali㉿kali)-[~]
└─$ sudo tcpdump -i any  port 8000 
tcpdump: WARNING: any: That device doesn't support promiscuous mode
(Promiscuous mode not supported on the "any" device)
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
08:33:14.023301 lo    In  IP localhost.38374 > localhost.8000: Flags [S], seq 874133864, win 65495, options [mss 65495,sackOK,TS val 393927833 ecr 0,nop,wscale 7], length 0
08:33:14.023310 lo    In  IP localhost.8000 > localhost.38374: Flags [R.], seq 0, ack 874133865, win 0, length 0

```
okay so it appears the app is still using the old port. if we run socat to redirect traffic coming from port 8000 at localhost to the server's new port 1337 we will be able to login.
![](Pasted%20image%2020250718160933.png)

creating a project in eclipse
create package files
![](Pasted%20image%2020250718163148.png)
click new file call it exploit.java
## Creating our own hacked.fatty.htb

the most efficient way to test out thick   clients written in java  is to use them as a reference libraries for your own java code. 
right click on the package or anywhgere near it, click build path
select lib and add external JAR, add fatty-client.jar.
![](Pasted%20image%2020250719105706.png)
Now the client will be used as a reference library for our exploit.java code
![](Pasted%20image%2020250719105833.png)
