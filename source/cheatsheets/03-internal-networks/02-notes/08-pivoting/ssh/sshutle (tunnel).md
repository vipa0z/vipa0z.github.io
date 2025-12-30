[Sshuttle](https://github.com/sshuttle/sshuttle) is another tool written in Python which removes the need to configure proxychains. However, this tool only works for pivoting over SSH and does not provide other options for pivoting over TOR or HTTPS proxy servers.

We can configure the Ubuntu server as a pivot point and route all of Nmap's network traffic with sshuttle using the example later in this section.
```shell-session
$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```
With this command, sshuttle creates an entry in our `iptables` to redirect all traffic to the 172.16.5.0/23 network through the pivot host.

```shell-session
$ nmap -v -sV -p3389 172.16.5.19 -A -Pn
```

