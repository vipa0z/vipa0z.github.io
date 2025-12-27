we can use `Netsh` for:

- `Finding routes`
- `Viewing the firewall configuration`
- `Adding proxies`
- `Creating port forwarding rules`
![](/images/88.webp)
We can use `netsh.exe` to forward all data received on a specific port (say 8080) to a remote host on a remote port. This can be performed using the below command.

#### Using Netsh.exe to Port Forward

```cmd-session
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

#### Verifying Port Forward


```cmd-session
C:\Windows\system32> "netsh.exe interface portproxy show v4tov4"

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.15.150   8080        172.16.5.25     3389
```


#### Connecting to the Internal Host through the Port Forward
specify the forwarder's address and forwarded port not the internal host's

![](/images/netsh_pivot.webp)