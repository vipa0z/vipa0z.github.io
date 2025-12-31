## **SOCKS Proxy Tunnel (Dynamic Forwarding)**

> You want to tunnel **all** traffic through Parrot (e.g., `proxychains`, Firefox, etc.)
1. Getting a route (ability to reach internal network IPs)
```
ssh -D 1080 victim1@ip
```

edit proxychains
```
 /etc/proxychains.conf or ~/.proxychains/proxychains.conf
socks5 127.0.0.1 1080
```


- Add `-N` if you just want to tunnel (no remote shell):

