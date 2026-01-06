JUST USE AUTOROUTE
fix for file already exists when reestablishing connections (after it dies)
```
sudo ip show routes
sudo ip route del <172.16.0.0/23>
```
![](https://miro.medium.com/v2/resize:fit:700/1*ermCj8d199rHTXeCabiXlA.png)
## Introduction

ligolo  is a tunneling tool simillar to chisel but very powerful.
ligolo can setup the routing and portforwarding  for you on its own.

----------------
# Preparation

start with a map  of hosts that you can build upon using eraser.io or draw.io......
##  the tunnel
first you would need an agent and a proxy, your attacking machine is gonna be running the proxy, the target will run the ligolo-agent.
`<URL>` PROXY
`<URL>` AGENT

Now that you have a basic understanding of what your target is assigned and what the IP for the connected networks are, lets  install and run the ligolo tunnel:

```
─(demise㉿kali)-[/opt]
└─$ sudo ip tuntap add user demise mode tun ligolo

┌──(demise㉿kali)-[/opt]
└─$ sudo ip link set ligolo up

```
`create a network interface for ligolo (tunnel interface)`
```
sudo ip tuntap add user [demise] mode  tun ligolo
sudo ip link set ligolo up
```

`verify interface exists`
```
ip addr show ligolo
```

## Creating the tunnel


`Setting up the ligolo-ng Proxy server (as an attacker)`
```
ligolo-proxy [-autocert -auto-cert -selfcert] 0.0.0.0:11601
# in realworld use -autocert 
# in lab environment use -selfcert
```


`run ligolo agent (on  target)`
```
victim$ ./ligolo-agent -connect ip:port -ignore-cert
```

type `session` and specify the target with `1`
### Routing to internal network
lets start adding a route  to the internal network using  the `Autorouting` functionality provided 
`view routing configs`
```
ifconfig
```

You will now see at the bottom a new  interface for the `lan` that the pivot host is connected to, confirming access to the internal network.

` manually adding route to the new interface (pivot's internal network nic)`
```
sudo ip route  add 172.16.x.0/24 dev ligolo
```

`start the tunnel`
```
ligolo> start
```



# Local Port forwarding (Accessing local ports)

if the host is running local services we can access them with `240.0.0.1
```
attcker$ sudo ip route add 240.0.0.1/32 dev ligolo
```

detect machine's local services
```
attcker$ nmap 240.0.0.1
```
## Remote Port forwarding

`start a listener on agent1`
```
Agent:pivot1@jhost1> listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp 
```
any network coming to pivot1's 30000 port will get forwarded to (kali 127.xx:10000)
this whole command says:
`forward traffic coming to jumphost1's port 30000 from any ip to attacker's ip  which they can access via localhost:10000`


