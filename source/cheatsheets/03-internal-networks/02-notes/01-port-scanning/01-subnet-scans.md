[Fping](https://fping.org/)   issue ICMP packets against a list of multiple hosts at once.
```shell
$ fping -asgq 172.16.5.0/23

172.16.5.5
172.16.5.25
172.16.5.50
172.16.5.100
172.16.5.125
172.16.5.240

       9 alive
```

We can combine the successful results and the information we gleaned from our passive checks into a list for a more detailed scan with Nmap.

---------------------------
## rustscan
```
rustscan -a -- -sC -sV  -oA nmap/eco-corp 
```

## nmap
We are looking to determine what services each host is running, identify critical hosts such as `Domain Controllers` and `web/file servers`
```bash
sudo nmap   -iL hosts.txt  -T4 -A -oA nmap/targetname
```
-   focus on AD Services First


#### Ping Sweep For Loop on Linux Pivot Hosts

```shell-session
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

#### Ping Sweep For Loop Using CMD

```cmd-session
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

#### Ping Sweep Using PowerShell


```powershell-session
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```



