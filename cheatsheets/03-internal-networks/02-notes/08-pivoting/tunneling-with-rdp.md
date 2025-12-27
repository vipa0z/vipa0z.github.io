
There are often times during an assessment when we may be limited to a Windows network and may not be able to use SSH for pivoting. We would have to use tools available for Windows operating systems in these cases.
We can use `SocksOverRDP` to tunnel our custom packets and then proxy through it. We will use the tool [Proxifier](https://www.proxifier.com/) as our proxy server. 
on our attack host will allow us to transfer them to each target where needed. We will need:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
    
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab) We can look for `ProxifierPE.zip`
 
 `View networks`
 ![](/images/Pasted image 20250705030105.png)
## Fixing Common issues:
 
 Loading SocksOverRDP.dll using regsvr32.exe
```cmd-session
FOOTHOLD> regsvr32.exe SocksOverRDP-Plugin.dll
```

connect to the accesible 172.16.5.19 over RDP using `mstsc.exe`
![](/images/Pasted image 20250705031413.png)
disable antivirus and add exclusion

## from 5.19 create a tunnel to .6.0/23

after running the plugin, connect to pivot host with mstc
copy file the `socksoverrdp.exe` to clipboard from kali
connect with mstc
(this message is important): it confirms the plugin is working
![](/images/Pasted image 20250705032332.png)
 `setup the proxy server. with admin shell`
```
PIVOT-HOST>.\Socksoverrdp.exe
```
success message:
![](/images/Pasted image 20250705032529.png)
`confirm tunnel is working, (DONT CLOSE MSTC SESSION)`
```cmd-session
FOOTHOLD> netstat -antb | findstr 1080

  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING
```
![](/images/Pasted image 20250705032745.png)
## Configuring PROXIFIER  to proxy our traffic through a target host and port
`chisel and PROXYCHAINS WANNABE)`
 to forward all our packets to 127.0.0.1:1080. Proxifier will route traffic through the given host and port. See the clip below for a quick walkthrough of configuring Proxifier.
![](/images/Pasted image 20250705033001.png)
With Proxifier configured and running, we can start mstsc.exe, and it will use Proxifier to pivot all our traffic via 127.0.0.1:1080, which will tunnel it over RDP to 172.16.5.19, which will then route it to 172.16.6.155 using SocksOverRDP-server.exe.


# Enter-PSSession 
as an alternative when RDP is extremely unstable:
![](/images/Pasted image 20250705034725.png)