
`Port already in use?`
```
┌──(demise㉿kali)-[/opt]                                                                                   
└─$ sudo lsof -i :11601                                                                                    
COMMAND     PID   USER FD   TYPE DEVICE SIZE/OFF NODE NAME
ligolo-pr 45992 demise 5u  IPv6 192226      0t0  TCP *:11601 (LISTEN)


└─$ sudo netstat -tulnp | grep 11601
tcp6       0      0 :::11601                :::*                    LISTEN      45992/ligolo-proxy  
```

`kill with sigkill`
```
─$ sudo kill -9 45992                                
[1]+  Killed                  ligolo-proxy -selfcert 0.0.0.0:11601

```
