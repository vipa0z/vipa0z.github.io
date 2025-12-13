```
`test.txt;net user prtgadm2 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm2 /add`
```
PRTG also shows up in the EyeWitness scan we performed earlier. Here we can see that EyeWitness lists the default credentials `prtgadmin:prtgadmin`. They are typically pre-filled on the login page, and we often find them unchanged. Vulnerability scanners such as Nessus also have [plugins](https://www.tenable.com/plugins/nessus/51874) that detect the presence of PRTG.

![image](https://academy.hackthebox.com/storage/modules/113/prtg_eyewitness.png)

Once we have discovered PRTG, we can confirm by browsing to the URL and are presented with the login page.

![](https://academy.hackthebox.com/storage/modules/113/prtg_login.png)

From the enumeration we performed so far, it seems to be PRTG version `17.3.33.2830` and is likely vulnerable to [CVE-2018-9276](https://nvd.nist.gov/vuln/detail/CVE-2018-9276) which is an authenticated command injection in the PRTG System Administrator web console for PRTG Network Monitor before version 18.2.39. Based on the version reported by Nmap, we can assume that we are dealing with a vulnerable version. Using `cURL` we can see that the version number is indeed `17.3.33.283`.

PRTG Network Monitor

```shell-session
curl -s http://10.129.201.50:8080/index.htm -A "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)" | grep version

  <link rel="stylesheet" type="text/css" href="/css/prtgmini.css?prtgversion=17.3.33.2830__" media="print,screen,projection" />
<div><h3><a target="_blank" href="https://blog.paessler.com/new-prtg-release-21.3.70-with-new-azure-hpe-and-redfish-sensors">New PRTG release 21.3.70 with new Azure, HPE, and Redfish sensors</a></h3><p>Just a short while ago, I introduced you to PRTG Release 21.3.69, with a load of new sensors, and now the next version is ready for installation. And this version also comes with brand new stuff!</p></div>
    <span class="prtgversion">&nbsp;PRTG Network Monitor 17.3.33.2830 </span>
```

Our first attempt to log in with the default credentials fails, but a few tries later, we are in with `prtgadmin:Password123`.

![](https://academy.hackthebox.com/storage/modules/113/prtg_logged_in.png)

---

## Leveraging Known Vulnerabilities

Once logged in, we can explore a bit, but we know that this is likely vulnerable to a command injection flaw so let's get right to it. This excellent [blog post](https://www.codewatch.org/blog/?p=453) by the individual who discovered this flaw does a great job of walking through the initial discovery process and how they discovered it. When creating a new notification, the `Parameter` field is passed directly into a PowerShell script without any type of input sanitization.

To begin, mouse over `Setup` in the top right and then the `Account Settings` menu and finally click on `Notifications`.

![](https://academy.hackthebox.com/storage/modules/113/prtg_notifications.png)

Next, click on `Add new notification`.

![](https://academy.hackthebox.com/storage/modules/113/prtg_add.png)

Give the notification a name and scroll down and tick the box next to `EXECUTE PROGRAM`. Under `Program File`, select `Demo exe notification - outfile.ps1` from the drop-down. Finally, in the parameter field, enter a command. For our purposes, we will add a new local admin user by entering `test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add`. During an actual assessment, we may want to do something that does not change the system, such as getting a reverse shell or connection to our favorite C2. Finally, click the `Save` button.

![image](https://academy.hackthebox.com/storage/modules/113/prtg_execute.png)

After clicking `Save`, we will be redirected to the `Notifications` page and see our new notification named `pwn` in the list.

![](https://academy.hackthebox.com/storage/modules/113/prtg_pwn.png)

Now, we could have scheduled the notification to run (and execute our command) at a later time when setting it up. This could prove handy as a persistence mechanism during a long-term engagement and is worth taking note of. Schedules can be modified in the account settings menu if we want to set it up to run at a specific time every day to get our connection back or something of that nature. At this point, all that is left is to click the `Test` button to run our notification and execute the command to add a local admin user. After clicking `Test` we will get a pop-up that says `EXE notification is queued up`. If we receive any sort of error message here, we can go back and double-check the notification settings.

Since this is a blind command execution, we won't get any feedback, so we'd have to either check our listener for a connection back or, in our case, check to see if we can authenticate to the host as a local admin. We can use `CrackMapExec` to confirm local admin access. We could also try to RDP to the box, access over WinRM, or use a tool such as [evil-winrm](https://github.com/Hackplayers/evil-winrm) or something from the [impacket](https://github.com/SecureAuthCorp/impacket) toolkit such as `wmiexec.py` or `psexec.py`.

METASPLOIT AUTHENTICATED RCE PRTG