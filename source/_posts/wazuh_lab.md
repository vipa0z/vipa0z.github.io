---
title: "Testing out Wazuh XDR: Simulating and Detecting attacks using wazuh & Atomic red team"
date: 2024-05-13 12:00:00 +0200
---


# _OVERVIEW

In `T1003.008`, Attackers dumps `/etc/shadow`, and `/etc/passwd` files. Which are highly Sensitive files that contain the hashes of user passwords, the attacker will then have to crack their hashes offline to obtain the passwords for all users on the compromised machine. In this short post, i'll be simulating this attack and detecting it using Wazuh and Atomic red team.

### T1003.008

![TECHNIQUE MAPPING](../images/ATT&CK1.png)

for this lab I'm using 3 machines, one acting as the server hosting my wazuh dashboard, target that runs Ubuntu, and Kali Linux machine with invoke atomic, I will be invoking the technique on the victim machine and run Atomic on the target system.
<!-- more --> 


![atomic script](https://miro.medium.com/v2/resize:fit:720/format:webp/0*cDElI84D0wREyPv8)


Observing Wazuh’s dashboard, We Immediately notice Over 50 Alerts!
![WAZUH DASHBOARD](https://miro.medium.com/v2/resize:fit:1100/format:webp/0*DuRWLLyvDHrYOtpg)

we can confirm this by checking the event logs. 
![log analysis](https://miro.medium.com/v2/resize:fit:640/format:webp/0*zq3wmbWfIXUPn-Gh)

From here, the recommended actions would be to recover from a restore point and change passwords for all users on the restored system.