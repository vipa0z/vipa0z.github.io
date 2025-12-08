many attacks apply to thick client applications. However, thick client applications are considered less secure than web applications with many attacks being applicable, including:

- Improper Error Handling.
- Hardcoded sensitive data.
- DLL Hijacking.
- Buffer Overflow.
- SQL Injection.
- Insecure Storage.
- Session Management.

#### #### Information Gathering 

In this step,  identify the application architecture, the programming languages and frameworks that have been used, and understand how the application and the infrastructure work.  also need to identify technologies that are used on the client and server sides and find entry points and user inputs.  look for identifying common vulnerabilities like the ones we mentioned earlier at the end of the [About](https://academy.hackthebox.com/module/113/section/2139##About) section. The following tools will help us gather information.
#### Tools for information gathering

|                                                 |                                                             |                                                                                     |                                                                             |
| ----------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| [CFF Explorer](https://ntcore.com/?page_id=388) | [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) | [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) | [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings) |

#### Client Side attacks

Although thick clients perform significant processing and data storage on the client side, they still communicate with servers for various tasks, such as data synchronization or accessing shared resources. This interaction with servers and other external systems can expose thick clients to vulnerabilities similar to those found in web applications, including command injection, weak access control, and SQL injection.

Sensitive information like usernames and passwords, tokens, or strings for communication with other services, might be stored in the application's local files. Hardcoded credentials and other sensitive information can also be found in the application's source code, thus Static Analysis is a necessary step while testing the application. Using the proper tools, we can reverse-engineer and examine .NET and Java applications including EXE, DLL, JAR, CLASS, WAR, and other file formats. Dynamic analysis should also be performed in this step, as thick client applications store sensitive information in the memory as well.

|                                       |                                      |                                   |                                                |
| ------------------------------------- | ------------------------------------ | --------------------------------- | ---------------------------------------------- |
| [Ghidra](https://www.ghidra-sre.org/) | [IDA](https://hex-rays.com/ida-pro/) | [OllyDbg](http://www.ollydbg.de/) | [Radare2](https://www.radare.org/r/index.html) |

|                                         |                               |                                        |                            |
| --------------------------------------- | ----------------------------- | -------------------------------------- | -------------------------- |
| [dnSpy](https://github.com/dnSpy/dnSpy) | [x64dbg](https://x64dbg.com/) | [JADX](https://github.com/skylot/jadx) | [Frida](https://frida.re/) |
#### Network Side Attacks

If the application is communicating with a local or remote server, network traffic analysis will help us capture sensitive information that might be transferred through HTTP/HTTPS or TCP/UDP connection, and give us a better understanding of how that application is working. Penetration testers that are performing traffic analysis on thick client applications should be familiar with tools like:

|                                         |                                     |                                                                             |                                            |
| --------------------------------------- | ----------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------ |
| [Wireshark](https://www.wireshark.org/) | [tcpdump](https://www.tcpdump.org/) | [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) | [Burp Suite](https://portswigger.net/burp) |


#### Server Side Attacks

Server-side attacks in thick client applications are similar to web application attacks, and penetration testers should pay attention to the most common ones including most of the OWASP Top Ten.
# reverse engineering

Inspecting the execution of the executable through `ProcMon64` shows that it is querying multiple things in the registry and does not show anything solid to go by.

![proc-restart](https://academy.hackthebox.com/storage/modules/113/thick_clients/proc-restart.png)

Let's start `x64dbg`, navigate to `Options` -> `Preferences`, and uncheck everything except `Exit Breakpoint`:

![text](https://academy.hackthebox.com/storage/modules/113/Exit_Breakpoint_1.png)

By unchecking the other options, the debugging will start directly from the application's exit point, and we will avoid going through any `dll` files that are loaded before the app starts. Then, we can select `file` -> `open` and select the `restart-service.exe` to import it and start the debugging. Once imported, we right click inside the `CPU` view and `Follow in Memory Map`:

![gdb_banner](https://academy.hackthebox.com/storage/modules/113/Follow-In-Memory-Map.png)

Checking the memory maps at this stage of the execution, of particular interest is the map with a size of `0000000000003000` with a type of `MAP` and protection set to `-RW--`.

![maps](https://academy.hackthebox.com/storage/modules/113/Identify-Memory-Map.png)

Memory-mapped files allow applications to access large files without having to read or write the entire file into memory at once. Instead, the file is mapped to a region of memory that the application can read and write as if it were a regular buffer in memory. This could be a place to potentially look for hardcoded credentials.

If we double-click on it, we will see the magic bytes `MZ` in the `ASCII` column that indicates that the file is a [DOS MZ executable](https://en.wikipedia.org/wiki/DOS_MZ_executable).

![magic_bytes_3](https://academy.hackthebox.com/storage/modules/113/thick_clients/magic_bytes_3.png)

Let's return to the Memory Map pane, then export the newly discovered mapped item from memory to a dump file by right-clicking on the address and selecting `Dump Memory to File`. Running `strings` on the exported file reveals some interesting information.


```powershell-session
C:\> C:\TOOLS\Strings\strings64.exe .\restart-service_00000000001E0000.bin

<SNIP>
"#M
z\V
).NETFramework,Version=v4.0,Profile=Client
FrameworkDisplayName
.NET Framework 4 Client Profile
<SNIP>
```

Reading the output reveals that the dump contains a `.NET` executable. We can use `De4Dot` to reverse `.NET` executables back to the source code by dragging the `restart-service_00000000001E0000.bin` onto the `de4dot` executable.


```cmd-session
de4dot v3.1.41592.3405

Detected Unknown Obfuscator (C:\Users\cybervaca\Desktop\restart-service_00000000001E0000.bin)
Cleaning C:\Users\cybervaca\Desktop\restart-service_00000000001E0000.bin
Renaming all obfuscated symbols
Saving C:\Users\cybervaca\Desktop\restart-service_00000000001E0000-cleaned.bin


Press any key to exit...
```

Now, we can read the source code of the exported application by dragging and dropping it onto the `DnSpy` executable.

![souce-code_hidden](https://academy.hackthebox.com/storage/modules/113/thick_clients/souce-code_hidden.png)

With the source code disclosed, we can understand that this binary is a custom-made `runas.exe` with the sole purpose of restarting the Oracle service using hardcoded credentials.

