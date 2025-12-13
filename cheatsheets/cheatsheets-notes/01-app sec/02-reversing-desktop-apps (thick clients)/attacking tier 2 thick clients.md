
## create folders and  file
```
2/224cf.bat
```
# PREVENT DELETION BY EDITING ACCESS DACLs 
In order to capture the files, it is required to change the permissions of the `Temp` folder to disallow file deletions. To do this, we right-click the folder `C:\Users\Matt\AppData\Local\Temp` and under `Properties` -> `Security` -> `Advanced` -> `cybervaca` -> `Disable inheritance` -> `Convert inherited permissions into explicit permissions on this object` -> `Edit` -> `Show advanced permissions`, we deselect the `Delete subfolders and files`, and `Delete` checkboxes.

![Permission entry dialog for 'Temp' folder. Principal: Matt. Type: Allow. Applies to: This folder, subfolders, and files. Advanced permissions include full control, read, write, and change permissions.](https://academy.hackthebox.com/storage/modules/113/thick_clients/change-perms.png)

Finally, we click `OK` -> `Apply` -> `OK` -> `OK` on the open windows. Once the folder permissions have been applied we simply run again the `Restart-OracleService.exe` and check the `temp` folder. The file `6F39.bat` is created under the `C:\Users\cybervaca\AppData\Local\Temp\2`.

## modify batch script to prevent deletion
### 3435cf.bat
writes b64 pass to 
```
programdata/
```
deletes files so modify it to prevent file deletion.
## read monta.ps1 fully
it writes the b64 text by decoding and then writing the bytes into restart-service.exe file
## restart-service.exe
use procmon, nothing..
use dbgx64 and uncheck all besides breakpoint at exit
check dump, follow in memory map, look for map with -RW (mapped file)
![](Pasted%20image%2020250717010251.png)

look for MAP 

follow in memmory
the highlighted text in assci reveals that a  mapped file
![](Pasted%20image%2020250717010538.png)
export the mapped region and run strings on it,
see if it's built with .NET with strings or detect it easy..
if it's a dotnet run dot4do and dnsspy read sourcecode look for hgardcoded creds.
if its not then try to use strings and grep for passwords



grep for passwords
go to that region and dump it....

run strings on file
```
strings restart-service325242.bin


.NETFRAMEWORK4
```

shows .Net.
## use de4dot to decompile to sourceCode

## USE DNSPY TO VIEW SOURECODE
LOOK FOR HARDCODED CREDENTIALS



















