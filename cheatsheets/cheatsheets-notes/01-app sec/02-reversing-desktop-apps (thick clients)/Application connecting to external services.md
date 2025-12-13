# catching connection strings

```
gdb ./octopus_checker
(gdb) set breakpoint pending on
(gdb) break SQLDriverConnect
(gdb) run
```
![[Pasted image 20250706191229.png]]