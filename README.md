# debugger

Binary Ninja debugger effort for IQT

## gdb vs. lldb servers

- lldb has single reg reads with 'p' packet, gdb doesn't, and registers must be read in group with 'g' packet
- lldb can have its registers polled with 'qRegisterInfo' packet, but gdb uses XML target description
- lldb has space in 'P' packet, like 'P 0=DEADBEEF' while gdb has 'P0=DEADBEEF'
- lldb has single reg writes with 'P' packet, gdb doesn't, and registers must be written in group with 'G' packet
## notes:

tcpdump -i lo0 -A -s0 'port 31337'
typical GDB RSP files
https://sourceware.org/gdb/onlinedocs/gdb/Packets.html
lldb-gdb-remote.txt
gcc -o helloworld helloworld.c -Wl,-no_pie

```bash
while True;
do
	debugserver localhost:31337 ~/fdumps/workspace/helloworld_thread || echo "App crashed... restarting..." >&2
	echo "Press Ctrl-C to quit." && sleep .1
done
```
  weak xml reply: $l<target><architecture>i386:x86-64</architecture><osabi>GNU/Linux</osabi></target>#ef
strong xml reply: $l<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd"><target><architecture>i386:x86-64</architecture>
