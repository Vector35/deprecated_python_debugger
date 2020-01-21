# debugger

Binary Ninja debugger effort for IQT

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
