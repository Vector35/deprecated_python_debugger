The debugger must support multiple platforms. Initially, those platforms are Windows, Linux, and MacOS.

In Windows, we use the [debug engine API](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-engine-and-extension-apis) the OS provides and WinDbg uses. On Linux we connect to a gdbserver and speak [remote serial protocol](https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html). On MacOS, we connect to debugserver and speak the [slightly augmented RSP](https://github.com/llvm-mirror/lldb/blob/master/docs/lldb-gdb-remote.txt) protocol.

To both abstract the details of each of these three initial debugging subsystems and allow extensions to future subsystems or variations on existing ones, we make each of these fit into a DebugAdapter class. See [DebugAdapter.py](./DebugAdapter.py) for details.

Since GDB and LLDB are so similar, a "gdb-like" adapter acts as a parent class and tries to capture as much commonality as possible before the gdb and lldb adapters derive from it. Also, since they both speak RSP, an RSP module sits between them and the server. Here's an attempt at a diagram:

```
                     +-----------------+
                     |   DebugAdapter  |
                     |(DebugAdapter.py)|
                     +-----------------+
                      |               |
                      |       +--------------+
                      |       | DebugAdapter |
                      |       |   GdbLike    |
                      |       | (gdblike.py) |
          +-----------+       +--------------+
          |                       |       |
          |                   +---+       +----+
          |                   |                |
+-------------------+  +--------------+  +--------------+
|   DebugAdapter    |  | DebugAdapter |  | DebugAdapter |
|      Dbgeng       |  |     GDB      |  |    LLDB      |
|    (dbgeng.py)    |  |   (gdb.py)   |  |   (lldb.py)  |
+-------------------+  +--------------+  +--------------+
          | ctypes     +--------------------------------+
+-------------------+  |            (rsp.py)            |
|  dbgengadapt.dll  |  +--------------------------------+
| (dbgengadapt.cpp) |        |                 |
+-------------------+        | socket          | socket
          | COM              |                 |
+-------------------+  +-----------+      +-------------+
| Windows Debug API |  | gdbserver |      | debugserver |
+-------------------+  +-----------+      +-------------+
```

You may notice that the socket could connect to any gdb stub, not just those implemented by gdbserver or debugserver. Remote connect is planned soon.

Sometimes the adapter must "shape" the behavior of the underlying debug subsystem so that it looks uniform from viewpoint of a generic DebugAdapter. For example, in Windows, setting a breakpoint on any address never fails. But on bad addresses, the next go/step/stepinto will get a memory write exception because that's when the engine actually writes the 0xCC byte. But the designed behavior of `breakpoint_set()` in DebugAdapter is to write immediately, and provide instance response to the caller if the breakpoint wasn't set correctly. So a `WriteProcessMemory()` is used as a probe, and if it succeeds, the adapter pretends the breakpoint is as good as set.

## Plugin Structure

```
                   +----------------+
                   |   DebugState   |
                   | (binjaplug.py) |
                   +----------------+
                     |     |      |
                 ?ui |     |      | adapter
       +-------------+     |      +-----------------+
       |                   |                        |
       |                   | memory_view            |
       |                   |                        |
+------------+    +------------------+    +-------------------+
| DebuggerUI |    | DebugProcessView |    |    DebugAdapter   |
|   (ui.py)  |    | (ProcessView.py) |    | (DebugAdapter.py) |
+------------+    +------------------+    +-------------------+
  |        |                                        |
  |        | debug_view                             v
  |        +----------------------+            (see above)
  |                               |
  | self.widget(name)             |
  |                               |
+-------------------+    +----------------+
|  Various Widgets  |    |   DebugView    |
| (dockwidget/*.py) |    | (DebugView.py) |
+-------------------+    +----------------+
```

The various pieces of the plugin are organized under the `DebugState` class. When the debugger is loaded as a plugin in Binary Ninja, its `ui` field is initialized with a `DebuggerUI` instance that controls the various dock widgets and the main debugging view. When a process is being debugged, `DebugState` contains an instance of `DebugAdapter` through the `adapter` field. `DebugState` contains an instance of `DebugProcessView` through `memory_view` at all times.

## DebugProcessView

`DebugProcessView` is a specialized `BinaryView` that reads and writes its memory from the connected `DebugAdapter`. When the adapter is not present, all reads/writes will return `None` to indicate an error. To save on data transfer, `DebugProcessView` caches all reads from the adapter. Whenever the debugger executes instructions or writes data it will call `mark_dirty` on the `DebugProcessView` and clear the cached data.

`DebugProcessView` provides two functions, `local_addr_to_remote` and `remote_addr_to_local` which will translate addresses for use in binaries that are compiled with Position Independent Code. **Local addresses** correspond to the loaded `BinaryView` analysis and **remote addresses** represent addresses in the debugged binary, which may be relocated in PIE executables.

## Android

Get gdbservers onto the phone, pushing both architectures. Mine came from the NDK version r15c:

```
adb push ~/android-ndk-r15c/prebuilt/android-arm64/gdbserver/gdbserver /data/local/tmp/gdbserver_aarch64
adb push ~/android-ndk-r15c/prebuilt/android-arm/gdbserver/gdbserver /data/local/tmp/gdbserver_armv7
```

Connect your local machine's 31337 to the phone's 31337 with `adb forward tcp:31337 tcp:31337`.

Run the appropriate gdbserver on the binary, telling it to listen on 31337, eg: `./gdbserver_aarch64 :31337 ./hello_aarch64-android`.

## testing

Enter ./testbins and, depending on your OS, execute:

```
make -f Makefile-linux
make -f Makefile-macos
nmake -f Makefile-win
```

Then run `test.py`.

Use `./tools/sniffrsp.py` to monitor traffic between you and gdbserver/debugserver.

There's also a command line interface to all the debug code: `./cli.py`

## gdb vs. lldb servers

These are differences noted during testing, and may not generalize to all gdbserver and debugserver cases.

- lldb has single reg reads with 'p' packet, but in gdb registers must be read in group with 'g' packet
- lldb can have its registers polled with 'qRegisterInfo' packet, but gdb uses only XML target description
- lldb has single reg writes with 'P' packet, gdb doesn't, and registers must be written in group with 'G' packet
- lldb can list solibs and executable image with 'jGetLoadedDynamicLibrariesInfos' packet, gdb still looks to /proc/pid/maps

## scattered notes:

`tcpdump -i lo0 -A -s0 'port 31337'`

```bash
while True;
do
	debugserver localhost:31337 ~/fdumps/workspace/helloworld_thread || echo "App crashed... restarting..." >&2
	echo "Press Ctrl-C to quit." && sleep .1
done
```

`$ debugserver localhost:31337 ./testbins/asmtest`

`$ gdbserver --once --no-startup-with-shell localhost:31337 ./testbins/asmtest`

(lldb) process connect connect://localhost:31337

