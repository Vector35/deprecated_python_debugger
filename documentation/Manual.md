# Binary Ninja Debugger Manual

## Document Conventions

Terms in **bold** can be found in the Glossary section. Strings `highlighted` refer to code, paths, or commands executed at a terminal.

`BNDP_ROOT` refers to the path where the debugger is installed.

# Table of contents

1. [Introduction](#introduction)
2. [Installation](#installation)
    - [Host Requirements](#host-requirements)
    - [Plugin Acquisition and Installation](#plugin-acquisition-and-installation)
    - [Platform Specific Considerations](#platform-specific-considerations)
        * [Android Phones](#android-phones)
        * [MacOS](#macos)
3. [Use](#use)
    - [GUI Mode](#gui-mode)
    - [Headless Mode](#headless-mode)
    - [Automated Tests](#automated-tests)
        * [Build Environment Requirements](#build-environment-requirements)
        * [Build Steps](#build-steps)
        * [Python Requirements](#python-requirements)
        * [Running](#running)
4. [Design](#design)
    - [Overview](#overview)
    - [Standard Backends](#standard-backends)
    - [DebugAdapter and its Subclasses](#debugadapter-and-its-subclasses)
    - [UI: DebugProcessView](#ui-debugprocessview)
5. [API](#api)
    - [DebugAdapter Methods](#debugadapter-methods)
        * [Initialization Methods](#initialization-methods)
        * [Session Start/Stop Methods](#session-startstop-methods)
        * [Target Info Methods](#target-info-methods)
        * [Thread Methods](#thread-methods)
        * [Breakpoint Methods](#breakpoint-methods)
        * [Register Methods](#register-methods)
        * [Memory Methods](#memory-methods)
        * [Execution Control Methods](#execution-control-methods)
    - [Subclassing DebugAdapter](#subclassing-debugadapter)
    - [GDB vs. LLDB](#gdb-vs-lldb)
    - [Troubleshooting new GDB Backends](#troubleshooting-new-gdb-backends)
        * [General Tips](#general-tips)
        * [Network Monitoring](#network-monitoring)
        * [Executing Backends Manually](#executing-backends-manually)
        * [Executing Client Manually](#executing-client-manually)
6. [Glossary](#glossary)

# Introduction

Binary Ninja Debugger Plugin (**BNDP**) is a plugin for Binary Ninja implementing debug functionality. It can be used from within the GUI or outside (headless). It officially supports 64-bit Windows, Linux, and MacOS targets. Its extensible design makes it easily adapted to other platforms.

# Installation

## Host Requirements

* Processor: [x86-64](https://en.wikipedia.org/wiki/X86-64)
* OS: one of
  * MacOS: 64-bit 10.14 "Mojave" or 10.15 "Catalina"
  * Linux: 64-bit Ubuntu (most recent LTS or latest stable)
  * Windows: 64-bit 10
* Python: 3.7.4
* Binary Ninja: at least version 1.3.2085

## Plugin Acquisition and Installation

BNDP is a python package and is acquired via GitHub (http://github.com/vector35/debugger), by the Plugin Manager from within Binary Ninja, or by ordinary file and directory copying.

It must be placed in the Binary Ninja plugin path, which varies based on platform. Please refer to [Using Plugins](https://docs.binary.ninja/getting-started.html#using-plugins) section within the [Getting Started Guide](https://docs.binary.ninja/getting-started.html) in the [Binary Ninja User Documentation](https://docs.binary.ninja/).

## Platform Specific Considerations

### Android Phones

BNDP can debug armv7 and aarch64 targets by communicating with an appropriate gdbserver. We assume familiarity with the Android software development kit (SDK), native development kit (NDK) and the [Android Debug Bridge](https://developer.android.com/studio/command-line/adb). The servers from NDK version r15c were tested:

```
adb push ~/android-ndk-r15c/prebuilt/android-arm64/gdbserver/gdbserver /data/local/tmp/gdbserver_aarch64
adb push ~/android-ndk-r15c/prebuilt/android-arm/gdbserver/gdbserver /data/local/tmp/gdbserver_armv7
```

Connect your local machine's 31337 to the phone's 31337 with `adb forward tcp:31337 tcp:31337`.

From the phone, run the appropriate gdbserver on the binary, telling it to listen on 31337, eg: `./gdbserver_aarch64 :31337 ./hello_aarch64-android`.

### MacOS

Developer mode is required, so a dialogue may have to be affirmed upon first launch of `lldb` and `/usr/sbin` must be in path so that `DevToolsSecurity` can be executed.

# Use

## GUI Mode

Open a target binary in Binary Ninja. At the lower right, click the view type (here: `Graph`) to raise a context menu that allows you to select `Debugger`:

![](./resources/gui1.png)

A view with debugger-related menu items will appear:

![](./resources/gui2.png)

Click the drop-down menu arrow near `Run` for additional settings. Click `Run` to execute the target. The other buttons will activate if the target is initialized successfully. Buttons `Resume`, `Step Into`, etc. work as expected. To set a breakpoint, select an address, right click, choose Debugger, then `Toggle Breakpoint`.

![](./resources/gui3.png)

The same step is used to clear the breakpoint. To view modules, registers, etc. select `View` from the application's main menu and then the desired view:

![](./resources/gui4.png)

## Headless Mode

The API attempts to hide target details behind a uniform interface called DebugAdapter. Start by importing the parent DebugAdapter and the appropriate child for your platform and creating an instance:

```python
from debugger import DebugAdapter, lldb
adapter = lldb.DebugAdapterLLDB()
```

The adapter is not yet associated with any target. To acquire a target, there are functions `exec()`, `attach()`, and `connect()`. Here is a call to execute:

```python
adapter.exec("/path/to/target", ['-param0', 'value0'])
```

Now you may call adapter methods. For target information there are `target_arch()`, `target_path()`, `target_pid()`, `target_base()`. For dealing with registers there are `reg_read()`, `reg_write()`, etc. For breakpoints there are `breakpoint_set()`, `breakpoint_clear()`. See DebugAdapter.py for the full list. Here is an example that uses the API to advance to function MD5Init():

```python
adapt.breakpoint_set(MD5Init)
(reason, data) = adapt.go()
assert reason == DebugAdapter.STOP_REASON.BREAKPOINT
assert adapt.reg_read('rip') == MD5Init
adapt.breakpoint_clear(MD5Init)
```

To acquire the values of functions like MD5Init, we anticipate you wanting to pair headless debugging with analysis:

```python
bv = BinaryViewType.get_view_of_file("/path/to/target")
bv.update_analysis_and_wait()
MD5Init = [f.start for f in bv.functions if f.symbol.full_name == 'MD5Init']
```

See `BNDP_ROOT/examples` for headless debugging scripts.
See `BNDP_ROOT/test.py`  for a giant example of headless debugging.
See `BNDP_ROOT/cli.py`  for an interactive console debugger.

## Automated Tests

### Build Environment Requirements

Building the tests requires an assembler, compiler, and make utility:

| OS      | assembler        | compiler                                                     | make                                                         |
| ------- | ---------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| MacOS   | Nasm v2.14.02    | Clang 11.0.0                                                 | GNU Make 3.8.1                                               |
| Linux   | Nasm v2.13.02    | GCC 7.5.0                                                    | GNU Make 4.1                                                 |
| Windows | Nasm v2.14.03rc2 | Visual Studio 2017<br />Microsoft (R) C/C++ Optimizing Compiler Version 19.15.26730 for x64 | nmake<br />Microsoft (R) Program Maintenance Utility Version 14.15.26730.0 |

These versions are used during development but are likely flexible.

### Build Steps

All builds use make (nmake for Windows) and a shell (“x64 Native Tools Command Prompt for VS 2017” for Windows). Change to the debugger/testbins directory and run make/nmake, specifying the appropriate Makefile:

| OS      | steps                                                        |
| ------- | ------------------------------------------------------------ |
| MacOS   | $ cd BNDP_ROOT/testbins<br />$ make -f Makefile-macos        |
| Linux   | $ cd BNDP_ROOT/testbins<br />$ make -f Makefile-linux        |
| Windows | c:\\> cd BNDP_ROOT\\testbins<br />c:\BNDP_ROOT\testbins> nmake -f Makefile-win64 |

### Python Requirements

The python package `colorama` is required and can be installed with: `pip3 install colorama`.

### Running

Simply execute  `BNDP_ROOT/test.py`.

# Design

## Overview

BNDP is a convenient means to interact with various debugger **backends**. It does not instrument targets itself.

The backends vary considerably, so a large part of BNDP's task is to present a unified interface by which these backends can be used.

This is achieved using debug **adapters**, named so because they adapt whatever idiosyncrasies a backend has to the ideal interface we envision in `DebugAdapter.py`. Each adaptation of a backend is a subclass of `DebugAdapter`, for example `DebugAdapterGdb` and `DebugAdapterLLDB` communicate with gdb and lldb backends, respectively.

## Standard Backends

BNDP can connect to three **backends**: gdb/gdbserver, lldb/debugserver, and **dbgeng**. The target is decoupled from BNDP in the first two modes, communicating using the [RSP protocol](https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html) over a socket. Theoretically any platform for which a gdbserver exists can be debugged. In dbgeng mode, BNDP is runtime linked to [Windows debugger engine](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/introduction) and can debug local binaries.

The gdb backend isn't a single piece of software or even a reliable behavior. It's a specification, and developers who wish to expose debug functionality are free to implement whatever subset of the specification they choose. For example, the Multiple Arcade Machine Emulator (MAME), BOCHS emulator, and VMware have the option to expose a gdb interface. So further adaptation is require depending on the gdb backend implementation. For example, we have `DebugAdapterMameColeco` for the gdb backend implemented by MAME when it's emulating a ColecoVision system with Z80 processor.

![](./resources/backend_arch.png)

BNDP is tested on **x64-linux**, **arm-android** and **aarch64-android** binaries in gdb mode, **x64-macos** binaries in lldb mode, and **x64-windows** binaries in dbgeng mode.

You should have success on the 32-bit x86 versions of the above binaries, but they're not as rigorously tested as 64-bit.

## DebugAdapter and its Subclasses

Each of the adapters is expected to provide some primitive operations, like reading registers, stepping, breakpoints, etc. The comprehensive, but still short, list is the abstract functions in class DebugAdapter in [DebugAdapter.py](https://github.com/Vector35/debugger/blob/master/DebugAdapter.py).

With classes and inheritance, we're able to factor out common behavior among adapters. For instance, GDB and LLDB have much in common, with LLDB speaking [an augmented RSP protocol](https://github.com/llvm-mirror/lldb/blob/master/docs/lldb-gdb-remote.txt). The current class diagram has plenty of room for an additional adapter and its corresponding **backend**:

![](./resources/adapter_class_diagram.png)

Higher level operations like "step over" are provided by some backends (like **dbgeng**) but not others (like gdb and lldb). For these, the operation is synthesized with primitive operations. "Step over" might involve disassembling to detect call or loop instructions and setting a one-shot breakpoint. "Go up" might involve reading the stack and setting a one-shot breakpoint at the return address.

## UI: DebugProcessView

`DebugProcessView` is a specialized `BinaryView` that reads and writes its memory from the connected `DebugAdapter`. When the adapter is not present, all reads/writes will return `None` to indicate an error. To save on data transfer, `DebugProcessView` caches all reads from the adapter. Whenever the debugger executes instructions or writes data it will call `mark_dirty` on the `DebugProcessView` and clear the cached data.

`DebugProcessView` provides two functions, `local_addr_to_remote` and `remote_addr_to_local` which will translate addresses for use in binaries that are compiled with Position Independent Code. **Local addresses** correspond to the loaded `BinaryView` analysis and **remote addresses** represent addresses in the debugged binary, which may be relocated in PIE executables.

# API

Prerequisite reading: [Design](#Design)

The API is centered around the `DebugAdapter` class. You can subclass it to interface with a new **backend**.

You can use existing subclasses `DebugAdapterGdbLike`, `DebugAdapterGdb`, `DebugAdapterLLDB`, and `DebugAdapterMameColeco` to connect to already tested backends.

You can programmatically debug targets by using `DebugAdapter` methods.

## DebugAdapter Methods

### Initialization Methods

Some **backends** need to perform some initialization before acquiring a target. For example, **dbgeng** needs to acquire COM interfaces.

```
	def setup()
	def teardown()
```

### Session Start/Stop Methods

These functions start and end a session. A session can be started by executing a target,, attaching to a target, or connecting to a listening **backend**. Detaching, when possible, means disconnecting the debugger and allowing the target to resume execution. Quitting means to end the session entirely.

```
	def exec(self, path, args=[])
	def attach(self, pid)
	def connect(self, server, port)
	def detach(self)
	def quit(self)
```

### Target Info Methods

Acquire the target's architecture, execution path, process ID, and load address. Note that these are not always applicable for certain targets. For example, PID does not make sense when connected to a full system BOCHS emulation.

```
	def target_arch(self)
	def target_path(self)
	def target_pid(self)
	def target_base(self)
```

See `BNDP_ROOT/DebugAdapter.py`.

### Thread Methods
```
	def thread_list(self):
	def thread_selected(self):
	def thread_select(self, tidx):
```

### Breakpoint Methods
```
	def breakpoint_set(self, address)
	def breakpoint_clear(self, address)
	def breakpoint_list(self)
```

### Register Methods
```
	def reg_read(self, reg)
	def reg_write(self, reg, value)
	def reg_list(self)
	def reg_bits(self, reg)
```

### Memory Methods
```
	def mem_read(self, address, length)
	def mem_write(self, address, data)
	def mem_modules(self, cache_ok=True)
```

### Execution Control Methods
```
	def go(self):
	def step_into(self):
	def step_over(self):
```

## Subclassing DebugAdapter

The DebugAdapter wants to present a general debug interface, hiding the idiosyncrasies of whatever **backend** it is connected to. Often you will have to "shape" the behavior of the backend to aim for this ideal.

For example, in Windows, setting a breakpoint always succeeds, no matter the address. It's only at the next go/step/step that bad addresses will raise a write exception because that's when the engine actually writes the 0xCC byte. But the designed behavior of `breakpoint_set()` in DebugAdapter is to write immediately, and provide instant response to the caller if the breakpoint wasn't set correctly. So a `WriteProcessMemory()` is used as a probe, and if it succeeds, the adapter pretends the breakpoint is as good as set.

On Windows, `step over` is available from the **dbgeng** backend, but with gdbserver and debugserver as backends, it is not. To attain this behavior, `step over` is synthesized by setting a temporary breakpoint at the following instruction, which requires analyzing the current instruction for length and branch behavior.

The stubs implemented by gdbserver and debugserver will not step over an address that has a breakpoint. The program counter will remain the same and a breakpoint event will occur. The breakpoint must be temporarily cleared. The MAME stub, however, has no such restriction.

## GDB vs. LLDB

The following differences were noted during development and are not an exhaustive list:

- lldb has single reg reads with 'p' packet, but in gdb registers must be read in group with 'g' packet.
- lldb can have its registers polled with 'qRegisterInfo' packet, but gdb uses only XML target description.
- lldb has single reg writes with 'P' packet, gdb doesn't, and registers must be written in group with 'G' packet.
- lldb can list `so` libs and executable image with 'jGetLoadedDynamicLibrariesInfos' packet, gdb still looks to /proc/pid/maps.

## Troubleshooting new GDB Backends

### General Tips

Prove functionality first with `BNDP_ROOT/cli.py` then with the GUI.

### Network Monitoring

For gdbserver and debugserver, monitoring packets can be indispensable.

- Use tcpdump: `tcpdump -i lo0 -A -s0 'port 31337'`
- Use `./tools/sniffrsp.py` to monitor traffic between you and gdbserver/debugserver
- Use wireshark

### Executing Backends Manually

LLDB:
```
$ debugserver localhost:31337 ./testbins/asmtest
```

GDB:
```
$ gdbserver --once --no-startup-with-shell localhost:31337 ./testbins/asmtest
```

MAME:
```
mame -v coleco -video soft -cart /path/to/DACMAN.ROM -window -nomax -resolution 560x432 -debugger gdbstub -debug
```

### Executing Client Manually

Monitoring, then mimicking behavior from working tools is often faster than starting at the docs:

LLDB:
```
(lldb) process connect connect://localhost:31337
```

GDB:
```
(gdb) target remote localhost:31337
```

# Glossary

- *backend*  
This is the code that is actually instrumenting (eg: writing breakpoint bytes, setting the trap flag) in targets. Examples are Microsoft's [debugger engine](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-engine-overview), gdbserver, debugserver, or MAME.
- *BNDP*  
Binary Ninja Debugger Plugin
- *dbgeng*  
Microsoft's [debugger engine](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-engine-overview).
