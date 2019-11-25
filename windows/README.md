Windows prototype debugger. The idea is that if a standalone command line debugger can be made, it should be rather simple to make a Binary Ninja interface to the core of this example.

## How To Use

Compile dbgengadapt.cpp to dbgengadapt.dll with `nmake`.

Run `python cli.py` to get a windbg like experience.

## How It Works

```
        ctypes                    COM            OS
cli.py --------> dbgengadapt.dll ------> dbgeng ----> target
```

## Features

- [x] attach `python cli.py 1234`
- [x] detach `FAKEDBG> detach`
- [x] start process `python cli.py c:\windows\system32\notepad.exe`
- [x] break into `FAKEDBG> break`
- [x] resume/go `FAKEDBG> go`
- [x] step into `FAKEDBG> t`
- [x] step over `FAKEDBG> p`
- [x] breakpoint add `FAKEDBG> bp 7ff7a18dac50`
- [x] breakpoint clear `FAKEDBG> bc 0`
- [ ] breakpoint callbacks
- [x] mem read `FAKEDBG> db 7ff7a18dac50`
- [x] mem write `FAKEDBG> db 7ff7a18dac50 de ad be ef`
- [x] reg read `FAKEDBG> r`
- [x] reg write `FAKEDBG> r rax deadbeef`
- [x] thread list `FAKEDBG> ~`
- [x] thread switch `FAKEDBG> ~2s`

