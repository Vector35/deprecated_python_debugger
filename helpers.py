import os
import time
import shutil
import socket
import platform
import subprocess

import binaryninja

import debugger.dbgeng as dbgeng
import debugger.lldb as lldb

#--------------------------------------------------------------------------
# TARGET LAUNCHING
#--------------------------------------------------------------------------

def get_available_port():
	for port in range(31337, 31337 + 256):
		ok = True
		sock = None
		try:
			#print('trying port %d' % port)
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.bind(('localhost', port))
		except Exception as e:
			print(e)
			ok = False
		if sock:
			sock.close()
		if ok:
			#print('returning port: %d' % port)
			return port

def connect_get_adapter(host, port):
	# return LLDB adapter connected to that gdbserver
	for tries in range(4):
		try:
			adapt = lldb.DebugAdapterLLDB(host=host, port=port)
			return adapt
		except ConnectionRefusedError:
			# allow quarter second for debugserver to start listening
			time.sleep(.25)
		except Exception as e:
			print(e)

# prevent child process from getting out ctrl+c signal
# thanks: https://stackoverflow.com/questions/3791398/how-to-stop-python-from-propagating-signals-to-subprocesses
def preexec():
    os.setpgrp()

def launch_get_adapter(fpath_target):
	system = platform.system()

	if system == 'Windows':
		adapt = dbgeng.DebugAdapterDbgeng()
		adapt.exec(fpath_target)
		return adapt

	if system == 'Darwin':
		# resolve path to debugserver
		path_debugserver = shutil.which('debugserver')
		if not path_debugserver:
			path_debugserver = '/Library/Developer/CommandLineTools/Library/' + \
			'PrivateFrameworks/LLDB.framework/Versions/A/Resources/debugserver'
		if not os.path.exists(path_debugserver):
			raise Exception('cannot locate debugserver')

		# get available port
		port = get_available_port()
		if port == None:
			raise Exception('no available ports')

		# invoke debugserver
		args = [path_debugserver, 'localhost:%d'%port, fpath_target]
		try:
			subprocess.Popen(args, stdin=None, stdout=None, stderr=None, preexec_fn=preexec)
		except Exception:
			raise Exception('invoking debugserver (used path: %s)' % path_debugserver)

		# connect to it
		return connect_get_adapter('localhost', port)

	elif system == 'Linux':
		pass

	else:
		raise Exception('unsupported system: %s' % system)

#--------------------------------------------------------------------------
# DISASSEMBLING
#--------------------------------------------------------------------------

def disasm1(data, addr, arch='x86_64'):
	arch = binaryninja.Architecture[arch]
	toksAndLen = arch.get_instruction_text(data, addr)
	if not toksAndLen or toksAndLen[1]==0:
		return None
	toks = toksAndLen[0]
	strs = ''.join(list(map(lambda x: x.text, toks)))
	return [strs, toksAndLen[1]]

def disasm(data, addr, arch='x86_64'):
	if not data:
		return
	lines = []
	offs = 0
	while offs < len(data):
		addrstr = '%s%016X%s' % (GREEN, i.address, NORMAL)
		(asmstr, length) = disasm1(data, addr+offs, arch)
		bytestr = hexlify(data[offs:offs+length]).decode('utf-8').ljust(16)
		asmstr = i.mnemonic + ' ' + i.op_str
		line = '%s: %s %s' % (addrstr, bytestr, asmstr)
		lines.append(line)
		offs += i.size
	return '\n'.join(lines)
