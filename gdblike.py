#!/usr/bin/env python3

import re
import socket
from struct import pack, unpack
from binascii import hexlify, unhexlify
import xml.parsers.expat

from . import rsp
from . import DebugAdapter

# asynchronously called when inside a "go" to inform us of stdout (and
# possibly other stuff)
def handler_async_pkt(pkt):
	if pkt.startswith('O'):
		msg = pkt[1:]
		print(''.join([chr(int(msg[2*x:2*x+2], 16)) for x in range(int(len(msg)/2))]), end='')
	else:
		print('handler_async_pkt() got unknown packet: %s' % repr(pkt))

class DebugAdapterGdbLike(DebugAdapter.DebugAdapter):
	def __init__(self, **kwargs):
		host = kwargs.get('host', 'localhost')
		port = kwargs.get('port', 31337)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((host, port))

		# register info
		self.reg_info = {} # eg: 'rip' -> {'id':8, 'width':64}
		self.reg_cache = {} # eg: 'rip' -> 0x400400

		# address -> True
		self.breakpoints = {}

		# client tracks selected thread
		self.tid = None

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
	def exec(self, path):
		# TODO: find/launch gdb/debugserver
		pass

	def attach(self, pid):
		# TODO: find/launch gdb/debugserver
		pass

	def detach(self):
		try:
			rsp.send_packet_data(self.sock, 'D')
			self.sock.shutdown(socket.SHUT_RDWR)
			self.sock.close()
			self.sock = None
		except rsp.RspDisconnected:
			pass

	def quit(self):
		try:
			rsp.send_packet_data(self.sock, 'k')
			self.sock.shutdown(socket.SHUT_RDWR)
			self.sock.close()
			self.sock = None
		except rsp.RspDisconnected:
			pass

	# threads
	def thread_list(self):
		result = []
		reply = rsp.tx_rx(self.sock, 'qfThreadInfo')
		while 1:
			if reply == 'l': break
			if not reply.startswith('m'):
				raise DebugAdapter.GeneralError("retrieving thread list from server after qfThreadInfo packet")
			tids = reply[1:].split(',')
			tids = list(map(lambda x: int(x,16), tids))
			result += tids
			reply = rsp.tx_rx(self.sock, 'qsThreadInfo')

		return result

	def thread_selected(self):
		if self.tid == None:
			return None

		if rsp.tx_rx(self.sock, 'T%X'%self.tid) != 'OK':
			self.tid == None

		return self.tid

	def thread_select(self, tid):
		if rsp.tx_rx(self.sock, 'T%X'%self.tid) != 'OK':
			raise DebugAdapter.GeneralError("tid 0x%X is not alive" % tid)

		self.reg_cache = {}

		# set thread for step and continue operations
		payload = 'Hc%x' % tid
		if rsp.tx_rx(self.sock, payload) != 'OK':
			raise DebugAdapter.GeneralError('setting tid 0x%X for step and continue' % tid)

		# set thread for other operations
		payload = 'Hg%x' % tid
		if rsp.tx_rx(self.sock, payload) != 'OK':
			raise DebugAdapter.GeneralError('setting tid 0x%X for other operations' % tid)

		#
		self.tid = tid

	# breakpoints
	def breakpoint_set(self, addr):
		if addr in self.breakpoints:
			raise DebugAdapter.BreakpointSetError("breakpoint set at 0x%X already exists" % addr)

		data = 'Z0,%x,1' % addr
		reply = rsp.tx_rx(self.sock, data)
		if reply != 'OK':
			raise DebugAdapter.BreakpointSetError('rsp replied: %s' % reply)
		self.breakpoints[addr] = True
		return 0

	def breakpoint_clear(self, addr):
		if not addr in self.breakpoints:
			raise DebugAdapter.BreakpointClearError("breakpoint clear at 0x%X doesn't exist" % addr)

		data = 'z0,%x,1' % addr
		reply = rsp.tx_rx(self.sock, data)
		if reply != 'OK':
			raise DebugAdapter.BreakpointClearError("rsp replied: %s" % reply)

		del self.breakpoints[addr]
		return 0

	def breakpoint_list(self):
		return self.breakpoints

	# register
	def reg_read(self, name):
		if not name in self.reg_info:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)

		if name in self.reg_cache:
			#print('RETURNING CACHED VALUE! %s = 0x%X' % (name, self.reg_cache[name]))
			return self.reg_cache[name]

		# see if gdb will respond to a single register query
		id_ = self.reg_info[name]['id']
		reply = rsp.tx_rx(self.sock, 'p%02x' % id_)
		if reply != '':
			val = int(''.join(reversed([reply[i:i+2] for i in range(0,len(reply),2)])), 16)
			self.reg_cache[name] = val # cache result
			return val

		# otherwise, do a general purpose register query
		tmp = self.general_read_registers()
		if not name in tmp:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)
		for (k,v) in tmp.items():
			self.reg_cache[k] = v # cache update
		return self.reg_cache[name]

	def reg_write(self, name, value):
		if not name in self.reg_info:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)

		del self.reg_cache[name]

		width = self.reg_info[name]['width']
		fmtstrs = {8:'%02X', 16:'%04X', 32:'%08X', 64:'%016X'}
		valstr = fmtstrs[width] % value
		valstr = [valstr[i:i+2] for i in range(0,len(valstr),2)]
		valstr = ''.join(reversed(valstr))

		# see if gdb will respond to a single register set
		payload = 'P%d=%s' % (self.reg_info[name]['id'], valstr)
		reply = rsp.tx_rx(self.sock, payload)
		if reply != '':
			return

		# otherwise, do a general purpose register query, followed by a set
		blob = rsp.tx_rx(self.sock, 'g')
		offset = self.reg_info[name].get('offset')
		if offset == None:
			raise DebugAdapter.GeneralError('requested register %s doesnt have offset' % name)
		a = 2*(offset//8)
		b = 2*((offset+width)//8)
		payload = 'G'+blob[0:a]+valstr+blob[b:]
		reply = rsp.tx_rx(self.sock, payload)
		if reply != 'OK':
			raise DebugAdapter.GeneralError('setting register %s' % name)

	def reg_list(self):
		return self.reg_info.keys()

	def reg_bits(self, name):
		if not name in self.reg_info:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)
		return int(self.reg_info[name]['width'])

	# mem
	def mem_read(self, address, length):
		packed = b''

		while(length):
			chunk = min(length, 256)

			data = 'm' + ("%x" % address) + ',' + ("%x" % chunk)
			reply = rsp.tx_rx(self.sock, data)
			if reply.startswith('E'): # error 'E' differentiated from hex 'e' by case
				# and len(reply)==3:
				raise DebugAdapter.GeneralError('reading from address 0x%X' % address)

			while(reply):
				packed += pack('B', int(reply[0:2],16))
				reply = reply[2:]

			length -= chunk

		return packed

	def mem_write(self, address, data):
		payload = 'M%X,%X:%s' % (address, len(data), ''.join(['%02X'%b for b in data]))
		reply = rsp.tx_rx(self.sock, payload)
		if reply != 'OK':
			raise DebugAdapter.GeneralError('writing to address 0x%X' % address)
			return 0

	def mem_modules(self):
		module2addr = {}
		reply = rsp.tx_rx(self.sock, 'jGetLoadedDynamicLibrariesInfos:{"fetch_all_solibs":true}')
		for (addr, path) in re.findall(r'"load_address":(\d+).*?"pathname":"([^"]+)"', reply):
			addr = int(addr, 10)
			module2addr[path] = addr
		return module2addr

	# break
	def break_into(self):
		rsp.send_raw(self.sock, '\x03')
		# TODO: detect error
		return True

	def break_reason(self):
		pkt_T = rsp.tx_rx(self.sock, '?')
		#print(pkt_T)

	# execution control, all return:
	# returns (STOP_REASON.XXX, <extra_info>)
	def go(self):
		self.reg_cache = {}
		#return self.go_generic('c', handler_async_pkt)
		rc = self.go_generic('vCont;c:-1', handler_async_pkt)
		self.set_thread_after_stop()
		return rc

	def step_into(self):
		self.reg_cache = {}
		rc = self.go_generic('vCont;s', handler_async_pkt)
		self.set_thread_after_stop()
		return rc

	def step_over(self):
		# gdb, lldb just doesn't have this, you must synthesize it yourself
		self.reg_cache = {}
		self.set_thread_after_stop()
		raise NotImplementedError('step over')

	#--------------------------------------------------------------------------
	# helpers, NOT part of the API
	#--------------------------------------------------------------------------
	def general_read_registers(self):
		result = {}

		id2reg = {self.reg_info[k]['id']: k for k in self.reg_info.keys()}
		reply = rsp.tx_rx(self.sock, 'g')
		for id_ in range(max(id2reg.keys())):
			reg = id2reg.get(id_)
			if reg == None: break
			width = self.reg_info[reg]['width']
			nchars = 2*(width//8)
			valstr = reply[0:nchars]
			valstr = ''.join(reversed([valstr[i:i+2] for i in range(0,len(valstr),2)]))
			result[reg] = int(valstr, 16)
			reply = reply[nchars:]
			if not reply: break

		return result

	def set_thread_after_stop(self):
		reply = rsp.tx_rx(self.sock, '?')
		context = rsp.packet_T_to_dict(reply)
		if not 'thread' in context:
			raise DebugAdapter.GeneralError('determing thread responsible for stop')
		self.tid = context.get('thread')

	def get_xml(self, fname):
		#print('downloading %s' % fname)
		data = rsp.tx_rx(self.sock, 'qXfer:features:read:%s:0,fff' % fname, 'ack_then_reply')
		if not data[0] in ['l', 'm']:
			raise DebugAdapter.GeneralError('acquiring register description xml')
		data = rsp.un_rle(data[1:])
		return data

	# See G.2.7 Registers for what's going on here
	# https://sourceware.org/gdb/current/onlinedocs/gdb/Target-Description-Format.html#Target-Description-Format
	def reg_info_load(self, force=False):
		# if we've already sensed the registers, return
		if not force and self.reg_info:
			return

		#
		# collect subfiles included from target.xml
		#
		subfiles = []
		def search_include(name, attrs):
			nonlocal subfiles
			if 'include' in name:
				if name != 'xi:include':
					raise Exception('unknown include tag: %s' % name)
				if not 'href' in attrs:
					raise Exception('include tag attributes contain no href')
				fname = attrs['href']
				#print('found include: %s' % fname)
				subfiles.append(fname)

		p = xml.parsers.expat.ParserCreate()
		p.StartElementHandler = search_include
		xmltxt = self.get_xml('target.xml')
		#print(xmltxt)
		p.Parse(xmltxt)

		#
		# collect registers referenced in all subfiles
		#
		regnum = 0
		self.reg_info = {}
		def search_reg(name, attrs):
			nonlocal regnum
			if name == 'reg':
				regname = attrs['name']
				if 'regnum' in attrs:
					regnum = int(attrs['regnum'])
					#print('-------- fast-forwarding regnum to %d' % regnum)
				bitsize = None
				if 'bitsize' in attrs:
					bitsize = int(attrs['bitsize'])
					#print('has bitsize %d' % bitsize)
				#print('assigning reg %s num %d' % (regname, regnum))
				self.reg_info[regname] = {'id':regnum, 'width':bitsize}
				regnum += 1

		p = xml.parsers.expat.ParserCreate()
		p.StartElementHandler = search_reg
		p.Parse(xmltxt)
		for fname in subfiles:
			#print('acquiring %s' % fname)
			xmltxt = self.get_xml(fname)
			p.Parse(xmltxt)

		#
		# calculate bit offset per register within a concatenated registers blob
		#
		id2name = {self.reg_info[k]['id']: k for k in self.reg_info.keys()}
		id2width = {v['id']: v['width'] for v in self.reg_info.values()}
		id_max = max(id2width.keys())

		offset = 0
		for i in range(id_max):
			if not i in id2width: # non-sequential id, can't know offset
				break

			name = id2name[i]
			self.reg_info[name]['offset'] = offset
			offset += id2width[i]

		#for reg in sorted(self.reg_info, key=lambda x: self.reg_info[x]['id']):
		#	print('%s id=%d width=%d' % (reg, self.reg_info[reg]['id'], self.reg_info[reg]['width']))

