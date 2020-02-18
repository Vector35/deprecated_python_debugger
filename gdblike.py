#!/usr/bin/env python3

import os
import re
import sys
import time
import socket
import xml.parsers.expat

from . import rsp
from . import DebugAdapter

#--------------------------------------------------------------------------
# UTILITIES FOR GDB-LIKE ADAPTERS
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

def connect(host, port):
	sock = None

	for tries in range(4):
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect(('localhost', port))
			return sock

		except ConnectionRefusedError:
			# allow quarter second for debugserver to start listening
			time.sleep(.25)

	raise ConnectionRefusedError

def preexec():
    os.setpgrp()

#--------------------------------------------------------------------------
# CLASS FOR GDB-LIKE ADAPTERS
#--------------------------------------------------------------------------

class DebugAdapterGdbLike(DebugAdapter.DebugAdapter):
	def __init__(self, **kwargs):
		DebugAdapter.DebugAdapter.__init__(self, **kwargs)

		# register info
		self.reg_info = {} # eg: 'rip' -> {'id':8, 'width':64}
		self.reg_cache = {} # eg: 'rip' -> 0x400400

		# address -> True
		self.breakpoints = {}

		# client tracks selected thread
		self.tid = None

		# inferred architecture (from xml response, regs, whatever)
		self.arch = None

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
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

	# misc info
	def architecture(self):
		# if stub reported architecture during xml parsing, return it!
		if self.arch:
			return self.arch

		if 'rax' in self.reg_info and 'rip' in self.reg_info:
			return 'x86_64'
		elif 'eax' in self.reg_info and 'eip' in self.reg_info:
			return 'x86'
		elif 'x0' in self.reg_info and 'pc' in self.reg_info:
			return 'aarch64'
		else:
			raise DebugAdapter.GeneralError('determining target architecture')

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
			raise DebugAdapter.GeneralError('no tid set by last stop or thread switch')

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

		# do a general purpose register query
		tmp = self.general_read_registers()
		if not name in tmp:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)
		self.reg_cache.update(tmp)
		return self.reg_cache[name]

		# see if gdb will respond to a single register query
		#id_ = self.reg_info[name]['id']
		#reply = rsp.tx_rx(self.sock, 'p%02x' % id_)
		#if reply != '':
		#	val = int(''.join(reversed([reply[i:i+2] for i in range(0,len(reply),2)])), 16)
		#	self.reg_cache[name] = val # cache result
		#	return val

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
		result = b''
		while(length):
			sz = min(length, 1024) # safely below ethernet MTU 1024
			reply = rsp.tx_rx(self.sock, 'm%x,%x' % (address, sz))
			if reply.startswith('E'):
				raise DebugAdapter.GeneralError('reading from address 0x%X' % address)
			result += bytes.fromhex(reply)
			length -= sz
		return result

	def mem_write(self, address, data):
		payload = 'M%X,%X:%s' % (address, len(data), ''.join(['%02X'%b for b in data]))
		reply = rsp.tx_rx(self.sock, payload)
		if reply != 'OK':
			raise DebugAdapter.GeneralError('writing to address 0x%X' % address)
			return 0

	def mem_modules(self):
		raise NotImplementedError('mem_modules()')

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
		#return self.go_generic('c', self.handler_async_pkt)
		rc = self.go_generic('vCont;c:-1', self.handler_async_pkt)
		self.set_thread_after_stop()
		return rc

	def step_into(self):
		self.reg_cache = {}
		rc = self.go_generic('vCont;s', self.handler_async_pkt)
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
		for id_ in range(max(id2reg.keys())+1):
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
		inarch = False
		def target_xml_start_elem(name, attrs):
			nonlocal subfiles, inarch
			if 'include' in name:
				if name != 'xi:include':
					raise Exception('unknown include tag: %s' % name)
				if not 'href' in attrs:
					raise Exception('include tag attributes contain no href')
				fname = attrs['href']
				#print('found include: %s' % fname)
				subfiles.append(fname)
			if name == 'architecture':
				inarch = True
		def target_xml_end_elem(name):
			nonlocal inarch
			if name == 'architecture':
				inarch = False
		def target_xml_char_data_handler(data):
			nonlocal inarch
			if inarch:
				self.arch = data

		p = xml.parsers.expat.ParserCreate()
		p.StartElementHandler = target_xml_start_elem
		p.EndElementHandler = target_xml_end_elem
		p.CharacterDataHandler = target_xml_char_data_handler
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
			#print(xmltxt)
			p = xml.parsers.expat.ParserCreate()
			p.StartElementHandler = search_reg
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

	# returns (STOP_REASON.XXX, <extra_info>)
	def go_generic(self, gotype, handler_async_pkt=None):
		try:
			if handler_async_pkt is None:
				handler_async_pkt = self.handler_async_pkt
			reply = rsp.tx_rx(self.sock, gotype, 'mixed_output_ack_then_reply', handler_async_pkt)
			(reason, reason_data) = (None, None)

			# thread info
			if reply[0] == 'T':
				tdict = rsp.packet_T_to_dict(reply)
				self.active_thread_tid = tdict['thread']
				signum = tdict.get('signal', 0)
				(reason, reason_data) = \
					(self.os_sig_to_reason.get(signum, DebugAdapter.STOP_REASON.UNKNOWN), signum)

			# exit status
			elif reply[0] == 'W':
				exit_status = int(reply[1:], 16)
				print('inferior exited with status: %d' % exit_status)
				(reason, reason_data) = (DebugAdapter.STOP_REASON.PROCESS_EXITED, exit_status)

			else:
				print(reply)
				(reason, reason_data) = (DebugAdapter.STOP_REASON.UNKNOWN, None)

			return (reason, reason_data)

		except rsp.RspDisconnected:
			return (DebugAdapter.STOP_REASON.BACKEND_DISCONNECTED, None)

	def raw(self, data):
		return rsp.tx_rx(self.sock, data)

	# asynchronously called when inside a "go" to inform us of stdout (and
	# possibly other stuff)
	def handler_async_pkt(self, pkt):
		if pkt.startswith('O'):
			msg = pkt[1:]
			data = ''.join([chr(int(msg[2*x:2*x+2], 16)) for x in range(int(len(msg)/2))])
			if self.cb_stdout is not None:
				self.cb_stdout(data)
			else:
				print(data, end='')
		else:
			print('handler_async_pkt() got unknown packet: %s' % repr(pkt))
