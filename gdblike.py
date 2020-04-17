#!/usr/bin/env python3

import os
import re
import sys
import time
import struct
import socket
import binascii
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
			sock.connect((host, port))
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

		# target info
		self.target_arch_ = None
		self.target_pid_ = None
		self.target_path_ = None

		# server capabilities
		self.server_capabilities = {}

	def setup(self):
		pass
	def teardown(self):
		pass

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
	def detach(self):
		try:
			self.rspConn.send_payload('D')
			self.sock.shutdown(socket.SHUT_RDWR)
			self.sock.close()
			self.sock = None
		except rsp.RspDisconnected:
			pass
		except OSError:
			pass

	def quit(self):
		try:
			self.rspConn.send_payload('k')
			self.sock.shutdown(socket.SHUT_RDWR)
			self.sock.close()
			self.sock = None
		except rsp.RspDisconnected:
			pass
		except OSError:
			# eg: [Errno 57] Socket is not connected
			# (example: target has exited, adapter sent code, closed socket already)
			pass

	# target info
	def target_arch(self):
		# if stub reported architecture during xml parsing, return it!
		if self.target_arch_:
			return self.target_arch_

		if 'rax' in self.reg_info and 'rip' in self.reg_info:
			self.target_arch_ = 'x86_64'
		elif 'eax' in self.reg_info and 'eip' in self.reg_info:
			self.target_arch_ = 'x86'
		elif 'x0' in self.reg_info and 'pc' in self.reg_info:
			self.target_arch_ = 'aarch64'
		elif 'r0' in self.reg_info and 'pc' in self.reg_info:
			self.target_arch_ = 'arm'
		else:
			raise DebugAdapter.GeneralError('determining target architecture')

		return self.target_arch_

	def target_path(self):
		if self.target_path_ != None:
			return self.target_path_

		if 'qXfer:exec-file:read+' in self.server_capabilities:
			pktlen = self.rspConn.pktlen
			reply = self.rspConn.tx_rx('qXfer:exec-file:read:%X:0,%X'%(self.target_pid_, pktlen))
			if reply.startswith('l'):
				self.target_path_ = reply[1:]

		return self.target_path_

	def target_pid(self):
		return self.target_pid_

	def target_base(self):
		module2addr = self.mem_modules()

		a = self.target_path()
		if a:
			if a in module2addr: return module2addr[a]
			b = os.path.abspath(a)
			if b in module2addr: return module2addr[b]
			c = os.path.basename(a)
			return module2addr.get(c)

		return None

	# threads
	def thread_list(self):
		result = []
		reply = self.rspConn.tx_rx('qfThreadInfo')
		while 1:
			if reply == 'l': break
			if not reply.startswith('m'):
				raise DebugAdapter.GeneralError("retrieving thread list from server after qfThreadInfo packet")
			tids = reply[1:].split(',')
			tids = list(map(lambda x: int(x,16), tids))
			result += tids
			reply = self.rspConn.tx_rx('qsThreadInfo')

		return result

	def thread_selected(self):
		if self.tid == None:
			raise DebugAdapter.GeneralError('no tid set by last stop or thread switch')

		if self.rspConn.tx_rx('T%X'%self.tid) != 'OK':
			self.tid == None

		return self.tid

	def thread_select(self, tid):
		if self.rspConn.tx_rx('T%X'%self.tid) != 'OK':
			raise DebugAdapter.GeneralError("tid 0x%X is not alive" % tid)

		self.reg_cache = {}

		# set thread for step and continue operations
		payload = 'Hc%x' % tid
		if self.rspConn.tx_rx(payload) != 'OK':
			raise DebugAdapter.GeneralError('setting tid 0x%X for step and continue' % tid)

		# set thread for other operations
		payload = 'Hg%x' % tid
		if self.rspConn.tx_rx(payload) != 'OK':
			raise DebugAdapter.GeneralError('setting tid 0x%X for other operations' % tid)

		#
		self.tid = tid

	# breakpoints
	def breakpoint_set(self, addr):
		if addr in self.breakpoints:
			raise DebugAdapter.BreakpointSetError("breakpoint set at 0x%X already exists" % addr)

		# TODO: somehow see if binja has a read on what arch the given address is,
		# (if within target, use binja analysis, else ???)
		# for now, we'll assume it's the arch in the cpsr for arm architectures
		sw_brk_sz = 1
		if self.target_arch() in ['arm', 'thumb', 'thumb2']:
			cpsr = self.reg_read('cpsr')
			sw_brk_sz = 2 if (cpsr & 0x20) else 4
		data = 'Z0,%x,%d' % (addr, sw_brk_sz)
		reply = self.rspConn.tx_rx(data)
		if reply != 'OK':
			raise DebugAdapter.BreakpointSetError('rsp replied: %s' % reply)
		self.breakpoints[addr] = True
		return 0

	def breakpoint_clear(self, addr):
		if not addr in self.breakpoints:
			raise DebugAdapter.BreakpointClearError("breakpoint clear at 0x%X doesn't exist" % addr)

		sw_brk_sz = 4 if self.target_arch() == 'arm' else 1
		data = 'z0,%x,%d' % (addr, sw_brk_sz)
		reply = self.rspConn.tx_rx(data)
		if reply != 'OK':
			raise DebugAdapter.BreakpointClearError("rsp replied: %s" % reply)

		del self.breakpoints[addr]
		return 0

	def breakpoint_list(self):
		return self.breakpoints

	# register
	def reg_read(self, name):
		if not name in self.reg_info:
			raise DebugAdapter.GeneralError("register %s doesnt exist in target description" % name)

		if name in self.reg_cache:
			#print('RETURNING CACHED VALUE! %s = 0x%X' % (name, self.reg_cache[name]))
			return self.reg_cache[name]

		# do a general purpose register query
		if self.reg_info[name]['group'] == 'general':
			tmp = self.read_reg_general()
			if not name in tmp:
				val = self.read_reg_specific(name)
				if val == None:
					raise DebugAdapter.GeneralError('requested register %s missing from read reply' % name)
				self.reg_cache[name] = val
			else:
				self.reg_cache.update(tmp)
		else:
			val = self.read_reg_specific(name)
			if val == None:
				raise DebugAdapter.GeneralError('requested register %s missing from read reply' % name)
			self.reg_cache[name] = val

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
		payload = 'P%X=%s' % (self.reg_info[name]['id'], valstr)
		reply = self.rspConn.tx_rx(payload)
		if reply != '':
			return

		# otherwise, do a general purpose register query, followed by a set
		blob = self.rspConn.tx_rx('g')
		offset = self.reg_info[name].get('offset')
		if offset == None:
			raise DebugAdapter.GeneralError('requested register %s doesnt have offset' % name)
		a = 2*(offset//8)
		b = 2*((offset+width)//8)
		payload = 'G'+blob[0:a]+valstr+blob[b:]
		reply = self.rspConn.tx_rx(payload)
		if reply != 'OK':
			raise DebugAdapter.GeneralError('setting register %s' % name)

	def reg_list(self):
		return list(self.reg_info.keys())

	def reg_bits(self, name):
		if not name in self.reg_info:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)
		return int(self.reg_info[name]['width'])

	# mem
	def mem_read(self, address, length):
		result = b''
		while(length):
			sz = min(length, 1024) # safely below ethernet MTU 1024
			reply = self.rspConn.tx_rx('m%x,%x' % (address, sz))
			if reply.startswith('E'):
				raise DebugAdapter.GeneralError('reading from address 0x%X' % address)
			result += bytes.fromhex(reply)
			address += sz
			length -= sz
		return result

	def mem_write(self, address, data):
		payload = 'M%X,%X:%s' % (address, len(data), ''.join(['%02X'%b for b in data]))
		reply = self.rspConn.tx_rx(payload)
		if reply != 'OK':
			raise DebugAdapter.GeneralError('writing to address 0x%X' % address)
			return 0

	def mem_modules(self, cache_ok=True):
		# this SHOULD work, but reply is always empty "l<library-list-svr4 version="1.0"/>"
		# and online people have the same issue
		#if 'qXfer:libraries-svr4:read+' in self.server_capabilities:
		#	print(self.rspConn.tx_rx('qXfer:libraries-svr4:read::0,fff'))
		#	...

		raise NotImplementedError('mem_modules()')

	# break
	def break_into(self):
		self.rspConn.send_raw('\x03')
		# TODO: detect error
		return True

	def break_reason(self):
		pkt_T = self.rspConn.tx_rx('?')
		#print(pkt_T)

	# execution control, all return:
	# returns (STOP_REASON.XXX, <extra_info>)
	def go(self):
		self.reg_cache = {}
		#return self.go_generic('c', self.handler_async_pkt)
		(reason, reason_data) = self.go_generic('vCont;c:-1', self.handler_async_pkt)
		self.handle_stop(reason, reason_data)
		return (reason, reason_data)

	def step_into(self):
		self.reg_cache = {}
		(reason, reason_data) = self.go_generic('vCont;s', self.handler_async_pkt)
		self.handle_stop(reason, reason_data)
		return (reason, reason_data)

	def step_over(self):
		# gdb, lldb just doesn't have this, you must synthesize it yourself
		self.reg_cache = {}
		raise NotImplementedError('step over')

	#--------------------------------------------------------------------------
	# helpers, NOT part of the API
	#--------------------------------------------------------------------------
	def test(self):
		print('%X' %self.target_base())
		pass

	def read_reg_general(self):
		result = {}
		id2reg = {self.reg_info[k]['id']: k for k in self.reg_info.keys()}
		reply = self.rspConn.tx_rx('g')
		for id_ in range(max(id2reg.keys())+1):
			reg = id2reg.get(id_)
			if reg == None: continue
			width = self.reg_info[reg]['width']
			nchars = 2*(width//8)
			valstr = reply[0:nchars]
			valstr = ''.join(reversed([valstr[i:i+2] for i in range(0,len(valstr),2)]))
			result[reg] = int(valstr, 16)
			reply = reply[nchars:]
			if not reply: break
		return result

	def read_reg_specific(self, name):
		id_ = self.reg_info[name]['id']
		reply = self.rspConn.tx_rx('p%02x' % id_)
		if reply != '':
			val = int(''.join(reversed([reply[i:i+2] for i in range(0,len(reply),2)])), 16)
			return val

	def handle_stop(self, reason, data):
		if reason in [DebugAdapter.STOP_REASON.PROCESS_EXITED,
			DebugAdapter.STOP_REASON.UNKNOWN, DebugAdapter.STOP_REASON.BACKEND_DISCONNECTED]:
			return

		reply = self.rspConn.tx_rx('?')
		context = rsp.packet_T_to_dict(reply)
		if not 'thread' in context:
			raise DebugAdapter.GeneralError('determing thread responsible for stop')
		self.tid = context.get('thread')

	def get_remote_file(self, fpath):
		#print('get_remote_file(%s)' % fpath)
		#import traceback
		#traceback.print_stack()

		# set filesystem to target's
		(result, errno, attachment) = self.rspConn.tx_rx('vFile:setfs:0', 'host_io')
		if result != 0: raise DebugAdapter.GeneralError('could not set remote filesystem')

		# open
		(fpath, flags, mode) = (''.join(['%02X'%ord(c) for c in fpath]), 0, 0)
		(result, errno, attachment) = self.rspConn.tx_rx('vFile:open:%s,%X,%X' % (fpath, flags, mode), 'host_io')
		if result < 0: raise Exception('unable to open file with host I/O')
		fd = result

		# fstat
		# NOTE: /proc/pid/maps is reported 0 length
		#(result, errno, attachment) = self.rspConn.tx_rx('vFile:fstat:%X'%fd, 'host_io')
		#if result != 0x40: raise Exception('expected 0x40 host io fstat return value')
		#if len(attachment) != 0x40:
		#	raise Exception('returned struct stat is %d bytes, expected 64' % len(attachment))
		#flen = struct.unpack('>I', attachment[32:36])[0]
		#print('file length: %d' % flen)

		# read loop
		data = b''
		offs = 0
		while 1:
			(result, errno, attachment) = self.rspConn.tx_rx('vFile:pread:%X,%X,%X'%(fd,1024,offs), 'host_io')
			if result < 0:
				raise Exception('host i/o pread() failed, result=%d, errno=%d' % (result, errno))
			if result == 0: # EOF
				break
			if result != len(attachment):
				raise Exception('host i/o pread() returned 0x%X but decoded binary attachment is size 0x%X' % \
				  (result, len(attachment)))
			data += attachment
			offs += len(attachment)

		# close
		(result, errno, attachment) = self.rspConn.tx_rx('vFile:close:%d'%fd, 'host_io')
		if result != 0:
			raise Exception('host i/o close() failed, result=%d, errno=%d' % (result, errno))

		# done
		return data

	def get_xml(self, fname):
		# https://sourceware.org/gdb/current/onlinedocs/gdb/General-Query-Packets.html#qXfer-target-description-read
		#print('downloading %s' % fname)
		xml = ''
		offs = 0
		pktsize = int(self.server_capabilities.get('PacketSize', '1000'), 16)
		while 1:
			data = self.rspConn.tx_rx('qXfer:features:read:%s:%X,%X' % (fname, offs, pktsize), 'ack_then_reply')
			if not data[0] in ['l', 'm']:
				raise DebugAdapter.GeneralError('acquiring register description xml')
			if data[1:]:
				#print('read 0x%X bytes' % len(tmp))
				tmp = rsp.un_rle(data[1:])
				xml += tmp
				offs += len(tmp)
			if data[0] == 'l':
				break

		#fpath = '/tmp/' + fname
		#print('saving %s' % fpath)
		#with open(fpath, 'w') as fp:
		#	fp.write(xml)

		return xml

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
				if data == 'i386:x86-64':
					data = 'x86_64'
				self.target_arch_ = data

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
		general_group_id = None
		def search_reg(name, attrs):
			nonlocal regnum, general_group_id
			if name == 'reg':
				regname = attrs['name']
				if 'regnum' in attrs:
					regnum = int(attrs['regnum'])
				else:
					# regnum is the running value
					pass
				bitsize = None
				if 'bitsize' in attrs:
					bitsize = int(attrs['bitsize'])

				# latch on first group/group_id mapping
				if general_group_id == None:
					if attrs.get('group') == 'general' and 'group_id' in attrs:
						general_group_id = attrs['group_id']

				group = attrs.get('group')
				if group == 'general' and (not attrs['group_id'] == general_group_id):
					group = 'unknown'

				#print('assigning reg %s num=%d group=%s' % (regname, regnum, group))
				self.reg_info[regname] = {'id':regnum, 'width':bitsize, 'group':group}

				# running value
				regnum += 1

		# parse targets.xml
		p = xml.parsers.expat.ParserCreate()
		p.StartElementHandler = search_reg
		p.Parse(xmltxt)

		# parse targets.xml include files
		for fname in subfiles:
			xmltxt = self.get_xml(fname)
			p = xml.parsers.expat.ParserCreate()
			p.StartElementHandler = search_reg
			p.Parse(xmltxt)

		# if NO group information existed in the XML info, make everything general
		# (this is observed on armv7/aarch64 over Android)
		if general_group_id == None:
			for reg_name in self.reg_info:
				self.reg_info[reg_name]['group'] = 'general'

		# calculate bit offset per register within a concatenated registers blob
		id2name = {self.reg_info[k]['id']: k for k in self.reg_info.keys()}
		id2width = {v['id']: v['width'] for v in self.reg_info.values()}

		if id2width:
			id_max = max(id2width.keys())

			offset = 0
			for i in range(id_max):
				if not i in id2width: # non-sequential id, can't know offset
					break

				name = id2name[i]
				self.reg_info[name]['offset'] = offset
				offset += id2width[i]
		else:
			pass
			# consider raising exception, not reg info in returned xml, something is wrong
			# observed this with gdbserver-armv7 paired with aarch64 inferior

		#for reg in sorted(self.reg_info, key=lambda x: self.reg_info[x]['id']):
		#	print('%s id=%d width=%d' % (reg, self.reg_info[reg]['id'], self.reg_info[reg]['width']))

	# more specific gdb's should override this
	# for example, lldb might want to check for 'metype' and 'medata' keys
	def thread_stop_pkt_to_reason(self, pkt_data):
		return (DebugAdapter.STOP_REASON.UNKNOWN, None)

	# returns (STOP_REASON.XXX, <extra_info>)
	def go_generic(self, gotype, handler_async_pkt=None):
		try:
			if handler_async_pkt is None:
				handler_async_pkt = self.handler_async_pkt
			reply = self.rspConn.tx_rx(gotype, 'mixed_output_ack_then_reply', handler_async_pkt)
			(reason, reason_data) = (DebugAdapter.STOP_REASON.UNKNOWN, None)

			# thread info
			# https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
			if reply[0] == 'T':
				tdict = rsp.packet_T_to_dict(reply)
				self.active_thread_tid = tdict['thread']
				(reason, reason_data) = self.thread_stop_pkt_to_reason(tdict)

			# exit status
			elif reply[0] == 'W':
				exit_status = int(reply[1:], 16)
				#print('gdblike: inferior exited with status: %d' % exit_status)
				(reason, reason_data) = (DebugAdapter.STOP_REASON.PROCESS_EXITED, exit_status)

			else:
				# TODO: somehow raise concern here
				print(reply)

			return (reason, reason_data)

		except rsp.RspDisconnected:
			return (DebugAdapter.STOP_REASON.BACKEND_DISCONNECTED, None)

	def raw(self, data):
		return self.rspConn.tx_rx(data)

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
