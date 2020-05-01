import re
import socket

# custom exceptions
class RspDisconnected(Exception):
	pass
class RspAckMissing(Exception):
	pass
class RspExpectedStartOfPacket(Exception):
	pass
class RspGeneralError(Exception):
	pass

# rsp connection class
class RspConnection():
	def __init__(self, sock):
		self.sock = sock
		self.acks_enabled = True
		self.server_capabilities = {}
		self.pktlen = 0xfff

	def acks_enable(self):
		self.acks_enabled = True

	def acks_disable(self):
		self.acks_enabled = False

	def ack_expect(self):
		if not self.acks_enabled: return

		resp = self.sock.recv(1)
		if resp == b'':
			raise RspDisconnected('disconnection while waiting for ack')
		if resp != b'+':
			raise RspAckMissing('got instead: %s' % str(resp))
		return b'+'

	def ack_send(self):
		if not self.acks_enabled: return
		self.sock.send(b'+')

	def negotiate(self, client_capabilities):
		# collect all server capabilities as a reply to our client abilities
		reply = self.tx_rx('qSupported:' + client_capabilities)
		for line in reply.split(';'):
			if '=' in line:
				(name, val) = line.split('=')
				self.server_capabilities[name] = val
			else:
				self.server_capabilities[line] = None
		#for (name,val) in self.server_capabilities.items():
		#	print('%s = %s' % (name,val))

		# store the maximum packet length
		self.pktlen = int(self.server_capabilities.get('PacketSize', '0xfff'), 16)

		# turn off acks if supported
		# (lldb appears to support this without advertising it in their capabilities list)
		#if 'QStartNoAckMode+' in self.server_capabilities:
		reply = self.tx_rx('QStartNoAckMode')
		if reply == 'OK':
			self.acks_enabled = False

	def send_raw(self, data: bytes):
		self.sock.send(data.encode('utf-8'))

	def send_payload(self, data: str):
		# packet is "$<data>#<checksum>"
		checksum = sum(map(ord, data)) % 256
		packet = '$' + data + '#' + ("%02x" % checksum)
		self.send_raw(packet)

	def recv_packet_data(self, decode=True):
		hexes = b'abcdefABCDEF0123456789'

		# start packet
		pkt = self.sock.recv(1)
		if pkt != b'$':
			raise RspExpectedStartOfPacket('got instead: %s' % str(pkt))

		# consume until '#' and checksum bytes
		while not (len(pkt)>=3 and pkt[-3] == ord('#') and pkt[-2] in hexes and pkt[-1] in hexes):
			tmp = self.sock.recv(1)
			if tmp == b'':
				raise RspDisconnected('disconnection while receiving packet')
			pkt = pkt + tmp

		# acknowledge
		self.ack_send()

		result = pkt[1:-3].decode('utf-8') if decode else pkt[1:-3]
		return result

	def tx_rx(self, data, expect='ack_then_reply', handler_async_pkt=None):
		try:
			self.send_payload(data)

			reply = None

			if expect == 'nothing':
				reply = ''
			elif expect == 'ack_then_reply':
				self.ack_expect()
				reply = self.recv_packet_data()
			elif expect == 'host_io':
				self.ack_expect()
				reply = self.recv_packet_data(False)
				if reply[0:1] != b'F':
					raise RspGeneralError('host i/o packet did not start with F: ' + str(reply))
				(result_errno, result, errno, attachment) = (None, None, None, None)
				# split off attachment
				if b';' in reply:
					(result_errno, attachment) = reply.split(b';', 1)
					attachment = binary_decode(attachment)
				else:
					result_errno = reply
				# split off errno
				result_errno = result_errno[1:].decode('utf-8')
				if ',' in result_errno:
					(result, errno) = result_errno.split(',')
					errno = int(errno, 16)
				else:
					result = result_errno
				# return result
				result = int(result, 16)
				return(result, errno, attachment)
			elif expect == 'mixed_output_ack_then_reply':
				ack_received = False
				while 1:
					peek1 = self.sock.recv(1, socket.MSG_PEEK)
					if peek1 == b'+':
						if ack_received:
							raise RspGeneralError('received two acks, somethings wrong')
						self.sock.recv(1)
						ack_received = True
						continue

					if peek1 != b'$':
						raise RspExpectedStartOfPacket('got: %s' % self.sock.recv(16))
					reply = self.recv_packet_data()
					if reply[0] == 'O':
						if handler_async_pkt:
							handler_async_pkt(reply)
					else:
						# return first non-output packet
						break
				if not ack_received and self.acks_enabled:
					raise RspGeneralError('expected ack, none received')
				result = reply
			elif expect == 'ack_then_ok':
				self.ack_expect()
				reply = self.recv_packet_data()
				if reply != 'OK':
					raise RspGeneralError('expected OK, got: %s' % reply)
			elif expect == 'ack_then_empty':
				self.ack_expect()
				reply = self.recv_packet_data()
				if reply != '':
					raise RspGeneralError('expected empty, got: %s' % reply)
			else:
				print('dunno how to expect %s' % expect)

			if '*' in reply:
				reply = un_rle(reply)

			return reply

		except OSError:
			raise RspDisconnected('disconnection while transmitting')

	def get_xml(self, fname):
		# https://sourceware.org/gdb/current/onlinedocs/gdb/General-Query-Packets.html#qXfer-target-description-read
		#print('downloading %s' % fname)
		xml = ''
		offs = 0
		pktsize = int(self.server_capabilities.get('PacketSize', '1000'), 16)
		while 1:
			data = self.tx_rx('qXfer:features:read:%s:%X,%X' % (fname, offs, pktsize), 'ack_then_reply')
			if not data[0] in ['l', 'm']:
				raise DebugAdapter.GeneralError('acquiring xml')
			if data[1:]:
				#print('read 0x%X bytes' % len(tmp))
				tmp = un_rle(data[1:])
				xml += tmp
				offs += len(tmp)
			if data[0] == 'l':
				break

		return xml

#--------------------------------------------------------------------------
# GDB RSP FUNCTIONS (HIGHER LEVEL)
#--------------------------------------------------------------------------

# https://sourceware.org/gdb/current/onlinedocs/gdb/Overview.html#Binary-Data
# see "The binary data representation uses..."
def binary_decode(data):
	result = b''
	skip = 0
	for (i,val) in enumerate(data):
		if skip:
			skip = False
		elif val == 0x7d: # '}'
			result += bytes([data[i+1] ^ 0x20])
			skip = True
		elif val == 0x2a: # '*'
			repeat = data[i+1] - 29
			result = result + bytes([result[-1]] * repeat)
			skip = True
		else:
			result += bytes([val])
	return result

def un_rle(data):
	if not '*' in data:
		return data

	skip = 0
	result = ''
	for (i,char) in enumerate(data):
		if skip:
			skip = False
		elif char == '*':
			repeat = ord(data[i+1])-29
			result = result + result[-1]*repeat
			skip = True
		else:
			result += char

	return result

def packet_T_to_dict(data, lookup_reg={}):
	# map the info to a context dictionary
	context = {}
	context['signal'] = int(data[1:3], 16)

	for key_vals in data[3:].split(';'):
		if not key_vals:
			continue

		if not ':' in key_vals:
			raise RspGeneralError('expected \':\' in packet T reply: %s' % key_vals)

		(key, val) = key_vals.split(':')
		val = un_rle(val)

		if key == 'thread':
			tid = None
			if val.startswith('p'):
				if not '.' in val:
					raise RspGeneralError('expected \'.\' in thread value of packet T reply: %s' % reply)
				(core_id, thread_id) = val[1:].split('.')
				# TODO: deal with cores
				context['thread'] = int(thread_id, 16)
			else:
				context['thread'] = int(val, 16)

		elif re.match(r'^[0-9a-fA-F]+$', key):
			rid = int(key, 16)
			reg_name = lookup_reg.get(rid, 'r%d' % rid)
			val = int(''.join(reversed([val[i:i+2] for i in range(0,len(val),2)])), 16)
			context[reg_name] = val
		else:
			# 'metype', 'mecount', 'medata', 'memory', etc.
			context[key] = val

	return context
