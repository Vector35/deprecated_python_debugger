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

def send_raw(sock, data):
	sock.send(data.encode('utf-8'))

def send_packet_data(sock, data):
	# packet is exactly "$<data>#<checksum>"
	checksum = sum(map(ord, data))
	packet = '$' + data + '#' + ("%02x" % (checksum % 256))
	send_raw(sock, packet)

def recv_packet_data(sock, decode=True):
	hexes = b'abcdefABCDEF0123456789'

	# consume ack's
	tmp = b'+'
	while tmp == b'+':
		tmp = sock.recv(1)
		if tmp == b'':
			raise RspDisconnected('disconnection while receiving packet')

	# start packet
	pkt = tmp
	if pkt != b'$':
		raise RspExpectedStartOfPacket('got instead: %s' % str(pkt))

	# consume until '#' and checksum bytes
	while not (len(pkt)>=3 and pkt[-3] == ord('#') and pkt[-2] in hexes and pkt[-1] in hexes):
		tmp = sock.recv(1)
		if tmp == b'':
			raise RspDisconnected('disconnection while receiving packet')
		pkt = pkt + tmp

	# acknowledge
	send_raw(sock, '+')

	result = pkt[1:-3].decode('utf-8') if decode else pkt[1:-3]
	return result

def consume_ack(sock):
	resp = sock.recv(1)
	if resp == b'':
		raise RspDisconnected('disconnection while waiting for ack')
	if resp != b'+':
		raise RspAckMissing('got instead: %s' % str(resp))
	return b'+'

#def is_connected(sock):
#	print('testing RSP connection')
#	result = None
#	try:
#		sock.setblocking(0)
#		resp = sock.recv(1, socket.MSG_PEEK)
#		sock.setblocking(1)
#		result = (resp != '')
#	except Exception:
#		result = False
#
#	print('RSP connection status: %s' % str(result))

def tx_rx(sock, data, expect='ack_then_reply', handler_async_pkt=None):
	try:
		send_packet_data(sock, data)

		reply = None

		if expect == 'nothing':
			reply = ''
		elif expect == 'ack_then_reply':
			consume_ack(sock)
			reply = recv_packet_data(sock)
		elif expect == 'host_io':
			consume_ack(sock)
			reply = recv_packet_data(sock, False)
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
				peek1 = sock.recv(1, socket.MSG_PEEK)
				if peek1 == b'+':
					if ack_received:
						raise RspGeneralError('received two acks, somethings wrong')
					sock.recv(1)
					ack_received = True
					continue

				if peek1 != b'$':
					raise RspExpectedStartOfPacket('got: %s' % sock.recv(16))
				reply = recv_packet_data(sock)
				if reply[0] == 'O':
					if handler_async_pkt:
						handler_async_pkt(reply)
				else:
					# return first non-output packet
					break
			if not ack_received:
				raise RspGeneralError('expected ack, none received')
			result = reply
		elif expect == 'ack_then_ok':
			consume_ack(sock)
			reply = recv_packet_data(sock)
			if reply != 'OK':
				raise RspGeneralError('expected OK, got: %s' % reply)
		elif expect == 'ack_then_empty':
			consume_ack(sock)
			reply = recv_packet_data(sock)
			if reply != '':
				raise RspGeneralError('expected empty, got: %s' % reply)
		else:
			print('dunno how to expect %s' % expect)

		if '*' in reply:
			reply = un_rle(reply)

		return reply

	except OSError:
		raise RspDisconnected('disconnection while transmitting')

def send_ack(sock):
	packet = '+'
	sock.send(packet)
	print(packet.decode('utf-8'), '->')

#--------------------------------------------------------------------------
# GDB RSP FUNCTIONS (HIGHER LEVEL)
#--------------------------------------------------------------------------

def register_scan(sock):
	result = [None]*256

	for i in range(256):
		reply = tx_rx(sock, 'qRegisterInfo%02X' % i, 'ack_then_reply')
		if not reply.startswith('name:'):
			break

		info = {}
		for key_vals in reply.split(';'):
			if not key_vals:
				continue

			if not ':' in key_vals:
				raise RspGeneralError('expected \':\' in qRegisterInfo reply: %s' % key_vals)

			(key, val) = key_vals.split(':')

			info[key] = val

		#print('reg %d is %s' % (i, name))
		result[i] = info

	return result

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

