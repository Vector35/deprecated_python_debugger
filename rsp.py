import re
import socket

def send_raw(sock, data):
	sock.send(data.encode('utf-8'))

def send_packet_data(sock, data):
	# packet is exactly "$<data>#<checksum>"
	checksum = sum(map(ord, data))
	packet = '$' + data + '#' + ("%02x" % (checksum % 256))
	send_raw(sock, packet)

def recv_packet_data(sock):
	hexes = b'abcdefABCDEF0123456789'

	# consume ack's
	tmp = b'+'
	while tmp == b'+':
		tmp = sock.recv(1)

	# start packet
	pkt = tmp
	assert pkt == b'$'

	# consume until '#' and checksum bytes
	while not (len(pkt)>=3 and pkt[-3] == ord('#') and pkt[-2] in hexes and pkt[-1] in hexes):
		pkt = pkt + sock.recv(1)

	# acknowledge
	send_raw(sock, '+')

	return pkt[1:-3].decode('utf-8')

def assert_ack(sock):
	ack = sock.recv(1)
	if ack != b'+':
		print('expected ack, got: ', ack)
		assert False

def tx_rx(sock, data, expect='ack_then_reply', handler_async_pkt=None):
	send_packet_data(sock, data)

	if expect == 'nothing':
		pass
	elif expect == 'ack_then_nothing':
		assert_ack(sock)
	elif expect == 'ack_then_reply':
		assert_ack(sock)
		return recv_packet_data(sock)
	elif expect == 'mixed_output_ack_then_reply':
		ack_received = False
		while 1:
			peek1 = sock.recv(1, socket.MSG_PEEK)
			if peek1 == b'+':
				assert not ack_received
				sock.recv(1)
				ack_received = True
				continue

			assert peek1 == b'$'
			reply = recv_packet_data(sock)
			if reply[0] == 'O':
				if handler_async_pkt:
					handler_async_pkt(reply)
			else:
				# return first non-output packet
				break
		assert ack_received
		return reply
	elif expect == 'ack_then_ok':
		assert_ack(sock)
		assert recv_packet_data(sock) == 'OK'
	else:
		print('dunno how to expect %s' % expect)

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
		name = re.match(r'^name:(.*?);', reply).group(1)
		#print('reg %d is %s' % (i, name))
		result[i] = name

	return result

def packet_T_to_dict(data, lookup_reg={}):
	# map the info to a context dictionary
	context = {}
	context['signal'] = int(data[1:3], 16)

	for key_vals in data[3:].split(';'):
		if not key_vals:
			continue

		if not ':' in key_vals:
			print(key_vals)
			assert(0)

		(key, val) = key_vals.split(':')

		if key == 'thread':
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

