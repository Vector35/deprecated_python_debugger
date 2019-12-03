import re

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

def tx_rx(sock, data, expect=None):
	send_packet_data(sock, data)

	if expect == None:
		# require no acknowledgement
		if data[0] in 'fiIkRt':
			pass
		# require simple ack
		elif data[0] in '!ADGHQTX' or data.startswith('vFlashErase') or data.startswith('vFlashWrite'):
			pass
		# return result data or error code
		elif data[0] in '?cCgmMpPsSqvzZ':
			return recv_packet_data(sock)
	else:
		if expect == 'nothing':
			pass
		elif expect == 'ack_then_nothing':
			assert_ack(sock)
		elif expect == 'ack_then_reply':
			assert_ack(sock)
			return recv_packet_data(sock)
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
		reply = tx_rx(sock, 'qRegisterInfo%02X' % i)
		if not reply.startswith('name:'):
			break
		name = re.match(r'^name:(.*?);', reply).group(1)
		#print('reg %d is %s' % (i, name))
		result[i] = name

	return result

def packet_T_to_dict(data):
	if not reg_id_to_name:
		register_info_learn()

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
			reg_name = reg_id_to_name[rid]
			val = int(''.join(reversed([val[i:i+2] for i in range(0,len(val),2)])), 16)
			context[reg_name] = val
		else:
			# 'metype', 'mecount', 'medata', 'memory', etc.
			context[key] = val

	return context

def packet_display(data):
	if not data:
		print('(empty packet)')
		return

	# stdout
	if data[0] == 'O':
		message = unhexlify(data[1:])
		print('stdout message: %s' % message)

	# thread info
	elif data[0] == 'T':
		if data[-1] == ';':
			data = data[0:-1]
		for (key,val) in [x.split(':') for x in data[3:].split(';')]:
			print('%s: %s' % (key, val))

	# exit status
	elif data[0] == 'W':
		exit_status = int(data[1:], 16)
		print('inferior exited with status: %d' % exit_status)
	else:
		print(data)

