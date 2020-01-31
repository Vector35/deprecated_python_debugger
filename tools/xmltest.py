#!/usr/bin/env python3
#
# POC download/parse description xml's from gdb

import sys
import socket
import xml.parsers.expat

sys.path.append('..')
import rsp

def get_xml(sock, fname):
	print('downloading %s' % fname)
	data = rsp.tx_rx(sock, 'qXfer:features:read:%s:0,fff' % fname, 'ack_then_reply')
	assert data[0] == 'l'
	data = rsp.un_rle(data[1:])
	return data

def download_xml(sock, fname):
	with open(fname, 'w') as fp:
		xmltxt = get_xml(sock, fname)
		print('writing %s' % fname)
		fp.write(xmltxt)

def parse_target_xml(sock):
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
			print('found include: %s' % fname)
			subfiles.append(fname)

	p = xml.parsers.expat.ParserCreate()
	p.StartElementHandler = search_include
	xmltxt = get_xml(sock, 'target.xml')
	print(xmltxt)
	p.Parse(xmltxt)

	#
	# collect registers referenced in all subfiles
	#
	regnum = 0
	regname2num = {}
	def search_reg(name, attrs):
		nonlocal regnum, regname2num
		if name == 'reg':
			regname = attrs['name']
			if 'regnum' in attrs:
				regnum = int(attrs['regnum'])
				print('-------- fast-forwarding regnum to %d' % regnum)
			if 'bitsize' in attrs:
				bitsize = int(attrs['bitsize'])
				print('has bitsize %d' % bitsize)
			print('assigning reg %s num %d' % (regname, regnum))
			regname2num[regname] = regnum
			regnum += 1

	for fname in subfiles:
		print('acquiring %s' % fname)
		xmltxt = get_xml(sock, fname)
		p = xml.parsers.expat.ParserCreate()
		p.StartElementHandler = search_reg
		p.Parse(xmltxt)

	#
	# done
	#
	for (name,num) in sorted(regname2num.items(), key=lambda x: x[1]):
		print('%d: %s' % (num, name))


if __name__ == '__main__':
	port = 31337
	if sys.argv[1:]:
		port = int(sys.argv[1])

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(('localhost', port))
	reply = rsp.tx_rx(sock, 'Hgp0.0')
	parse_target_xml(sock)
	sock.close()

