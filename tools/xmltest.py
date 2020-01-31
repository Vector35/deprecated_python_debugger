#!/usr/bin/env python3
#
# POC download/parse description xml's from gdb

import sys
import rsp
import socket
import xml.parsers.expat

def get_xml(sock, fname):
	print('downloading %s' % fname)
	data = rsp.tx_rx(sock, 'qXfer:features:read:%s:0,fff' % fname, 'ack_then_reply')
	assert data[0] == 'l'
	return data[1:]

def download_xml(sock, fname):
	with open(fname, 'w') as fp:
		xmltxt = get_xml(sock, fname)
		print('writing %s' % fname)
		fp.write(xmltxt)

def parse_target_xml(sock):
	subfiles = []

	def start_element(name, attrs):
	    #print('Start element:', name, attrs)
	    if 'include' in name:
	    	if name != 'xi:include':
	    		raise Exception('unknown include tag: %s' % name)
	    	if not 'href' in attrs:
	    		raise Exception('include tag attributes contain no href')
	    	fname = attrs['href']
	    	subfiles.append(fname)
	def end_element(name):
	    #print('End element:', name)
	    pass
	
	def char_data(data):
	    #print('Character data:', repr(data))
	    pass

	p = xml.parsers.expat.ParserCreate()
	p.StartElementHandler = start_element
	p.EndElementHandler = end_element
	p.CharacterDataHandler = char_data

	xmltxt = get_xml(sock, 'target.xml') 
	p.Parse(xmltxt)

	for fname in subfiles:
		download_xml(sock, fname)

if __name__ == '__main__':
	port = 31337
	if sys.argv[1:]:
		port = int(sys.argv[1])

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(('localhost', port))

	#reply = rsp.tx_rx(sock, 'qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386', 'ack_then_reply')
	#print(reply)
#<- +
#<- $PacketSize=3fff;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;QCatchSyscalls+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:spu:read+;qXfer:spu:write+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;fork-events+;vfork-events+;exec-events+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;FastTracepoints+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+;swbreak+;hwbreak+;qXfer:exec-file:read+;vContSupported+;QThreadEvents+;no-resumed+#f1
#-> +
#-> $vMustReplyEmpty#3a
	#reply = rsp.tx_rx(sock, 'vMustReplyEmpty', 'ack_then_reply')	
#<- +
#<- $#00
#-> +
#-> $QStartNoAckMode#b0
#<- +
#<- $OK#9a
#-> +
#-> $QProgramSignals:0;1;3;4;6;7;8;9;a;b;c;d;e;f;10;11;12;13;14;15;16;17;18;19;1a;1b;1c;1d;1e;1f;20;21;22;23;24;25;26;27;28;29;2a;2b;2c;2d;2e;2f;30;31;32;33;34;35;36;37;38;39;3a;3b;3c;3d;3e;3f;40;41;42;43;44;45;46;47;48;49;4a;4b;4c;4d;4e;4f;50;51;52;53;54;55;56;57;58;59;5a;5b;5c;5d;5e;5f;60;61;62;63;64;65;66;67;68;69;6a;6b;6c;6d;6e;6f;70;71;72;73;74;75;76;77;78;79;7a;7b;7c;7d;7e;7f;80;81;82;83;84;85;86;87;88;89;8a;8b;8c;8d;8e;8f;90;91;92;93;94;95;96;97;98;99;9a;#a3
	#reply = rsp.tx_rx(sock, 'QProgramSignals:0;1;3;4;6;7;8;9;a;b;c;d;e;f;10;11;12;13;14;15;16;17;18;19;1a;1b;1c;1d;1e;1f;20;21;22;23;24;25;26;27;28;29;2a;2b;2c;2d;2e;2f;30;31;32;33;34;35;36;37;38;39;3a;3b;3c;3d;3e;3f;40;41;42;43;44;45;46;47;48;49;4a;4b;4c;4d;4e;4f;50;51;52;53;54;55;56;57;58;59;5a;5b;5c;5d;5e;5f;60;61;62;63;64;65;66;67;68;69;6a;6b;6c;6d;6e;6f;70;71;72;73;74;75;76;77;78;79;7a;7b;7c;7d;7e;7f;80;81;82;83;84;85;86;87;88;89;8a;8b;8c;8d;8e;8f;90;91;92;93;94;95;96;97;98;99;9a;', 'ack_then_reply')
#<- $OK#9a
#-> $Hgp0.0#ad
	reply = rsp.tx_rx(sock, 'Hgp0.0')
#<- $OK#9a
#-> $qXfer:features:read:target.xml:0,fff#7d

	parse_target_xml(sock)	

	#reply = rsp.tx_rx(sock, 'qXfer:features:read:target.xml:0,fff', 'ack_then_reply')
	#print(reply)

	sock.close()





