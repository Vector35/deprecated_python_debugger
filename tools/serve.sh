#!/bin/bash

while True;
do
	#debugserver localhost:31337 ~/Downloads/hello || echo "App crashed... restarting..." >&2
	#debugserver localhost:31337 ~/fdumps/workspace/helloworld_thread || echo "App crashed... restarting..." >&2
	debugserver localhost:31337 ~/fdumps/workspace/helloworld || echo "App crashed... restarting..." >&2
	echo "Press Ctrl-C to quit." && sleep .1
done
