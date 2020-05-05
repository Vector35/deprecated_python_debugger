#!/usr/bin/env python
#
# display live code coverage of DACMAN Colecovision game running in MAME
# drawn as Hilbert curve
#
# $ mame -v coleco -video soft -cart /path/to/DACMAN.ROM -window -nomax -resolution 560x432 -debugger gdbstub -debug
# $ ./dacman_live_hilbert /path/to/DACMAN.ROM
#

import os
import sys
import math
import time
import struct
import platform
from collections import defaultdict

import binaryninja
from binaryninja.binaryview import BinaryViewType

from PIL import Image, ImageDraw

# globals
n = None
draw = None

#------------------------------------------------------------------------------
# Hilbert curve mapping algorithms from:
# https://en.wikipedia.org/wiki/Hilbert_curve
#------------------------------------------------------------------------------

def rot(n, x, y, rx, ry):
	if ry == 0:
		if rx == 1:
			x = n-1 - x;
			y = n-1 - y;

		(y,x) = (x,y)

	return (x,y)

def d2xy(n, d):
	(x,y,t) = (0,0,d)

	level = 1
	while level<n:
		rx = 1 & (t//2)
		ry = 1 & (t ^ rx)
		(x, y) = rot(level, x, y, rx, ry)
		x += level * rx
		y += level * ry
		t //= 4
		level *= 2

	return (x,y)

def xy2d(n, x, y):
	(rx,ry,s,d)=(0,0,0,0)

	s = n//2
	while s > 0:
		rx = int((x & s) > 0)
		ry = int((y & s) > 0)
		d += s * s * ((3 * rx) ^ ry)
		(x, y) = rot(n, x, y, rx, ry)
		s //= 2

	return d

#------------------------------------------------------------------------------
# Hilbert curve drawing helpers
#------------------------------------------------------------------------------

# trace a Hilbert region by "wall following"
def wall_follower(d0, d1):
	global n

	def ok(x, y):
		if x<0 or y<0: return False
		d = xy2d(n**2, x, y)
		#print('is %d within %d,%d' % (d, d0, d1))
		return d>=0 and d>=d0 and d<d1

	# move left until stop
	(x,y) = d2xy(n**2, d0)
	while 1:
		if x == 0: break
		if not ok(x-1,y): break
		x = x-1

	start = (x,y)
	trace = [start]
	direction = 'down'

	tendencies = ['right', 'down', 'left', 'up']

	while 1:
		#print('at (%d,%d) heading %s' % (x,y,direction))

		tendency = tendencies[(tendencies.index(direction)+1) % 4]

		xmod = {'right':1, 'down':0, 'left':-1, 'up':0}
		ymod = {'right':0, 'down':-1, 'left':0, 'up':1}

		moved = False

		# case A: we can turn right
		x_try = x+xmod[tendency]
		y_try = y+ymod[tendency]
		if ok(x_try, y_try):
			direction = tendency
			(x,y) = (x_try, y_try)
			moved = True
		else:
			# case B: we can continue in current direction
			x_try = x+xmod[direction]
			y_try = y+ymod[direction]
			if ok(x_try, y_try):
				(x,y) = (x_try, y_try)
				moved = True
			else:
				# case C: we can't continue! ah!
				direction = tendencies[(tendencies.index(direction)-1)%4]

		if moved:
			trace.append((x,y))
			
			if (x,y) == start:
				break

	return trace

# [start, stop)
def draw_hilbert(start, stop, color='#ffffff'):
	global n
	global draw

	pts = [d2xy(n, x) for x in range(start, stop)]
	lines = zip(pts[:-1], pts[1:])
	for line in lines:
		((x1,y1),(x2,y2)) = line
		#print('drawing line (%d,%d) -> (%d,%d)' % (x1,y1,x2,y2))
		draw.line((x1,y1,x2,y2), width=1, fill=color)

def draw_region(start, stop, color1='#00ff00', color2=None):
	global draw
	trace = wall_follower(start, stop)
	draw.polygon(trace, outline=color1, fill=color2)

#------------------------------------------------------------------------------
# main()
#------------------------------------------------------------------------------

if __name__ == '__main__':
	# analyze functions
	fpath = sys.argv[1]
	bv = BinaryViewType.get_view_of_file(fpath)
	bv.update_analysis_and_wait()
	lowest = None
	highest = None
	addr2func = {}
	for f in bv.functions:
		addr_start = f.start
		addr_end = f.start + f.total_bytes

		if lowest==None or addr_start < lowest:
			lowest = addr_start
		if highest==None or addr_end >= highest:
			highest = addr_end

		addr2func[addr_start] = f

	print('lowest address: 0x%04X' % lowest)
	print('highest address: 0x%04X' % highest)

	# launch debugger, set breakpoints
	from debugger import DebugAdapter, gdblike
	adapter = gdblike.connect_sense('localhost', 23946)
	for addr in addr2func:
		print('setting breakpoint at %04X: %s' % (addr, addr2func[addr].symbol.full_name))
		adapter.breakpoint_set(addr)

	# calculate image size
	pixels = 1
	while pixels < (highest-lowest):
		pixels *= 4
	n = int(math.sqrt(pixels))
	print('n:', n)
	img = Image.new('RGB', (n,n))
	draw = ImageDraw.Draw(img)

	# intialize pygame
	import pygame
	from pygame.locals import *	
	pygame.init()
	surface = pygame.display.set_mode((4*n, 4*n), RESIZABLE)
	pygame.display.set_caption('DACMAN code coverage')

	# palette is "tab20" from matplotlib
	palette_i = 0
	palette = [
		'#1F77B4', '#AEC7E8', '#FF7F0E', '#FFBB78', '#2CA02C', '#98DF8A', '#D62728', '#FF9896',
		'#9467BD', '#C5B0D5', '#8C564B', '#C49C94', '#E377C2', '#F7B6D2', '#7F7F7F', '#C7C7C7',
		'#BCBD22', '#DBDB8D', '#17BECF', '#9EDAE5'
	]

	print('reading to rock, press any key!')
	input()

	while 1:
		# process pygame events
		for event in pygame.event.get():
			if event.type == QUIT:
				pygame.quit()
				sys.exit()

		# wait for breakpoint, clear it
		(reason, data) = adapter.go()
		assert reason in [DebugAdapter.STOP_REASON.BREAKPOINT, DebugAdapter.STOP_REASON.SINGLE_STEP]
		pc = adapter.reg_read('pc')
		f = addr2func[pc]
		print('%s()' % f.symbol.full_name)
		adapter.breakpoint_clear(pc)

		# draw function
		addr_start = f.start
		addr_end = f.start + f.total_bytes
		if addr_end - addr_start < 4:
			continue
		print('drawing %s [0x%04X, 0x%04X)' % (f.symbol.full_name, addr_start, addr_end))
		draw_region(addr_start - lowest, addr_end - lowest, None, palette[palette_i])
		palette_i = (palette_i+1) % len(palette)

		# drawing to pygame
		raw_str = img.tobytes('raw', 'RGB')
		img_surface = pygame.image.fromstring(raw_str, (n, n), 'RGB')
		img_surface = pygame.transform.scale(img_surface, (4*n, 4*n))
		surface.blit(img_surface, (0,0))
		pygame.display.update()

		#time.sleep(.1)
