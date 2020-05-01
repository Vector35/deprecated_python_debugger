#!/usr/bin/env python3

# packets supported by MAME stub
# https://github.com/mamedev/mame/blob/master/src/osd/modules/debugger/debuggdbstub.cpp
# ! -
# ? get last stop reason
# c continue
# D detach
# g read general registers
# G write general registers
# H set thread for step,continue,others
# i do one clock cycle
# I signal, then cycle step
# k kill process
# m read mem
# M write mem
# p read reg
# P write reg
# q general query
# s single step
# z remove breakpoint
# Z add breakpoint
#

import os
import re
import shutil
import socket
import subprocess
from struct import pack, unpack

from . import rsp
from . import utils
from . import gdblike
from . import DebugAdapter

class DebugAdapterMameColeco(gdblike.DebugAdapterGdbLike):
	def __init__(self, **kwargs):
		gdblike.DebugAdapterGdbLike.__init__(self, **kwargs)

		self.rsp = None

		self.module_cache = {}

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	def exec(self, path, args=[]):
		raise NotImplementedError('no execute, connect to listening MAME process')

	def connect_continued(self, sock,connection):
		self.sock = sock
		self.rspConn = connection

		self.reg_info_load()

		# no pid, not tid
		self.tid = 0
		self.target_pid_ = 0

	def mem_modules(self, cache_ok=True):
		raise NotImplementedError('no module list on ColecoVision')

	def go(self):
		self.reg_cache = {}
		(reason, reason_data) = self.go_generic('c')
		self.handle_stop(reason, reason_data)
		return (reason, reason_data)

	def step_into(self):
		self.reg_cache = {}
		(reason, reason_data) = self.go_generic('s')
		self.handle_stop(reason, reason_data)
		return (reason, reason_data)

	# thread stuff
	def thread_list(self):
		return [0]

	def thread_selected(self):
		return 0

	def thread_select(self, tid):
		if tid != 0:
			raise DebugAdapter.GeneralError('mame_coleco has only one implicit thread: 0')

	#
	def mem_modules(self):
		#[0000, 2000) - BIOS ROM
		#[2000, 4000) - Expansion Port
		#[4000, 6000) - Expansion Port
		#[6000, 8000) - RAM (1K mapped into 8K)
		#[8000, FFFF] - Cartridge ROM (32K 4 sections, enabled separately)

		# from https://github.com/mamedev/mame/blob/master/src/mame/drivers/coleco.cpp
		# ROM_START (coleco)
		# 	ROM_REGION( 0x10000, "maincpu", 0 )
		# 	ROM_SYSTEM_BIOS( 0, "original", "Original" )
		# 	ROMX_LOAD( "313 10031-4005 73108a.u2", 0x0000, 0x2000, CRC(3aa93ef3) SHA1(45bedc4cbdeac66c7df59e9e599195c778d86a92), ROM_BIOS(0) )
		# 	ROM_SYSTEM_BIOS( 1, "thick", "Thick characters" )
		# 	// differences to 0x3aa93ef3 modified characters, added a pad 2 related fix
		# 	ROMX_LOAD( "colecoa.rom", 0x0000, 0x2000, CRC(39bb16fc) SHA1(99ba9be24ada3e86e5c17aeecb7a2d68c5edfe59), ROM_BIOS(1) )
		# ROM_END

		return {
			'colecoa.rom': 0,
			'ram_mapped.bin': 0x6000,
			'cartridge.rom': 0x8000
		}

	# callbacks
	def thread_stop_pkt_to_reason(self, pkt_data):
		''' callback: given the stop packet data in the form of a "TDICT", return
			a (reason, extra_data) tuple '''
		# pkt_data eg: {'signal': 5, 'r10': 29625, 'r11': 3}
		if pkt_data.get('signal', -1) == 5:
			return (DebugAdapter.STOP_REASON.SINGLE_STEP, None)
		else:
			return (DebugAdapter.STOP_REASON.UNKNOWN, None)

