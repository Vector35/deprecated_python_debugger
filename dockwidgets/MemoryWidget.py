from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView

import binaryninja
import binaryninjaui
from binaryninja import BinaryView, Symbol, SymbolType, Type, Structure, StructureType
from binaryninjaui import DockContextHandler, UIActionHandler, LinearView, ViewFrame

from . import widget
from .. import binjaplug, ProcessView

class DebugMemoryWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data
		self.memory_view = ProcessView.DebugProcessView(data)

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)

		self.editor = LinearView(self.memory_view, ViewFrame.viewFrameForWidget(self))
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		self.old_symbols = []
		self.old_dvs = set()

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		layout.addWidget(self.editor)
		self.setLayout(layout)

	def notifyOffsetChanged(self, offset):
		pass

	def notifyMemoryChanged(self):
		adapter = binjaplug.get_state(self.bv).adapter
		self.memory_view.mark_dirty()
		# Refresh the editor
		if adapter is None:
			self.editor.navigate(0)
			return
		
		addr_regs = {}
		reg_addrs = {}

		for reg in adapter.reg_list():
			addr = adapter.reg_read(reg)
			reg_symbol_name = '$' + reg

			if addr not in addr_regs.keys():
				addr_regs[addr] = [reg_symbol_name]
			else:
				addr_regs[addr].append(reg_symbol_name)
			reg_addrs[reg] = addr

		for symbol in self.old_symbols:
			# Symbols are immutable so just destroy the old one
			self.memory_view.undefine_auto_symbol(symbol)

		for dv in self.old_dvs:
			self.memory_view.undefine_data_var(dv)

		self.old_symbols = []
		self.old_dvs = set()
		new_dvs = set()

		for (addr, regs) in addr_regs.items():
			symbol_name = "@".join(regs)
			fancy_name = ",".join(regs)
			
			self.memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, addr, fancy_name, raw_name=symbol_name))
			self.old_symbols.append(self.memory_view.get_symbol_by_raw_name(symbol_name))
			new_dvs.add(addr)
		
		for new_dv in new_dvs:
			self.memory_view.define_data_var(new_dv, Type.int(8))
			self.old_dvs.add(new_dv)

		# Special stack frame
		width = reg_addrs['rbp'] - reg_addrs['rsp']
		if width > 0:
			if width > 0x1000:
				width = 0x1000
			struct = Structure()
			struct.type = StructureType.StructStructureType
			struct.width = width
			self.memory_view.undefine_data_var(reg_addrs['rsp'])
			self.memory_view.undefine_data_var(reg_addrs['rbp'])

			for i in range(0, width + 1, self.bv.arch.address_size):
				struct.insert(i, Type.pointer(self.bv.arch, Type.void()))

			self.memory_view.define_data_var(reg_addrs['rsp'], Type.structure_type(struct))
			self.memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, reg_addrs['rsp'], "$stack_frame", raw_name="$stack_frame"))

			self.old_symbols.append(self.memory_view.get_symbol_by_raw_name("$stack_frame"))
			self.old_dvs.add(reg_addrs['rsp'])

		self.editor.navigate(adapter.reg_read('rsp'))

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

