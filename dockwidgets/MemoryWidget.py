from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView

import binaryninja
import binaryninjaui
from binaryninja import BinaryView, Symbol, SymbolType, Type
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
		if adapter:
			self.editor.navigate(adapter.reg_read('rbp'))
		else:
			self.editor.navigate(0)

		old_dvs = set()
		new_dvs = set()

		for reg in adapter.reg_list():
			addr = adapter.reg_read(reg)
			reg_symbol_name = '$' + reg

			reg_symbol = self.memory_view.get_symbol_by_raw_name(reg_symbol_name)
			if reg_symbol is not None:
				# Symbols are immutable so just destroy the old one
				self.memory_view.undefine_auto_symbol(reg_symbol)
				old_dvs.add(reg_symbol.address)
			
			self.memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, addr, reg_symbol_name, raw_name=reg_symbol_name))
			new_dvs.add(addr)
		
		for old_dv in old_dvs.difference(new_dvs):
			self.memory_view.undefine_data_var(old_dv)
		for new_dv in new_dvs.difference(old_dvs):
			self.memory_view.define_data_var(new_dv, Type.int(8))

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

