from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView

import binaryninja
import binaryninjaui
from binaryninja import BinaryView
from binaryninjaui import DockContextHandler, UIActionHandler, HexEditor, ViewFrame

from . import widget
from .. import binjaplug

class DebugMemoryView(BinaryView):
	name = "Debugged Process Memory"
	def __init__(self, parent):
		BinaryView.__init__(self, parent_view=parent, file_metadata=parent.file)
		self.value_cache = {}

	def perform_get_address_size(self):
		return self.parent_view.arch.address_size

	@classmethod
	def is_valid_for_data(self, data):
		return False

	def perform_get_length(self):
		# Assume 8 bit bytes (hopefully a safe assumption)
		return (2 ** (self.perform_get_address_size() * 8)) - 1

	def perform_read(self, addr, length):
		if binjaplug.adapter is None:
			return None
		# Cache reads (will be cleared whenever view is marked dirty)
		if addr in self.value_cache.keys():
			return self.value_cache[addr]
		value = binjaplug.adapter.mem_read(addr, length)
		self.value_cache[addr] = value
		return value
	
	def perform_write(self, addr, data):
		if binjaplug.adapter is None:
			return 0
		# Assume any memory change invalidates all of memory (suboptimal, may not be necessary)
		self.mark_dirty()
		if binjaplug.adapter.mem_write(addr, data) == 0:
			return len(data)
		else:
			return 0
	
	def mark_dirty(self):
		self.value_cache = {}

DebugMemoryView.register()

class DebugMemoryWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data
		self.memory_view = DebugMemoryView(data)

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		self.editor = HexEditor(self.memory_view, ViewFrame.viewFrameForWidget(self), 0)

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		layout.addWidget(self.editor)
		self.setLayout(layout)

	def notifyOffsetChanged(self, offset):
		pass

	def notifyMemoryChanged(self):
		self.memory_view.mark_dirty()
		# Refresh the editor (currently via a hack)
		self.editor.resize(self.editor.width() - 1, self.editor.height())
		self.editor.resize(self.editor.width() + 1, self.editor.height())
		self.editor.navigate(binjaplug.adapter.reg_read('rbp'))

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

