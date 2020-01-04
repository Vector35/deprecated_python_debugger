from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView

import binaryninja
import binaryninjaui
from binaryninjaui import DockContextHandler, UIActionHandler

from . import widget

class DebugRegistersListModel(QAbstractItemModel):
	def __init__(self, parent, context):
		QAbstractItemModel.__init__(self, parent)
		self.columns = ["Name", "Value"]
		self.rows = []
		self.context = context
		self.update_rows()

	def update_rows(self):
		self.beginResetModel()

		old_regs = {}
		for (reg, value) in self.rows:
			old_regs[reg] = value

		self.rows = []
		self.row_info = []
		if self.context.adapter is None:
			self.endResetModel()
			return

		# Fill self.rows
		for register in self.context.adapter.reg_list():
			value = self.context.adapter.reg_read(register)
			self.rows.append((register, value))
			self.row_info.append({
				'bits': self.context.adapter.reg_bits(register),
				'updated': old_regs.get(register, -1) != value
			})

		self.endResetModel()

	def index(self, row, column, parent):
		if parent.isValid() or column > len(self.columns) or row >= len(self.rows):
			return QModelIndex()
		return self.createIndex(row, column)
	
	def parent(self, child):
		return QModelIndex()

	def hasChildren(self, parent):
		return False
	
	def rowCount(self, parent):
		if parent.isValid():
			return 0
		return len(self.rows)
	
	def columnCount(self, parent):
		return len(self.columns)
	
	def headerData(self, section, orientation, role):
		if role != Qt.DisplayRole:
			return None
		if orientation == Qt.Vertical:
			return None
		return self.columns[section]

	def data(self, index, role):
		if not index.isValid():
			return None
		if index.row() < 0 or index.row() >= len(self.rows):
			return None
		
		conts = self.rows[index.row()][index.column()]
		info = self.row_info[index.row()]

		if role == Qt.DisplayRole:
			# Format data into displayable text
			if index.column() == 1:
				# Pad out to ceil(bitlength/4) nibbles
				text = ('%X' % conts).rjust((info['bits'] + 3) // 4, "0")
			else:
				text = str(conts)
			return text
		elif role == Qt.UserRole:
			return info["updated"]

		return None

class DebugRegistersItemDelegate(QItemDelegate):
	def __init__(self, parent):
		QItemDelegate.__init__(self, parent)
		
		self.font = binaryninjaui.getMonospaceFont(parent)
		self.font.setKerning(False)
		self.baseline = QFontMetricsF(self.font).ascent()
		self.char_width = binaryninjaui.getFontWidthAndAdjustSpacing(self.font)[0]
		self.char_height = QFontMetricsF(self.font).height()
		self.char_offset = binaryninjaui.getFontVerticalOffset()

		self.expected_char_widths = [10, 32]
	
	def sizeHint(self, option, idx):
		return QSize(self.char_width * self.expected_char_widths[idx.column()] + 4, self.char_height)

	def paint(self, painter, option, idx):
		# Draw background highlight in theme style
		selected = option.state & QStyle.State_Selected != 0
		if selected:
			painter.setBrush(binaryninjaui.getThemeColor(binaryninjaui.SelectionColor))
		else:
			painter.setBrush(option.backgroundBrush)
		painter.setPen(Qt.NoPen)
		painter.drawRect(option.rect)

		text = idx.data()
		updated = bool(idx.data(Qt.UserRole))

		# Draw text
		painter.setFont(self.font)
		if updated:
			painter.setPen(option.palette.color(QPalette.Highlight).rgba())
		else:
			painter.setPen(option.palette.color(QPalette.WindowText).rgba())
		painter.drawText(2 + option.rect.left(), self.char_offset + self.baseline + option.rect.top(), str(text))


class DebugRegistersWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data, context):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data
		self.context = context
		
		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		self.table = QTableView(self)
		self.model = DebugRegistersListModel(self.table, self.context)
		self.table.setModel(self.model)

		self.item_delegate = DebugRegistersItemDelegate(self)
		self.table.setItemDelegate(self.item_delegate)

		# self.table.setSortingEnabled(True)
		self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
		self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)

		self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
		self.table.verticalHeader().setVisible(False)

		self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
		self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)

		self.table.resizeColumnsToContents()
		self.table.resizeRowsToContents()

		for i in range(len(self.model.columns)):
			self.table.setColumnWidth(i, self.item_delegate.sizeHint(self.table.viewOptions(), self.model.index(-1, i, QModelIndex())).width())

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		layout.addWidget(self.table)
		self.setLayout(layout)

	def notifyOffsetChanged(self, offset):
		pass

	def notifyRegisterChanged(self):
		self.model.update_rows()

	def notifyViewChanged(self, view_frame):
		self.model.update_rows()

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

