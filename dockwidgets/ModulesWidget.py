from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView, QLabel, QPushButton

import binaryninja
import binaryninjaui
from binaryninjaui import DockContextHandler, UIActionHandler

from . import widget
from .. import binjaplug

class DebugModulesListModel(QAbstractItemModel):
	def __init__(self, parent, bv):
		QAbstractItemModel.__init__(self, parent)
		self.bv = bv
		self.columns = ["Address", "Name", "Full Path"]
		self.update_rows(None)

	def update_rows(self, new_rows):
		self.beginResetModel()

		if new_rows is None:
			self.rows = []
		else:
			self.rows = new_rows

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

		info = self.rows[index.row()]

		if role == Qt.DisplayRole:
			# Format data into displayable text
			if self.columns[index.column()] == "Address":
				text = '0x%x' % info['address']
			elif self.columns[index.column()] == "Name":
				text = info['modpath']
				if '/' in text:
					text = text[text.rfind('/')+1:]
			elif self.columns[index.column()] == "Full Path":
				text = info['modpath']
			else:
				raise NotImplementedError('Unknown column')
			return text

		return None

class DebugModulesItemDelegate(QItemDelegate):
	def __init__(self, parent):
		QItemDelegate.__init__(self, parent)

		self.font = binaryninjaui.getMonospaceFont(parent)
		self.font.setKerning(False)
		self.baseline = QFontMetricsF(self.font).ascent()
		self.char_width = binaryninjaui.getFontWidthAndAdjustSpacing(self.font)[0]
		self.char_height = QFontMetricsF(self.font).height()
		self.char_offset = binaryninjaui.getFontVerticalOffset()

		self.expected_char_widths = [20, 20, 30]

	def sizeHint(self, option, idx):
		width = self.expected_char_widths[idx.column()]
		data = idx.data()
		if data is not None:
			width = max(width, len(data))
		return QSize(self.char_width * width + 4, self.char_height)

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
		painter.setFont(self.font)
		painter.setPen(option.palette.color(QPalette.WindowText).rgba())
		painter.drawText(2 + option.rect.left(), self.char_offset + self.baseline + option.rect.top(), str(text))


class DebugModulesWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		if not type(data) == binaryninja.binaryview.BinaryView:
			raise Exception('expected widget data to be a BinaryView')

		self.bv = data

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		self.table = QTableView(self)
		self.model = DebugModulesListModel(self.table, data)
		self.table.setModel(self.model)

		self.item_delegate = DebugModulesItemDelegate(self)
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

		update_layout = QHBoxLayout()
		update_layout.setContentsMargins(0, 0, 0, 0)

		update_label = QLabel("Data is Stale")
		update_button = QPushButton("Refresh")
		update_button.clicked.connect(lambda: self.refresh())

		update_layout.addWidget(update_label)
		update_layout.addStretch(1)
		update_layout.addWidget(update_button)

		self.update_box = QWidget()
		self.update_box.setLayout(update_layout)

		self.layout = QVBoxLayout()
		self.layout.setContentsMargins(0, 0, 0, 0)
		self.layout.setSpacing(0)
		self.layout.addWidget(self.table)
		self.setLayout(self.layout)

	def notifyOffsetChanged(self, offset):
		pass

	def refresh(self):
		debug_state = binjaplug.get_state(self.bv)
		debug_state.ui.update_modules()

	def notifyModulesChanged(self, new_modules):
		self.model.update_rows(new_modules)
		self.table.resizeColumnsToContents()
		self.layout.removeWidget(self.update_box)
		self.update_box.setVisible(False)

	def mark_dirty(self):
		self.layout.addWidget(self.update_box)
		self.update_box.setVisible(True)

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

