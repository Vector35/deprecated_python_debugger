from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView

import binaryninja
import binaryninjaui
from binaryninjaui import DockContextHandler, UIActionHandler

from . import widget
from .. import binjaplug

class DebugThreadsListModel(QAbstractItemModel):
	def __init__(self, parent):
		QAbstractItemModel.__init__(self, parent)
		self.columns = ["TID", "Location"]
		self.rows = []
		self.update_rows(None)

	# called from widget's notifyThreadsChanged() function
	# new_rows is list of {'tid':<uint>, 'rip':<uint>, 'selected':<bool>}
	def update_rows(self, new_rows):
		self.beginResetModel()

		old_threads = {}
		for (tid, ip) in self.rows:
			old_threads[tid] = ip

		# clear old data
		self.rows = []
		self.row_info = []
		if new_rows is None:
			self.endResetModel()
			return

		# set new data
		sel_row = None
		for info in new_rows:
			(tid, rip) = (info['tid'], info['rip'])
			# actual values for the table rows
			self.rows.append((tid, rip))
			# parallel list of the incoming dict, augmented
			#  (keys 'selected', 'bits', 'state' used in display)
			if info.get('selected', False):
				sel_row = len(self.rows)-1
			info['state'] = ['updated', 'unchanged'][old_threads.get(tid,-1) == rip]
			self.row_info.append(info)

		self.endResetModel()

		# return index to selected (row, col=0)
		if sel_row != None:
			return self.createIndex(sel_row, 0)

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

	def flags(self, index):
		f = super().flags(index)

		if index.column() == 1:
			f |= Qt.ItemIsEditable
		return f

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

		contents = self.rows[index.row()][index.column()]
		info = self.row_info[index.row()]

		if role == Qt.DisplayRole:
			# Format data into displayable text
			if index.column() == 1:
				# Pad out to ceil(bitlength/4) nibbles
				text = ('%X' % contents).rjust((info['bits'] + 3) // 4, "0")
			else:
				# TID should just be integer
				text = '%X' % contents
			return text
		elif role == Qt.UserRole:
			return info['state'] # 'updated', 'modified', 'unchanged'
		# TODO: look into Qt::CheckStateRole for whether thread selected or not

		return None

	# called back after user edits
	def setData(self, index, value, role):
		pass

class DebugThreadsItemDelegate(QItemDelegate):
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
		state = idx.data(Qt.UserRole)

		# Draw text depending on state
		painter.setFont(self.font)
		if state == 'updated':
			painter.setPen(option.palette.color(QPalette.Highlight).rgba())
		elif state == 'modified':
			painter.setPen(binaryninjaui.getThemeColor(binaryninjaui.OrangeStandardHighlightColor).rgba())
		else:
			painter.setPen(option.palette.color(QPalette.WindowText).rgba())
		painter.drawText(2 + option.rect.left(), self.char_offset + self.baseline + option.rect.top(), str(text))

	def setEditorData(self, editor, idx):
		return None
		# TODO: add checkbox to select thread
		#if idx.column() == 1:
		#	data = idx.data()
		#	editor.setText(data)

class DebugThreadsWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		self.table = QTableView(self)
		self.model = DebugThreadsListModel(self.table)
		self.table.setModel(self.model)
		self.table.clicked.connect(self.threadRowClicked)

		self.item_delegate = DebugThreadsItemDelegate(self)
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

	# called from QTableView's clicked signal
	# index: QModelIndex
	def threadRowClicked(self, index):
		index = self.model.createIndex(index.row(), 0)
		tid_str = self.model.data(index, Qt.DisplayRole)
		#print('clicked to change to thread %s' % tid_str)
		stateObj = binjaplug.get_state(self.bv)
		if stateObj.state == 'STOPPED':
			adapter = stateObj.adapter
			tid = int(tid_str, 16)
			adapter.thread_select(tid)
			binjaplug.context_display(self.bv)
		else:
			print('cannot set thread in state %s' % stateObj.state)

	# called from plugin's context_display() function
	def notifyThreadsChanged(self, new_threads):
		idx_selected = self.model.update_rows(new_threads)
		if idx_selected:
			self.table.setCurrentIndex(idx_selected)

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

