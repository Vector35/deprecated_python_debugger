import binaryninjaui
if "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
	from PySide6 import QtCore
	from PySide6.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
	from PySide6.QtGui import QPalette, QFontMetricsF
	from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView
else:
	from PySide2 import QtCore
	from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
	from PySide2.QtGui import QPalette, QFontMetricsF
	from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView

from binaryninjaui import DockContextHandler, UIActionHandler, ThemeColor
from binaryninja import BinaryView

from . import widget
from .. import binjaplug

class DebugRegistersListModel(QAbstractItemModel):
	def __init__(self, parent, bv):
		QAbstractItemModel.__init__(self, parent)
		self.bv = bv
		self.columns = ["Name", "Value"]
		self.rows = []
		self.update_rows(None)

	def update_rows(self, new_rows):
		self.beginResetModel()

		old_regs = {}
		for (reg, value) in self.rows:
			old_regs[reg] = value

		self.rows = []
		self.row_info = []
		if new_rows is None:
			self.endResetModel()
			return

		# Fill self.rows
		for info in new_rows:
			self.rows.append((info['name'], info['value']))
			info['state'] = 'unchanged' if old_regs.get(info['name'], -1) == info['value'] else 'updated'
			self.row_info.append(info)

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

		conts = self.rows[index.row()][index.column()]
		info = self.row_info[index.row()]

		if role == Qt.DisplayRole:
			# Format data into displayable text
			if index.column() == 1:
				# Pad out to ceil(bitlength/4) nibbles
				text = ('%x' % conts).rjust((info['bits'] + 3) // 4, "0")
			else:
				text = str(conts)
			return text
		elif role == Qt.UserRole:
			return info['state']

		return None

	def setData(self, index, value, role):
		# Verify that we can edit this value
		if (self.flags(index) & Qt.EditRole) != Qt.EditRole:
			return False
		if len(value) == 0:
			return False

		info = self.row_info[index.row()]
		old_val = self.rows[index.row()][1]
		try:
			new_val = int(value, 16)
		except:
			return False
		register = info['name']

		if new_val == old_val:
			return False

		# Tell the debugger to update
		debug_state = binjaplug.get_state(self.bv)
		debug_state.registers[register] = new_val

		# Update internal copy to show modification
		updated_val = debug_state.registers[register]

		# Make sure the debugger actually let us set the register
		self.rows[index.row()] = (register, updated_val)
		self.row_info[index.row()]['state'] = 'modified' if updated_val == new_val else info['state']

		self.dataChanged.emit(index, index, [role])
		self.layoutChanged.emit()
		return True

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
		width = self.expected_char_widths[idx.column()]
		data = idx.data()
		if data is not None:
			width = max(width, len(data))
		return QSize(self.char_width * width + 4, self.char_height)

	def paint(self, painter, option, idx):
		# Draw background highlight in theme style
		selected = option.state & QStyle.State_Selected != 0
		if selected:
			painter.setBrush(binaryninjaui.getThemeColor(binaryninjaui.ThemeColor.SelectionColor))
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
			painter.setPen(binaryninjaui.getThemeColor(ThemeColor.OrangeStandardHighlightColor).rgba())
		else:
			painter.setPen(option.palette.color(QPalette.WindowText).rgba())
		painter.drawText(2 + option.rect.left(), self.char_offset + self.baseline + option.rect.top(), str(text))

	def setEditorData(self, editor, idx):
		if idx.column() == 1:
			data = idx.data()
			editor.setText(data)


class DebugRegistersWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		if not type(data) == BinaryView:
			raise Exception('expected widget data to be a BinaryView')

		self.bv = data

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		self.table = QTableView(self)
		self.model = DebugRegistersListModel(self.table, data)
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

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		layout.addWidget(self.table)
		self.setLayout(layout)

	def notifyOffsetChanged(self, offset):
		pass

	def notifyRegistersChanged(self, new_regs):
		self.model.update_rows(new_regs)
		self.table.resizeColumnsToContents()

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

