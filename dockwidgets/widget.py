from PySide2.QtWidgets import QApplication, QWidget
from binaryninjaui import DockHandler

debug_dockwidgets = {}

def create_widget(widget_class, name, parent, data, *args):
	# It is imperative this function return *some* value because Shiboken will try to deref what we return
	# If we return nothing (or throw) there will be a null pointer deref (and we won't even get to see why)
	# So in the event of an error or a nothing, return an empty widget that at least stops the crash
	try:
		widget = widget_class(parent, name, data, *args)
		assert widget is not None
		global debug_dockwidgets
		debug_dockwidgets[name] = widget
		return widget
	except Exception as e:
		print(e)
		return QWidget(parent)

def register_dockwidget(widget_class, name, area, orientation, default_visibility, *args):
	mainWindow = QApplication.allWidgets()[0].window()

	# binaryninja/api/ui/dockhandler.h
	dock_handler = mainWindow.findChild(DockHandler, '__DockHandler')

	# create main debugger controls
	dock_handler.addDockWidget(name, lambda n,p,d: create_widget(widget_class, n, p, d, *args), area, orientation, default_visibility)
