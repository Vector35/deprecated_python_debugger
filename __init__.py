# this makes the current directory a python module and a valid binja plugin

#print('__init__.py sees __name__=', __name__)

# create the widgets, debugger, etc.
try:
	from . import binjaplug
	binjaplug.initialize()
except ModuleNotFoundError:
	print('binjaplug not found, assuming this is cli mode')

