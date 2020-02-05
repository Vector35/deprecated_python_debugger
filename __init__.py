# this makes the current directory a python module and a valid binja plugin

#print('__init__.py sees __name__=', __name__)

# create the widgets, debugger, etc.
try:
	from . import binjaplug
	binjaplug.initialize()

	def get(bv):
		return binjaplug.get_state(bv)
except (ModuleNotFoundError, ImportError):
	print('binjaplug not found, assuming this is cli mode')

