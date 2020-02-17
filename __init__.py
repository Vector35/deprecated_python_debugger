# This plugin supports scripting both in the ui and in headless plugins
# Start scripts with the following:
# import debugger
# dbg = debugger.get(bv)
from . import binjaplug

"""
Retrieve the debugger state instance for a given BinaryView
"""
def get(bv):
	return binjaplug.get_state(bv)

