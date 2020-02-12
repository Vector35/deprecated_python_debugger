# this makes the current directory a python module and a valid binja plugin

#print('__init__.py sees __name__=', __name__)

from . import binjaplug

def get(bv):
	return binjaplug.get_state(bv)

