# this makes the current directory a python module and a valid binja plugin

# create the widgets, debugger, etc.
from . import binjaplug
binjaplug.initialize()

