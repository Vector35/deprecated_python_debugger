import os
import re
import time

import binaryninja
from binaryninja import BinaryView, Symbol, SymbolType, Type, Structure, StructureType, FunctionGraphType, LowLevelILOperation, MediumLevelILOperation

from . import DebugAdapter, ProcessView, dbgeng

try:
	# create the widgets, debugger, etc.
	from . import ui
	ui.initialize_ui()
	have_ui = True
except (ModuleNotFoundError, ImportError, IndexError) as e:
	have_ui = False
	print(e)
	print("Could not initialize UI, using headless mode only")

#------------------------------------------------------------------------------
# Globals
#------------------------------------------------------------------------------

def get_state(bv):
	# TODO: Better way of determining this
	if 'Memory' in bv.sections:
		bv = bv.parent_view.parent_view

	# Try to find an existing state object
	for state in DebuggerState.states:
		if state.bv == bv:
			return state

	# Else make a new one, initially inactive
	state = DebuggerState(bv)
	DebuggerState.states.append(state)
	return state

def delete_state(bv):
	print("Detroying debugger state for {}".format(bv))

	# Try to find an existing state object
	for (i, state) in enumerate(DebuggerState.states):
		if state.bv == bv:
			DebuggerState.states.pop(i)
			return

#------------------------------------------------------------------------------
# Helper Classes
#------------------------------------------------------------------------------

class DebuggerRegisters:
	def __init__(self, state):
		self.state = state

	def __getitem__(self, reg):
		if self.state.adapter is None:
			return None
		return self.state.adapter.reg_read(reg)

	def __setitem__(self, reg, value):
		if self.state.adapter is None:
			return None
		self.state.adapter.reg_write(reg, value)

	def __iter__(self):
		if self.state.adapter is None:
			return None
		for reg in self.state.adapter.reg_list():
			yield (reg, self.state.adapter.reg_read(reg))

	def __repr__(self):
		return '<debugger registers for {}>'.format(self.state.adapter)


class DebuggerThreads:
	def __init__(self, state):
		self.state = state

	def __iter__(self):
		if self.state.adapter is None:
			return None
		for tid in self.state.adapter.thread_list():
			yield tid

	def __repr__(self):
		return '<debugger threads for {}>'.format(self.state.adapter)


class DebuggerModules:
	def __init__(self, state):
		self.state = state
		self.mark_dirty()
		self.translations = {}

	def mark_dirty(self):
		self.module_cache = None

	@property
	def current(self):
		fpath_exe = self.state.bv.file.original_filename
		if isinstance(self.state.adapter, dbgeng.DebugAdapterDbgeng):
			fpath_exe = fpath_exe.replace('/', '\\')

		for (mod, base) in self:
			if mod == fpath_exe:
				return mod

		# Can't find by full path, try to find by basename

		def strip_to_last(path):
			slash = path.rfind('/')
			if slash != -1:
				return path[slash+1:]
			slash = path.rfind('\\')
			if slash != -1:
				return path[slash+1:]
			return path

		for (mod, base) in self:
			if strip_to_last(fpath_exe) == strip_to_last(mod):
				return mod

		raise Exception("Cannot find current module! Is the loaded bndb pointing to a different file?")

	def __iter__(self):
		if self.state.adapter is None:
			return None
		if self.module_cache is None:
			self.module_cache = self.state.adapter.mem_modules().items()
		for (module, modbase) in self.module_cache:
			if module in self.translations:
				yield (self.translations[module], modbase)
			else:
				yield (module, modbase)

	def __getitem__(self, item):
		for (modpath, modaddr) in self:
			if modpath == item:
				return modaddr
		return None

	def __repr__(self):
		return '<debugger modules for {}>'.format(self.state.adapter)

	def get_module_for_addr(self, remote_address):
		# TODO: Compare loaded segments
		closest_modaddr = 0
		closest_modpath = ""
		for (modpath, modaddr) in self:
			if modaddr < remote_address and modaddr > closest_modaddr:
				closest_modaddr = modaddr
				closest_modpath = modpath
		return closest_modpath


'''
Breakpoints are stored inside this helper class, in the format (module, offset).
Storing like this allows us to persist breakpoints even with ASLR changing module bases.
The downside is that, currently, getting the list of modules+bases is very slow.

To use this class, first figure out what data you have / state you're in:
- If you want to set a breakpoint at a module-offset pair, use the xxx_offset functions
- If you want to use a remote address, the debugger MUST be running. Then, use the
  various xxx_absolute functions with your address. This class will automatically
  translate your address into a module-offset pair internally
- If you are not debugging and want to use a remote address, translate it into a
  module-offset pair yourself first.
'''
class DebuggerBreakpoints:
	def __init__(self, state, initial=[]):
		self.state = state
		self.breakpoints = initial

	def __iter__(self):
		for bp in self.breakpoints:
			yield (bp['module'], bp['offset'])

	'''
	Add a breakpoint at a given remote address in the running process and save to metadata
	Requires that the debugger be running.
	Will set the breakpoint immediately on the debugger.
	'''
	def add_absolute(self, remote_address):
		assert self.state.adapter is not None

		module = self.state.modules.get_module_for_addr(remote_address)
		modstart = self.state.modules[module]
		relative_address = remote_address - modstart

		info = {'module': module, 'offset': relative_address}
		if info not in self.breakpoints:
			self.breakpoints.append(info)
			self.state.bv.store_metadata('debugger.breakpoints', self.breakpoints)
			return self.state.adapter.breakpoint_set(remote_address)
		return False

	'''
	Add a breakpoint at a given module/offset and save to metadata.
	If the debugger is running, will set the breakpoint immediately.
	'''
	def add_offset(self, module, offset):
		info = {'module': module, 'offset': offset}
		if info not in self.breakpoints:
			self.breakpoints.append(info)
			self.state.bv.store_metadata('debugger.breakpoints', self.breakpoints)

			if self.state.adapter is not None:
				remote_address = self.state.modules[module] + offset
				return self.state.adapter.breakpoint_set(remote_address)
			else:
				return True

		return False

	'''
	Unset a breakpoint at a given remote address in the running process and save to metadata
	Requires that the debugger be running.
	Will unset the breakpoint immediately on the debugger.
	'''
	def remove_absolute(self, remote_address):
		assert self.state.adapter is not None

		module = self.state.modules.get_module_for_addr(remote_address)
		modstart = self.state.modules[module]
		relative_address = remote_address - modstart

		info = {'module': module, 'offset': relative_address}
		if info in self.breakpoints:
			self.breakpoints.remove(info)
			self.state.bv.store_metadata('debugger.breakpoints', self.breakpoints)
			return self.state.adapter.breakpoint_clear(remote_address)
		return False

	'''
	Unset a breakpoint at a given module/offset and save to metadata.
	If the debugger is running, will unset the breakpoint immediately.
	'''
	def remove_offset(self, module, offset):
		info = {'module': module, 'offset': offset}
		if info in self.breakpoints:
			self.breakpoints.remove(info)
			self.state.bv.store_metadata('debugger.breakpoints', self.breakpoints)

			if self.state.adapter is not None:
				remote_address = self.state.modules[module] + offset
				return self.state.adapter.breakpoint_clear(remote_address)
			else:
				return True

		return False

	'''
	Determine if a given remote address has a breakpoint set.
	Requires that the debugger be running.
	'''
	def contains_absolute(self, remote_address):
		assert self.state.adapter is not None

		module = self.state.modules.get_module_for_addr(remote_address)
		modstart = self.state.modules[module]
		relative_address = remote_address - modstart

		info = {'module': module, 'offset': relative_address}
		return info in self.breakpoints

	'''
	Determine if a given module/offset has a breakpoint set.
	'''
	def contains_offset(self, module, offset):
		info = {'module': module, 'offset': offset}
		return info in self.breakpoints

	'''
	Set all saved breakpoints on the running debugger.
	Requires that the debugger be running.
	This method is used when starting the debugger or a new module is loaded (TODO)
	'''
	def apply(self):
		assert self.state.adapter is not None

		remote_breakpoints = self.state.adapter.breakpoint_list()
		for bp in self.breakpoints:
			remote_address = self.state.modules[bp['module']] + bp['offset']
			if remote_address not in remote_breakpoints:
				self.state.adapter.breakpoint_set(remote_address)


#------------------------------------------------------------------------------
# DEBUGGER STATE / CONTROLLER
#
# Controller of the debugger for a single BinaryView
#------------------------------------------------------------------------------

class DebuggerState:
	states = []

	def __init__(self, bv):
		self.bv = bv
		self.adapter = None
		self.running = False
		# address -> adapter id
		self.memory_view = ProcessView.DebugProcessView(bv)
		self.old_symbols = []
		self.old_dvs = set()

		def get_metadata(key, default):
			try:
				return bv.query_metadata(key)
			except:
				return default

		self.command_line_args = get_metadata('debugger.command_line_args', [])
		initial_bps = get_metadata('debugger.breakpoints', [])

		self.adapter_type = list(DebugAdapter.ADAPTER_TYPE)[get_metadata('debugger.adapter_type', DebugAdapter.ADAPTER_TYPE.DEFAULT.value)]
		self.remote_host = get_metadata('debugger.remote_host', 'localhost')
		self.remote_port = get_metadata('debugger.remote_port', 31337)

		# Convenience
		self.registers = DebuggerRegisters(self)
		self.threads = DebuggerThreads(self)
		self.modules = DebuggerModules(self)
		self.breakpoints = DebuggerBreakpoints(self, initial_bps)

		if have_ui:
			self.ui = ui.DebuggerUI(self)
		else:
			self.ui = None

		if self.bv and self.bv.entry_point:
			local_entry_offset = self.bv.entry_point - self.bv.start
			if not self.breakpoints.contains_offset(self.bv.file.original_filename, local_entry_offset):
				self.breakpoints.add_offset(self.bv.file.original_filename, local_entry_offset)
				if self.ui is not None:
					self.ui.breakpoint_tag_add(self.bv.entry_point)
					self.ui.update_breakpoints()

	#--------------------------------------------------------------------------
	# Convenience Functions
	#--------------------------------------------------------------------------

	@property
	def ip(self):
		if self.bv.arch.name == 'x86_64':
			return self.registers['rip']
		elif self.bv.arch.name == 'x86':
			return self.registers['eip']
		elif self.bv.arch.name == 'aarch64':
			return self.registers['pc']
		else:
			raise NotImplementedError('unimplemented architecture %s' % self.bv.arch.name)

	@property
	def local_ip(self):
		return self.memory_view.remote_addr_to_local(self.ip)

	@property
	def remote_ip(self):
		return self.ip

	@property
	def stack_pointer(self):
		if self.bv.arch.name == 'x86_64':
			return self.registers['rsp']
		elif self.bv.arch.name == 'x86':
			return self.registers['esp']
		elif self.bv.arch.name == 'aarch64':
			return self.registers['sp']
		else:
			raise NotImplementedError('unimplemented architecture %s' % self.bv.arch.name)

	# Mark memory as dirty, will refresh memory view
	def memory_dirty(self):
		self.memory_view.mark_dirty()
		self.modules.mark_dirty()

	# Create symbols and variables for the memory view
	def update_memory_view(self):
		if self.adapter == None:
			raise Exception('missing adapter')
		if self.memory_view == None:
			raise Exception('missing memory_view')

		addr_regs = {}
		reg_addrs = {}

		for (reg, addr) in self.registers:
			reg_symbol_name = '$' + reg

			if addr not in addr_regs.keys():
				addr_regs[addr] = [reg_symbol_name]
			else:
				addr_regs[addr].append(reg_symbol_name)
			reg_addrs[reg] = addr

		for symbol in self.old_symbols:
			# Symbols are immutable so just destroy the old one
			self.memory_view.undefine_auto_symbol(symbol)

		for dv in self.old_dvs:
			self.memory_view.undefine_data_var(dv)

		self.old_symbols = []
		self.old_dvs = set()
		new_dvs = set()

		for (reg, addr) in reg_addrs.items():
			symbol_name = '$' + reg
			self.memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, addr, symbol_name, namespace=symbol_name))
			self.old_symbols.append(self.memory_view.get_symbol_by_raw_name(symbol_name, namespace=symbol_name))
			new_dvs.add(addr)

		for new_dv in new_dvs:
			self.memory_view.define_data_var(new_dv, Type.int(8))
			self.old_dvs.add(new_dv)

		# Special struct for stack frame
		if self.bv.arch.name == 'x86_64':
			width = reg_addrs['rbp'] - reg_addrs['rsp'] + self.bv.arch.address_size
			if width > 0:
				if width > 0x1000:
					width = 0x1000
				struct = Structure()
				struct.type = StructureType.StructStructureType
				struct.width = width
				for i in range(0, width, self.bv.arch.address_size):
					var_name = "var_{:x}".format(width - i)
					struct.insert(i, Type.pointer(self.bv.arch, Type.void()), var_name)
				self.memory_view.define_data_var(reg_addrs['rsp'], Type.structure_type(struct))
				self.memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, reg_addrs['rsp'], "$stack_frame", raw_name="$stack_frame"))

				self.old_symbols.append(self.memory_view.get_symbol_by_raw_name("$stack_frame"))
				self.old_dvs.add(reg_addrs['rsp'])
		else:
			pass
			# raise NotImplementedError('only x86_64 so far')

	#--------------------------------------------------------------------------
	# I/O Handling
	#--------------------------------------------------------------------------

	def on_stdout(self, output):
		if self.ui is not None:
			self.ui.on_stdout(output)
		else:
			print(output)

	def send_console_input(self, text):
		assert self.adapter
		self.adapter.stdin_write(text)

	#--------------------------------------------------------------------------
	# Debugger Functions (Blocking)
	#--------------------------------------------------------------------------

	def run(self):
		if DebugAdapter.ADAPTER_TYPE.use_exec(self.adapter_type):
			self.exec()
		elif DebugAdapter.ADAPTER_TYPE.use_connect(self.adapter_type):
			self.attach()
		else:
			raise Exception("don't know how to connect to adapter of type %s" % self.adapter_type)

	def exec(self):
		fpath = self.bv.file.original_filename

		if not os.path.exists(fpath):
			raise Exception('cannot find debug target: ' + fpath)

		self.adapter = DebugAdapter.get_new_adapter(self.adapter_type, stdout=self.on_stdout)

		if DebugAdapter.ADAPTER_TYPE.use_exec(self.adapter_type):
			try:
				self.adapter.exec(fpath, self.command_line_args)
			except Exception as e:
				self.adapter = None
				raise e
		else:
			raise Exception("cannot exec adapter of type %s" % self.adapter_type)

		self.memory_view.update_base()
		self.breakpoints.apply()
		self.memory_dirty()

	def attach(self):
		self.adapter = DebugAdapter.get_new_adapter(self.adapter_type, stdout=self.on_stdout)
		if DebugAdapter.ADAPTER_TYPE.use_connect(self.adapter_type):
			try:
				self.adapter.connect(self.remote_host, self.remote_port)
			except Exception as e:
				self.adapter = None
				raise e
		else:
			raise Exception("cannot connect to adapter of type %s" % self.adapter_type)

		self.memory_view.update_base()

		current_module = self.modules.current
		if current_module != self.bv.file.original_filename:
			print("Detected remote process running at different path: {}".format(current_module))
			self.modules.translations[current_module] = self.bv.file.original_filename

		self.breakpoints.apply()
		self.memory_dirty()

	def quit(self):
		if self.adapter is not None:
			try:
				self.adapter.quit()
			except BrokenPipeError:
				pass
			except ConnectionResetError:
				pass
			except OSError:
				pass
			finally:
				self.adapter = None
		self.memory_dirty()

	def restart(self):
		self.quit()
		time.sleep(1)
		self.run() # sets state

	def detach(self):
		if self.adapter is not None:
			try:
				self.adapter.detach()
			except BrokenPipeError:
				pass
			except ConnectionResetError:
				pass
			except OSError:
				pass
			finally:
				self.adapter = None
		self.memory_dirty()

	def pause(self):
		if not self.adapter:
			raise Exception('missing adapter')
		result = self.adapter.break_into()
		self.memory_dirty()
		return result

	def go(self):
		if not self.adapter:
			raise Exception('missing adapter')

		remote_rip = self.ip
		bphere = self.breakpoints.contains_absolute(remote_rip)

		seq = []
		if bphere:
			# Clear the breakpoint and step once (past the breakpoint)
			# Then re-set it in case we loop and hit it again
			seq.append((self.adapter.breakpoint_clear, (remote_rip,)))
			seq.append((self.adapter.step_into, ()))
			seq.append((self.adapter.breakpoint_set, (remote_rip,)))
			seq.append((self.adapter.go, ()))
		else:
			seq.append((self.adapter.go, ()))

		self.running = True
		result = self.exec_adapter_sequence(seq)
		self.running = False
		self.memory_dirty()
		return result

	# Continue until one of any given remote addresses
	def step_to(self, remote_addresses=[]):
		if not self.adapter:
			raise Exception('missing adapter')
		# Make sure this is an iterable
		if not hasattr(remote_addresses, '__iter__'):
			remote_addresses = [remote_addresses]

		(reason, data) = (None, None)

		# if currently a breakpoint at rip, temporarily clear it
		# for all addresses: if no breakpoint at address, set it
		# then go
		# then clean up

		remote_rip = self.ip

		seq = []
		for remote_address in remote_addresses:
			if not self.breakpoints.contains_absolute(remote_address):
				seq.append((self.adapter.breakpoint_set, (remote_address,)))

		if self.breakpoints.contains_absolute(remote_rip):
			# Clear the breakpoint and step once (past the breakpoint)
			# Then re-set it in case we loop and hit it again
			seq.append((self.adapter.breakpoint_clear, (remote_rip,)))
			seq.append((self.adapter.step_into, ()))
			seq.append((self.adapter.breakpoint_set, (remote_rip,)))
			seq.append((self.adapter.go, ()))
		else:
			seq.append((self.adapter.go, ()))

		for remote_address in remote_addresses:
			if not self.breakpoints.contains_absolute(remote_address):
				seq.append((self.adapter.breakpoint_clear, (remote_address,)))
		# TODO: Cancel (and raise some exception)
		result = self.exec_adapter_sequence(seq)
		self.memory_dirty()
		return result

	# Step once in the disassembly / il, potentially into a function call
	def step_into(self, il=FunctionGraphType.NormalFunctionGraph):
		if not self.adapter:
			raise Exception('missing adapter')

		remote_rip = self.ip

		# Cannot IL step through non-analyzed code
		if not self.memory_view.is_local_addr(remote_rip):
			il = FunctionGraphType.NormalFunctionGraph

		if il == FunctionGraphType.NormalFunctionGraph:
			# if currently a breakpoint at rip, temporarily clear it
			# TODO: detect windbg adapter because dbgeng's step behavior might ignore breakpoint
			# at current rip

			seq = []
			if self.breakpoints.contains_absolute(remote_rip):
				seq.append((self.adapter.breakpoint_clear, (remote_rip,)))
				seq.append((self.adapter.step_into, ()))
				seq.append((self.adapter.breakpoint_set, (remote_rip,)))
			else:
				seq.append((self.adapter.step_into, ()))
			# TODO: Cancel (and raise some exception)
			result = self.exec_adapter_sequence(seq)
			self.memory_dirty()
			return result
		elif il == FunctionGraphType.LowLevelILFunctionGraph:
			# Step into until we're at an llil instruction
			result = (None, None)
			while True:
				# Step once in disassembly, then see if we've hit an IL instruction
				result = self.step_into(FunctionGraphType.NormalFunctionGraph)
				self.memory_dirty()
				new_remote_rip = self.ip
				new_local_rip = self.memory_view.remote_addr_to_local(new_remote_rip)
				if not self.memory_view.is_local_addr(new_remote_rip):
					# Stepped outside of loaded bv
					return result

				fns = self.bv.get_functions_containing(new_local_rip)
				if len(fns) == 0:
					return result
				for fn in fns:
					start = fn.llil.get_instruction_start(new_local_rip)
					if start is not None and fn.llil[start].address == new_local_rip:
						return result
		elif il == FunctionGraphType.MediumLevelILFunctionGraph:
			# Step into until we're at an mlil instruction
			result = (None, None)
			while True:
				# Step once in disassembly, then see if we've hit an IL instruction
				result = self.step_into(FunctionGraphType.NormalFunctionGraph)
				self.memory_dirty()
				new_remote_rip = self.ip
				new_local_rip = self.memory_view.remote_addr_to_local(new_remote_rip)
				if not self.memory_view.is_local_addr(new_remote_rip):
					# Stepped outside of loaded bv
					return result

				fns = self.bv.get_functions_containing(new_local_rip)
				if len(fns) == 0:
					return result
				for fn in fns:
					start = fn.mlil.get_instruction_start(new_local_rip)
					if start is not None and fn.mlil[start].address == new_local_rip:
						return result
		else:
			raise NotImplementedError('step unimplemented for il type %s' % il)

	# Step until reaching the next line in the disassembly / il
	def step_over(self, il=FunctionGraphType.NormalFunctionGraph):
		if not self.adapter:
			raise Exception('missing adapter')

		try:
			return self.adapter.step_over()
		except NotImplementedError:
			pass

		remote_rip = self.ip
		local_rip = self.memory_view.remote_addr_to_local(remote_rip)

		# Cannot IL step through non-analyzed code
		if not self.memory_view.is_local_addr(remote_rip):
			il = FunctionGraphType.NormalFunctionGraph

		if il == FunctionGraphType.NormalFunctionGraph:
			if self.bv.read(local_rip, 1):
				instxt = self.bv.get_disassembly(local_rip)
				inslen = self.bv.get_instruction_length(local_rip)
			else:
				data = self.adapter.mem_read(remote_rip, 16)
				(tokens, length) = self.bv.arch.get_instruction_text(data, local_rip)
				instxt = ''.join([x.text for x in tokens])
				inslen = length

			local_ripnext = local_rip + inslen
			remote_ripnext = remote_rip + inslen

			llil = self.memory_view.arch.get_low_level_il_from_bytes(self.memory_view.read(remote_rip, self.memory_view.arch.max_instr_length), remote_rip)
			call = llil.operation == LowLevelILOperation.LLIL_CALL

			# Optimization: just use step into if this isn't a call
			if not call:
				return self.step_into(il)

			return self.step_to([remote_ripnext])
		else:
			targets = []
			if il == FunctionGraphType.LowLevelILFunctionGraph:
				# Step over until we're at an llil instruction
				result = (None, None)
				while True:
					# Step once in disassembly, then see if we've hit an IL instruction
					result = self.step_over(FunctionGraphType.NormalFunctionGraph)
					self.memory_dirty()
					new_remote_rip = self.ip
					new_local_rip = self.memory_view.remote_addr_to_local(new_remote_rip)
					if not self.memory_view.is_local_addr(new_remote_rip):
						# Stepped outside of loaded bv
						return result

					fns = self.bv.get_functions_containing(new_local_rip)
					if len(fns) == 0:
						return result
					for fn in fns:
						start = fn.llil.get_instruction_start(new_local_rip)
						if start is not None and fn.llil[start].address == new_local_rip:
							return result
			elif il == FunctionGraphType.MediumLevelILFunctionGraph:
				# Step over until we're at an mlil instruction
				result = (None, None)
				while True:
					# Step once in disassembly, then see if we've hit an IL instruction
					result = self.step_over(FunctionGraphType.NormalFunctionGraph)
					self.memory_dirty()
					new_remote_rip = self.ip
					new_local_rip = self.memory_view.remote_addr_to_local(new_remote_rip)
					if not self.memory_view.is_local_addr(new_remote_rip):
						# Stepped outside of loaded bv
						return result

					fns = self.bv.get_functions_containing(new_local_rip)
					if len(fns) == 0:
						return result
					for fn in fns:
						start = fn.mlil.get_instruction_start(new_local_rip)
						if start is not None and fn.mlil[start].address == new_local_rip:
							return result
			else:
				raise NotImplementedError('step unimplemented for il type %s' % il)

			return self.step_to(targets)

	def step_return(self):
		if not self.adapter:
			raise Exception('missing adapter')

		remote_rip = self.ip
		local_rip = self.memory_view.remote_addr_to_local(remote_rip)

		# TODO: If we don't have a function loaded, walk the stack
		funcs = self.bv.get_functions_containing(local_rip)
		if len(funcs) != 0:
			mlil = funcs[0].mlil

			# Set a bp on every ret in the function and go
			rets = set()
			for insn in mlil.instructions:
				if insn.operation == binaryninja.MediumLevelILOperation.MLIL_RET or insn.operation == binaryninja.MediumLevelILOperation.MLIL_TAILCALL:
					rets.add(self.memory_view.local_addr_to_remote(insn.address))
			return self.step_to(rets)
		else:
			print("Can't find current function")
			return (None, None)

	# execute a sequence of adapter commands, capturing the return of the last
	# blocking call
	def exec_adapter_sequence(self, seq):
		(reason, data) = (None, None)

		for (func, args) in seq:
			if func in [self.adapter.step_into, self.adapter.step_over, self.adapter.go]:
				(reason, data) = func(*args)
				if reason == DebugAdapter.STOP_REASON.PROCESS_EXITED or reason == DebugAdapter.STOP_REASON.BACKEND_DISCONNECTED:
					# Process is dead, stop sequence
					break
			else:
				func(*args)

		return (reason, data)
