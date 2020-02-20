from binaryninja import Symbol, SymbolType, Structure, StructureType, Type, BinaryReader

def analyze_stack(state):
	# Create structure for stack frame
	if state.bv.arch.name == 'x86_64':
		ip = state.local_ip
		rbp = state.registers['rbp']
		rsp = state.registers['rsp']

		recurse_stack_x86_64(state, ip, rsp, rbp)

		state.memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, rsp, "$stack_frame", raw_name="$stack_frame"))
	else:
		raise NotImplementedError('only x86_64 so far')

def recurse_stack_x86_64(state, ip, rsp, rbp):
	current_function = None

	# Use analysis for stack variables if it's available
	use_fancy_stack = False
	for fn in state.bv.get_functions_containing(ip):
		if fn.arch == state.memory_view.arch:
			current_function = fn
			# Some instructions cause no stack variables to be defined
			use_fancy_stack = current_function.get_stack_var_at_frame_offset(0, ip) is not None

	width = rbp - rsp + state.bv.arch.address_size
	if width > 0:
		if width > 0x1000:
			width = 0x1000

		if use_fancy_stack:
			create_analysis_stack_structure_x86_64(state, ip, current_function, rbp)

			# Read the old stack frame from memory
			br = BinaryReader(state.memory_view)
			saved_rbp = deref_var_x86_64(current_function, ip, rbp, '__saved_rbp', br)
			remote_return_addr = deref_var_x86_64(current_function, ip, rbp, '__return_addr', br)
			local_return_addr = state.memory_view.remote_addr_to_local(remote_return_addr)

			# And if this corresponds to a function we have analysis for, create its stack (recursively)
			rbp_func = state.bv.get_functions_containing(local_return_addr)
			if state.bv.read(local_return_addr, 1) and len(rbp_func) > 0:
				recurse_stack_x86_64(state, local_return_addr, rbp + state.memory_view.arch.address_size * 2, saved_rbp)
		else:
			# Can't recurse if we don't know where rbp goes (todo: yes we can)
			create_generic_stack_structure_x86_64(state, rsp, width)

def deref_var_x86_64(function, ip, rbp, name, reader):
	local_vars = [v for v in function.vars if v.name == name]
	for local_var in local_vars:
		if function.get_stack_var_at_frame_offset(local_var.storage, ip) == local_var:
			reader.seek(rbp + local_var.storage)
			reader.read64le()
			return reader.read64le()

def create_analysis_stack_structure_x86_64(state, ip, function, rbp):
	struct = Structure()
	struct.type = StructureType.StructStructureType

	width = -min(v.storage for v in function.vars)
	struct.width = width
	base = rbp - width

	# Take variables from current function
	for var in function.stack_layout:
		current_var = function.get_stack_var_at_frame_offset(var.storage, ip)
		if current_var == var:
			real_address = rbp + var.storage
			struct.insert(real_address - base, var.type, var.name)

	state.memory_view.define_data_var(base + state.memory_view.arch.address_size, Type.structure_type(struct))

def create_generic_stack_structure_x86_64(state, address, width):
	struct = Structure()
	struct.type = StructureType.StructStructureType
	struct.width = width

	# No function info, just use offsets
	for i in range(0, width, state.bv.arch.address_size):
		offset = (width - i)
		var_name = "var_{:x}".format(offset)
		struct.insert(i, Type.pointer(state.bv.arch, Type.void()), var_name)

	state.memory_view.define_data_var(address, Type.structure_type(struct))

