import os
from .ssa import ssa_operand, ssa_function, ssa_instruction
from .emulation.core import RegisterInputType
from .arch.x64 import RegistersX64
from typing import Dict


class FunctionDefinition(object):
    def __init__(self, name: str, arguments: Dict[int, int]):
        self.name = name
        self.arguments = arguments

    def get_arg_type(self, arg_op: ssa_operand.RegisterSSA):
        for known_arg_op, mem_type in self.arguments.items():
            if arg_op.index == known_arg_op:
                return mem_type
        return None


def get_known_function_definitions(binary_file: str, function_ssa: ssa_function.FunctionSSA) -> Dict[int, FunctionDefinition]:

    # Import plt functions if exist.
    plt_functions = dict()
    if os.path.isfile(binary_file + "_plt.txt"):
        with open(binary_file + "_plt.txt", 'r') as fp:
            for line in fp:
                line_split = line.split(" ")
                addr = int(line_split[0], 16)
                name = line_split[1].strip()
                plt_functions[name] = addr

    # Known function definitions.
    fct_defs = dict()
    cconv_regs = function_ssa.calling_convention.get_registers()
    temp_fct = FunctionDefinition("read", {cconv_regs[0]: RegisterInputType.Value,
                                           cconv_regs[1]: RegisterInputType.Memory,
                                           cconv_regs[2]: RegisterInputType.Value})
    fct_defs[temp_fct.name] = temp_fct
    temp_fct = FunctionDefinition("memcpy", {cconv_regs[0]: RegisterInputType.Memory,
                                             cconv_regs[1]: RegisterInputType.Memory,
                                             cconv_regs[2]: RegisterInputType.Value})
    fct_defs[temp_fct.name] = temp_fct
    temp_fct = FunctionDefinition("memset", {cconv_regs[0]: RegisterInputType.Memory,
                                             cconv_regs[1]: RegisterInputType.Value,
                                             cconv_regs[2]: RegisterInputType.Value})
    fct_defs[temp_fct.name] = temp_fct
    temp_fct = FunctionDefinition("memcmp", {cconv_regs[0]: RegisterInputType.Memory,
                                             cconv_regs[1]: RegisterInputType.Memory,
                                             cconv_regs[2]: RegisterInputType.Value})
    fct_defs[temp_fct.name] = temp_fct
    temp_fct = FunctionDefinition("strlen", {cconv_regs[0]: RegisterInputType.Memory})
    fct_defs[temp_fct.name] = temp_fct
    temp_fct = FunctionDefinition("open", {cconv_regs[0]: RegisterInputType.Memory})
    fct_defs[temp_fct.name] = temp_fct
    temp_fct = FunctionDefinition("strcmp", {cconv_regs[0]: RegisterInputType.Memory,
                                             cconv_regs[1]: RegisterInputType.Memory})
    fct_defs[temp_fct.name] = temp_fct
    temp_fct = FunctionDefinition("strncmp", {cconv_regs[0]: RegisterInputType.Memory,
                                              cconv_regs[1]: RegisterInputType.Memory,
                                              cconv_regs[2]: RegisterInputType.Value})
    fct_defs[temp_fct.name] = temp_fct

    # Create map from key to known function definition.
    known_fcts = dict()
    for name, addr in plt_functions.items():
        if name in fct_defs.keys():
            known_fcts[addr] = fct_defs[name]

    return known_fcts


def get_type_when_memory_op(mem_op_ssa: ssa_operand.MemorySSA, curr_op_ssa: ssa_operand.OperandSSA) -> int:

    # If current operand is the base of a memory expression, we consider the type as "Memory".
    if type(mem_op_ssa) == ssa_operand.MemoryX64SSA:
        if mem_op_ssa.base == curr_op_ssa:
            return RegisterInputType.Memory

        elif mem_op_ssa.has_index and mem_op_ssa.index == curr_op_ssa:

            # If current operand is the index of a memory expression and this index has a factor,
            # we consider the type as "Value".
            if mem_op_ssa.has_index_factor:
                return RegisterInputType.Value

            # When reaching this point (current operand is the index of a memory expression without
            # factor) we cannot tell if it is a "Memory" or "Value" and we still consider it as unknown.

        else:
            raise ValueError("Memory expression %s does not contain operand %s."
                             % (mem_op_ssa, curr_op_ssa))
    else:
        raise NotImplementedError("Memory for architecture not implemented.")

    return RegisterInputType.Unknown


def get_input_regs_from_fct(function_ssa: ssa_function.FunctionSSA, known_fcts: Dict[int, FunctionDefinition]) -> Dict[ssa_operand.OperandSSA, int]:

    # Create a SSA operand set for all argument registers.
    arg_regs_ssa = list()
    #'''
    for arg_reg in function_ssa.calling_convention.get_registers():
        temp_op_ssa = ssa_operand.RegisterX64SSA(arg_reg, 0, ssa_operand.OperandAccessType.Read)
        arg_regs_ssa.append(temp_op_ssa)
    #'''

    '''
    # TODO / DEBUG
    temp_op_ssa = ssa_operand.RegisterX64SSA(function_ssa.calling_convention.get_registers()[4], 0, ssa_operand.OperandAccessType.Read)
    arg_regs_ssa.append(temp_op_ssa)
    #'''

    # Create initial work list for checking if argument register is used for values or as memory object.
    work_list = list()
    arg_is_used = dict()
    already_processed = dict()
    for arg_reg_ssa in arg_regs_ssa:
        work_list.append((arg_reg_ssa, arg_reg_ssa))
        already_processed[arg_reg_ssa] = set()
        arg_is_used[arg_reg_ssa] = False
    input_args = dict() # type: Dict[ssa_operand.OperandSSA, int]

    already_processed_arg_regs = set()
    # Follow argument register usage to check if it is used as value or memory object.
    while work_list:
        curr_tupel = work_list[0]
        curr_op_ssa = curr_tupel[0]
        curr_op_arg_reg_dep = curr_tupel[1]
        work_list.pop(0)
        curr_uses = function_ssa.uses_map[curr_op_ssa]

        # Check all instructions that use the operand for memory usage.
        for instr in curr_uses:

            # Only process instruction for which we do not have decided the type of the operand.
            if curr_op_arg_reg_dep in already_processed_arg_regs:
                continue

            # Loop detection for the currently processed operand.
            if instr in already_processed[curr_op_arg_reg_dep]:
                continue
            already_processed[curr_op_arg_reg_dep].add(instr)

            # Consider direct copies of the operand and arithmetic because of pointer arithmetic (incomplete list).
            if instr.mnemonic in ["mov", "add", "sub", "cvtsi2sd", "xor", "movdqu", "movzx", "movsxd"]:  # TODO architecture specific
                count_as_used = True
                def_op_ssa = instr.definitions[0]

                # Do not follow all instructions but only check how the operands were used.
                do_follow = True
                if instr.mnemonic in ["xor"]:
                    do_follow = False

                # Special case of instructions for which the data flow is interrupted if the current operand is
                # in both "use" slots (such as "xor rdi, rdi" which just clears the register)
                if instr.mnemonic in ["xor"]:
                    ctr = 0
                    for use_op_ssa in instr.uses:
                        if use_op_ssa == curr_op_ssa:
                            ctr += 1
                    if ctr > 1:
                        count_as_used = False

                # Set argument register as used according to the result of the currently processed instruction.
                arg_is_used[curr_op_arg_reg_dep] |= count_as_used

                # Our currently processed operand is a register.
                if isinstance(curr_op_ssa, ssa_operand.RegisterSSA):

                    # Current operand is used in the definition memory expression as register.
                    if isinstance(def_op_ssa, ssa_operand.MemorySSA) and def_op_ssa.contains(curr_op_ssa):

                        # Try to deduce operand type.
                        op_type = get_type_when_memory_op(def_op_ssa, curr_op_ssa)
                        if op_type != RegisterInputType.Unknown:
                            input_args[curr_op_arg_reg_dep] = op_type
                            already_processed_arg_regs.add(curr_op_arg_reg_dep)
                            break

                    # Current operand is used in the use memory expression as register.
                    for use_op_ssa in instr.uses:
                        if isinstance(use_op_ssa, ssa_operand.MemorySSA) and use_op_ssa.contains(curr_op_ssa):

                            # Try to deduce operand type.
                            op_type = get_type_when_memory_op(use_op_ssa, curr_op_ssa)
                            if op_type != RegisterInputType.Unknown:
                                input_args[curr_op_arg_reg_dep] = op_type
                                already_processed_arg_regs.add(curr_op_arg_reg_dep)
                                break

                if do_follow:
                    work_list.append((def_op_ssa, curr_op_arg_reg_dep))

            # Check if operand is used in a memory expression when loading the address.
            elif instr.mnemonic == "lea":  # TODO architecture specific
                arg_is_used[curr_op_arg_reg_dep] = True

                # Since "lea" is often used for optimization purposes to calculate a value, we cannot
                # distinguish if it is used as "Memory" pointer or "Value. Hence, we ignore it.
                pass

            # Check if operand is checked against a low number (not zero) to deduce if it is a "Value".
            elif instr.mnemonic in ["cmp", "test"]: # TODO architecture specific
                arg_is_used[curr_op_arg_reg_dep] = True

                if isinstance(curr_op_ssa, ssa_operand.RegisterSSA):
                    used_plain = False
                    for use_op_ssa in instr.uses:

                        # If the current operand is part of a memory expression, try to deduce operand type.
                        if isinstance(use_op_ssa, ssa_operand.MemorySSA) and use_op_ssa.contains(curr_op_ssa):
                            op_type = get_type_when_memory_op(use_op_ssa, curr_op_ssa)
                            if op_type != RegisterInputType.Unknown:
                                input_args[curr_op_arg_reg_dep] = op_type
                                already_processed_arg_regs.add(curr_op_arg_reg_dep)
                                break
                            break

                        # Set flag if current operand is used plain by the instruction.
                        elif use_op_ssa == curr_op_ssa:
                            used_plain = True
                            break

                    # If the current operand is used plain and compared against a constant value which is non-zero
                    # and in a specific range that does not constitute an address, we consider it a "Value".
                    if used_plain:
                        for use_op_ssa in instr.uses:
                            if isinstance(use_op_ssa, ssa_operand.ConstantSSA):
                                if use_op_ssa.value != 0 and use_op_ssa.value < 0x1000:
                                    input_args[curr_op_arg_reg_dep] = RegisterInputType.Value
                                    already_processed_arg_regs.add(curr_op_arg_reg_dep)
                                    break

            # Check if operand is used with an instruction from that we can deduce it is a "Value".
            elif instr.mnemonic in ["imul", "mul", "div", "ror", "rol", "sar", "sal", "mulsd"]:
                arg_is_used[curr_op_arg_reg_dep] = True

                if isinstance(curr_op_ssa, ssa_operand.RegisterSSA):
                    for use_op_ssa in instr.uses:
                        if use_op_ssa == curr_op_ssa:
                            input_args[curr_op_arg_reg_dep] = RegisterInputType.Value
                            already_processed_arg_regs.add(curr_op_arg_reg_dep)
                            break

            # Check if operand is used with an instruction for which we can deduce only memory dereferences.
            elif instr.mnemonic in ["push"]:
                arg_is_used[curr_op_arg_reg_dep] = True

                if isinstance(curr_op_ssa, ssa_operand.RegisterSSA):
                    for use_op_ssa in instr.uses:

                        # If the current operand is part of a memory expression, try to deduce operand type.
                        if isinstance(use_op_ssa, ssa_operand.MemorySSA) and use_op_ssa.contains(curr_op_ssa):
                            op_type = get_type_when_memory_op(use_op_ssa, curr_op_ssa)
                            if op_type != RegisterInputType.Unknown:
                                input_args[curr_op_arg_reg_dep] = op_type
                                already_processed_arg_regs.add(curr_op_arg_reg_dep)
                                break
                            break

            # Check if operand is used as an argument for a known function (e.g., read from libc) and
            # deduce type from it.
            elif type(instr) == ssa_instruction.InstructionSSA and instr.is_call:
                target = instr.uses[0]
                if isinstance(target, ssa_operand.ConstantSSA):
                    target_addr = target.value
                    if target_addr in known_fcts.keys():
                        fct_obj = known_fcts[target_addr]
                        op_type = fct_obj.get_arg_type(curr_op_ssa)
                        if op_type is not None and op_type != RegisterInputType.Unknown:
                            input_args[curr_op_arg_reg_dep] = op_type
                            already_processed_arg_regs.add(curr_op_arg_reg_dep)
                            break

            # Consider phi instructions to also include loops.
            elif type(instr) == ssa_instruction.PhiNodeSSA:
                def_op_ssa = instr.definitions[0]
                work_list.append((def_op_ssa, curr_op_arg_reg_dep))

            else:
                arg_is_used[curr_op_arg_reg_dep] = True

    # Go backwards through the argument register and check which is the last argument register we identified as used.
    # Fill the type with "Unknown" if we could not identify it.
    # Further, if we did not find a usage of an argument register in between the last used one and the beginning,
    # add it as "Unknown".
    arg_regs_idxs = function_ssa.calling_convention.get_registers()
    arg_regs_idxs.reverse()
    found = False
    for arg_reg_idx in arg_regs_idxs:

        temp_op_ssa = ssa_operand.RegisterX64SSA(arg_reg_idx, 0, ssa_operand.OperandAccessType.Read)
        if temp_op_ssa in arg_is_used.keys() and arg_is_used[temp_op_ssa]:
            found = True
            if temp_op_ssa not in input_args.keys():
                input_args[temp_op_ssa] = RegisterInputType.Unknown

        else:
            if found:
                input_args[temp_op_ssa] = RegisterInputType.Unknown

    '''
    # TODO / DEBUG
    input_args = dict()
    temp_op_ssa = ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read)
    input_args[temp_op_ssa] = RegisterInputType.Memory
    temp_op_ssa = ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read)
    input_args[temp_op_ssa] = RegisterInputType.Value
    #'''

    return input_args


def get_input_regs(binary_file: str, function_ssa: ssa_function.FunctionSSA) -> Dict[ssa_operand.OperandSSA, int]:
    known_fcts = get_known_function_definitions(binary_file, function_ssa)
    return get_input_regs_from_fct(function_ssa, known_fcts)


def convert_input_args_ssa_to_unicorn(input_args: Dict[ssa_operand.OperandSSA, int]) -> Dict[int, int]:
    """
    Converts the input arguments (as returned by `get_input_regs`) into input arguments used by unicorn
    (more specifically, the SSA register into a unicorn register).

    :param input_args: input arguments as returned by `get_input_regs`
    :return: dict of input arguments with SSA register representation replaced by unicorn register representation.
    """
    input_args_unicorn = dict()
    for arg_reg_ssa, access_type in input_args.items():
        unicorn_op = RegistersX64.to_unicorn(arg_reg_ssa.index)
        input_args_unicorn[unicorn_op] = access_type
    return input_args_unicorn