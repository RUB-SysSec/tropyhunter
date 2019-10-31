from unicorn import *
from unicorn.x86_const import *
from typing import Dict, Any, List, DefaultDict, Optional, Set
from ..arch.x64 import RegistersX64
import random
import os
import struct
import time
from .core import EmulatorEnv, InputDataTypeRule
from .core import InitialMemoryObject, RuntimeMemoryObject, RuntimeMemoryObjectType, RegisterInputType, RegisterInput
from .lib_emulation import *


def eflags_set_cf(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur | 0x1
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_set_pf(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur | (2 < 0x1)
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_set_af(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur | (4 < 0x1)
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_set_zf(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur | (6 < 0x1)
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_set_sf(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur | (7 < 0x1)
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_set_of(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur | (11 < 0x1)
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_clear_cf(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur & ~0x1
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_clear_pf(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur & ~(2 < 0x1)
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_clear_af(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur & ~(4 < 0x1)
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_clear_zf(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur & ~(6 < 0x1)
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_clear_sf(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur & ~(7 < 0x1)
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def eflags_clear_of(mu: Uc):
    eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags = eflags_cur & ~(11 < 0x1)
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)


def hook_syscall(mu: Uc, emu_env: EmulatorEnv):
    syscall_id = mu.reg_read(UC_X86_REG_RAX)

    # read
    if syscall_id == 0x0:
        fd = mu.reg_read(UC_X86_REG_RDI)
        dst_ptr = mu.reg_read(UC_X86_REG_RSI)
        size = mu.reg_read(UC_X86_REG_RDX)
        emu_read(mu, emu_env, fd, dst_ptr, size)

    # open
    elif syscall_id == 0x2:
        file_ptr = mu.reg_read(UC_X86_REG_RDI)
        emu_open(mu, emu_env, file_ptr)

    # close
    elif syscall_id == 0x3:
        fd = mu.reg_read(UC_X86_REG_RDI)
        emu_close(mu, emu_env, fd)

    # fstat
    elif syscall_id == 0x5:
        fd = mu.reg_read(UC_X86_REG_RDI)
        dst_ptr = mu.reg_read(UC_X86_REG_RSI)
        emu_fstat(mu, emu_env, fd, dst_ptr)

    # poll
    elif syscall_id == 0x7:
        poll_fd_ptr = mu.reg_read(UC_X86_REG_RDI)
        num = mu.reg_read(UC_X86_REG_RSI)
        timeout = mu.reg_read(UC_X86_REG_RDX)
        emu_poll(mu, emu_env, poll_fd_ptr, num, timeout)

    # getpid
    elif syscall_id == 0x27:
        emu_getpid(mu, emu_env)

    # getuid
    elif syscall_id == 0x66:
        emu_getuid(mu, emu_env)

    # time
    elif syscall_id == 0xc9:
        dst_ptr = mu.reg_read(UC_X86_REG_RDI)
        emu_time(mu, emu_env, dst_ptr)

    # sys_getrandom
    elif syscall_id == 0x13e:
        dst_ptr = mu.reg_read(UC_X86_REG_RDI)
        count = mu.reg_read(UC_X86_REG_RSI)
        flags = mu.reg_read(UC_X86_REG_RDX)
        emu_sys_getrandom(mu, emu_env, dst_ptr, count, flags)

    else:
        print("Instruction address: %08x Unknown syscall: %d" % (mu.reg_read(UC_X86_REG_RIP), syscall_id))


def hook_code(mu: Uc, address, size, emu_env: EmulatorEnv):

    # DEBUG
    if emu_env.debug_instr_trace:
        print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
    if address in emu_env.debug_dyn_breakpoints:
        print("Dynamic Breakpoint at %08x" % address)

    # Magic number of unicorn which means something does not work while fetching the instruction.
    if size == 0xf1f1f1f1:
        cs_gen = emu_env.capstone.disasm(mu.mem_read(address, 16), address)
        try:
            cs_instr = cs_gen.__next__()
        except:
            cs_instr = None
        # Since unicorn crashes when using rdrand and instruction hook on rdrand does not work either,
        # check it manually :(
        if cs_instr and cs_instr.mnemonic == "rdrand":
            # https://www.felixcloutier.com/x86/rdrand
            unicorn_reg = RegistersX64.from_str_to_unicorn(cs_instr.op_str)
            data = os.urandom(8)
            value = struct.unpack("Q", data)
            mu.reg_write(unicorn_reg, value[0])
            eflags_clear_of(mu)
            eflags_clear_sf(mu)
            eflags_clear_zf(mu)
            eflags_clear_af(mu)
            eflags_clear_pf(mu)
            eflags_set_cf(mu)
            mu.reg_write(UC_X86_REG_RIP, address + cs_instr.size)
            return

    # If a plt function is called, check if we have a function that emulates it.
    if address in emu_env.plt_functions.keys():
        name = emu_env.plt_functions[address]
        if name in emu_env.lib_wrapper_funcs.keys():
            emu_env.lib_wrapper_funcs[name](mu, emu_env)
        elif emu_env.debug_output:
            print("Library function '%s' not available." % name)
        mu.reg_write(UC_X86_REG_RIP, emu_env.addr_ret_instr)

    # If we have multiple function endings, stop emulation if we reached one.
    if emu_env.fct_ends.end_exists(address):
        # print("Reached stop at address: %08x" % address) # DEBUG
        mu.emu_stop()

    curr_time = int(time.time())
    if (curr_time - emu_env.single_run_start_time) > emu_env.single_run_timeout:
        emu_env.single_run_is_timeout = True
        mu.emu_stop()


def hook_unmapped_read(mu: Uc, access, address, size, value, emu_env: EmulatorEnv):
    '''
    print("hook_unmapped_read")
    print("Instruction address: " + hex(mu.reg_read(UC_X86_REG_RIP)))
    print("Address: " + hex(address))
    print("Size: " + hex(size))
    print(value)
    # '''

    allignment = address % 4096
    base_addr = address - allignment
    size_4kb_aligned = (int(size / (4096)) + 1) * ((4096))

    # Seed with random values.
    data = b'\x00' * size_4kb_aligned

    # Store object for created memory.
    init_mem_obj = InitialMemoryObject(base_addr, size_4kb_aligned, data)
    mem_obj = RuntimeMemoryObject(base_addr,
                                  base_addr + size_4kb_aligned,
                                  RuntimeMemoryObjectType.Runtime,
                                  init_mem_obj=init_mem_obj)
    emu_env.runtime_memory_objs.append(mem_obj)

    mu.mem_map(base_addr, size_4kb_aligned)
    mu.mem_write(base_addr, data)

    return True


def hook_unmapped_write(mu: Uc, access, address, size, value, emu_env: EmulatorEnv):
    '''
    print("hook_unmapped_write")
    print("Instruction address: " + hex(mu.reg_read(UC_X86_REG_RIP)))
    print("Address: " + hex(address))
    print("Size: " + hex(size))
    print("Value: " + str(value))
    #'''

    allignment = address % 4096
    base_addr = address - allignment
    size_4kb_aligned = (int(size / (4096)) + 1) * ((4096))

    # Seed with random values.
    data = b'\x00' * size_4kb_aligned

    # Store object for created memory.
    init_mem_obj = InitialMemoryObject(base_addr, size_4kb_aligned, data)
    mem_obj = RuntimeMemoryObject(base_addr,
                                  base_addr + size_4kb_aligned,
                                  RuntimeMemoryObjectType.Runtime,
                                  init_mem_obj=init_mem_obj)
    emu_env.runtime_memory_objs.append(mem_obj)

    mu.mem_map(base_addr, size_4kb_aligned)
    mu.mem_write(base_addr, data)

    return True


def hook_mem_read(mu: Uc, access, address: int, size: int, value: int, emu_env: EmulatorEnv):

    '''
    print("hook_mem_read")
    print("Instruction address: " + hex(mu.reg_read(UC_X86_REG_RIP)))
    print("Address: " + hex(address))
    print("Size: " + hex(size))
    print("Data: " + str(mu.mem_read(address, size)))
    # '''

    # Add memory access to the runtime memory objects.
    for mem_obj in emu_env.runtime_memory_objs:
        if mem_obj.contains_addr(address):
            data = bytes(mu.mem_read(address, size))
            instr_addr = mu.reg_read(UC_X86_REG_RIP)
            mem_obj.add_mem_read(address, size, data, instr_addr)
            break


def hook_mem_write(mu: Uc, access, address, size, value, emu_env: EmulatorEnv):

    '''
    print("hook_mem_write")
    print("Instruction address: " + hex(mu.reg_read(UC_X86_REG_RIP)))
    print("Address: " + hex(address))
    print("Size: " + hex(size))
    print("Value: " + str(value))
    # '''

    # Add memory access to the runtime memory objects.
    for mem_obj in emu_env.runtime_memory_objs:
        if mem_obj.contains_addr(address):

            data = b"" # type: bytes
            if size == 1:
                data = struct.pack("B", value)  # TODO architecture specific
            elif size == 2:
                data = struct.pack("H", value)  # TODO architecture specific
            elif size == 4:
                data = struct.pack("I", value) # TODO architecture specific
            elif size == 8:
                try:
                    data = struct.pack("Q", value) # TODO architecture specific
                except:
                    data = struct.pack("q", value)  # TODO architecture specific
            else:
                raise NotImplementedError("Write data size not implemented yet.")
            instr_addr = mu.reg_read(UC_X86_REG_RIP)
            mem_obj.add_mem_write(address, size, data, instr_addr)
            break


def hook_block(mu: Uc, address, size, emu_env: EmulatorEnv):
    if emu_env.debug_bb_trace:
        print(">>> Basic block: %08x" % address)
    emu_env.basic_block_coverage.add(address)


def generate_input_data(input_data_type: int, size: int) -> bytes:
    data = b''
    if input_data_type == InputDataTypeRule.Zero:
        data = b"\x00" * size

    elif input_data_type == InputDataTypeRule.One:
        data = b""  # type: bytes
        if size == 1:
            data += struct.pack("B", 1)  # TODO architecture specific
        elif size == 2:
            data += struct.pack("H", 1)  # TODO architecture specific
        elif size == 4:
            data += struct.pack("I", 1)  # TODO architecture specific
        elif size == 8:
            data += struct.pack("Q", 1)  # TODO architecture specific
        else:
            raise NotImplementedError("Input data size not implemented yet.")

    # Creates small positive random values for a 8 byte alignment.
    elif input_data_type == InputDataTypeRule.RandomPlus8Small:
        data = b''
        while len(data) < size:
            rest_len = size - len(data)
            if rest_len >= 8:
                data += struct.pack("Q", ord(os.urandom(1)) & 0x7f)
            else:
                data += b'\x00' * rest_len

    # Creates small positive random values for a 4 byte alignment.
    elif input_data_type == InputDataTypeRule.RandomPlus4Small:
        data = b''
        while len(data) < size:
            rest_len = size - len(data)
            if rest_len >= 4:
                data += struct.pack("H", ord(os.urandom(1)) & 0x7f)
            else:
                data += b'\x00' * rest_len

    elif input_data_type == InputDataTypeRule.RandomPlus:
        # Fixes the highest bit so the highest bit is 0 in order to have a positive number when read (obviously, this
        # reduces the entropy of our random value but we do not care)
        data = b''
        for _ in range(size):
            data += chr(ord(os.urandom(1)) & 0x7f).encode("ISO-8859-1")

    # Creates small negative random values for a 8 byte alignment.
    elif input_data_type == InputDataTypeRule.RandomMinus:
        # Fixes the highest bit so the highest bit is 1 in order to have a negative number when read (obviously, this
        # reduces the entropy of our random value but we do not care)
        data = b''
        for _ in range(size):
            data += str(chr(ord(os.urandom(1)) | 0x80)).encode("ISO-8859-1")

    # Creates small negative random values for a 4 byte alignment.
    elif input_data_type == InputDataTypeRule.RandomMinus8Small:
        data = b''
        while len(data) < size:
            rest_len = size - len(data)
            if rest_len >= 8:
                data += struct.pack("Q", ord(os.urandom(1)) | 0x80)
            else:
                data += b'\x00' * rest_len

    elif input_data_type == InputDataTypeRule.RandomMinus4Small:
        data = b''
        while len(data) < size:
            rest_len = size - len(data)
            if rest_len >= 4:
                data += struct.pack("H", ord(os.urandom(1)) | 0x80)
            else:
                data += b'\x00' * rest_len

    elif input_data_type == InputDataTypeRule.Random:
        data = os.urandom(size)

    else:
        raise NotImplementedError("Input data type rule not implemented.")

    return data


def init_input_regs(mu: Uc, emu_env: EmulatorEnv, input_regs: Dict[int, RegisterInput]):

    for unicorn_reg, reg_input_obj in input_regs.items():

        # Use value when one is given.
        if reg_input_obj.value is not None:
            mu.reg_write(unicorn_reg, reg_input_obj.value)

        # Generate random value for register and store it for reuse.
        elif reg_input_obj.input_type == RegisterInputType.Value:
            value = 8
            if reg_input_obj.value is not None:
                value = reg_input_obj.value

            mu.reg_write(unicorn_reg, value)
            reg_input_obj.set_value(value)
            print("Set register %s to initial value: %d"
                  % (RegistersX64.from_unicorn_to_str(unicorn_reg), value))

        # Generate random memory address for register and store it for reuse.
        elif reg_input_obj.input_type == RegisterInputType.Memory:
            mem_addr = emu_env.dyn_mem_obj_start_addr + (emu_env.dyn_mem_obj_ctr * emu_env.dyn_mem_obj_size)

            # If a rule is given to generate the data, use it otherwise generate data with 0.
            data = generate_input_data(reg_input_obj.init_data_type, emu_env.dyn_mem_obj_size)

            # Store object for created memory.
            init_mem_obj = InitialMemoryObject(mem_addr, emu_env.dyn_mem_obj_size, data)
            mem_obj = RuntimeMemoryObject(mem_addr,
                                          mem_addr + emu_env.dyn_mem_obj_size,
                                          RuntimeMemoryObjectType.Argument,
                                          init_mem_obj=init_mem_obj)
            emu_env.runtime_memory_objs.append(mem_obj)

            # Map memory in unicorn
            mu.reg_write(unicorn_reg, mem_addr)
            mu.mem_map(mem_addr, emu_env.dyn_mem_obj_size)
            mu.mem_write(mem_addr,data)

            reg_input_obj.set_value(mem_addr)
            emu_env.dyn_mem_obj_ctr += 1
            print("Set register %s to initial memory address: %08x"
                  % (RegistersX64.from_unicorn_to_str(unicorn_reg), mem_addr))

    # Prepare stack register.
    mu.reg_write(emu_env.stack_reg, emu_env.stack_addr + emu_env.stack_size - 1)
    mu.mem_write(emu_env.stack_addr, b'\x00' * emu_env.stack_size)

    # Prepare all special memory locations (e.g., artificial instructions, fs register for Linux x86_64).
    # Fill memory locations with 0 and if initial data is given overwrite it.
    for mem_obj in emu_env.special_mem_list:
        mu.mem_write(mem_obj.start_addr, b'\x00' * (mem_obj.end_addr - mem_obj.start_addr))
        if mem_obj.init_mem_obj is not None:
            mu.mem_write(mem_obj.init_mem_obj.addr, mem_obj.init_mem_obj.data)

    # Prepare register with special values (e.g., fs register for Linux x86_64).
    for uc_reg, value in emu_env.special_reg_map.items():
        mu.reg_write(uc_reg, value)

    # After the memory was initialized, change everything that has to be changed according to our fuzzing rules.
    for fuzz_mem_obj in set(emu_env.runtime_memory_changes):
        for mem_obj in emu_env.runtime_memory_objs:
            if mem_obj.contains_addr(fuzz_mem_obj.addr):
                emu_env.runtime_memory_changes.remove(fuzz_mem_obj)
                data = generate_input_data(fuzz_mem_obj.fuzz_type, fuzz_mem_obj.size)
                mem_obj.change_init_data(fuzz_mem_obj.addr, data)
                mu.mem_write(fuzz_mem_obj.addr, data)
                break


def init_emulator(memory_objects: List[InitialMemoryObject], emu_env: EmulatorEnv):

    # x86_64
    mu = Uc(emu_env.uc_arch, emu_env.uc_mode) # TODO architecture specific

    # Load memory objects extracted from the binary file into memory.
    highest_mem_obj_addr = 0
    highest_mem_obj_size = 0
    for memory_obj in memory_objects:
        base_addr = memory_obj.addr - (memory_obj.addr % 4096)
        size_4kb_aligned = (int(memory_obj.size / 4096) + 1) * 4096
        if memory_obj.addr != base_addr:
            size_4kb_aligned += 4096

        # Store object for created memory.
        mem_obj = RuntimeMemoryObject(base_addr,
                                      base_addr + size_4kb_aligned,
                                      RuntimeMemoryObjectType.Section,
                                      init_mem_obj=memory_obj)
        emu_env.runtime_memory_objs.append(mem_obj)

        mu.mem_map(base_addr, size_4kb_aligned)
        mu.mem_write(memory_obj.addr, memory_obj.data)

        # Get the highest memory address of the created sections.
        if base_addr > highest_mem_obj_addr:
            highest_mem_obj_addr = base_addr
            highest_mem_obj_size = size_4kb_aligned

    # Prepare stack.
    mu.mem_map(emu_env.stack_addr, emu_env.stack_size)
    mem_obj = RuntimeMemoryObject(emu_env.stack_addr,
                                  emu_env.stack_addr + emu_env.stack_size,
                                  RuntimeMemoryObjectType.Stack)
    emu_env.runtime_memory_objs.append(mem_obj)

    # Prepare special memory object in which artificial instructions such as a return instruction reside.
    artificial_instr_start_addr = emu_env.special_start_addr + (emu_env.special_ctr * emu_env.special_size)
    mu.mem_map(artificial_instr_start_addr, emu_env.special_size)
    init_mem_obj = InitialMemoryObject(artificial_instr_start_addr, emu_env.special_size, b'\x00' * emu_env.special_size)
    # Set return instruction.
    init_mem_obj.change_data(artificial_instr_start_addr, b'\xC3') # TODO architecture specific
    emu_env.addr_ret_instr = artificial_instr_start_addr
    mem_obj = RuntimeMemoryObject(artificial_instr_start_addr,
                                  artificial_instr_start_addr + emu_env.special_size,
                                  RuntimeMemoryObjectType.Special,
                                  name="artificial_instrs",
                                  init_mem_obj=init_mem_obj)
    emu_env.runtime_memory_objs.append(mem_obj)
    emu_env.special_mem_list.append(mem_obj)
    emu_env.special_ctr += 1

    ''' TODO worked in unicorn 1.0.1, but crashes unicorn 1.0.2
    # Prepare fs (used by Linux under x86_64)
    fs_start_addr = emu_env.special_start_addr + (emu_env.special_ctr * emu_env.special_size)
    mu.mem_map(fs_start_addr, emu_env.special_size)
    init_mem_obj = InitialMemoryObject(fs_start_addr, emu_env.special_size, b'\x00' * emu_env.special_size)
    mem_obj = RuntimeMemoryObject(fs_start_addr,
                                  fs_start_addr + emu_env.special_size,
                                  RuntimeMemoryObjectType.Special,
                                  init_mem_obj=init_mem_obj)
    emu_env.runtime_memory_objs.append(mem_obj)
    emu_env.special_mem_list.append(mem_obj)
    emu_env.special_reg_map[UC_X86_REG_FS] = mem_obj.start_addr
    emu_env.special_ctr += 1
    '''

    # Set start address for dynamic memory objects.
    emu_env.dyn_mem_obj_start_addr = highest_mem_obj_addr + 2 * highest_mem_obj_size

    return mu


def emulate_function(mu: Uc, emu_env: EmulatorEnv, fct_start: int, input_regs: Dict[int, RegisterInput]) -> bool:

    # Destroy on the fly malloc memory.
    for _, mem_obj in emu_env.emu_heap_objs.items():
        mu.mem_unmap(mem_obj.address, mem_obj.size_aligned)

    # Reset emulation environment for emulation.
    emu_env.reset()

    # Initialize input registers.
    init_input_regs(mu, emu_env, input_regs)

    emu_env.single_run_start_time = int(time.time())

    # Start emulation.
    emu_success = True
    try:
        mu.emu_start(fct_start, 0xFFFFFFFF)
    except Exception as e:
        emu_success = False
        if emu_env.debug_output:
            print("Emulation crashed at last instruction %08x." % mu.reg_read(UC_X86_REG_RIP))
            print(e)

    emu_env.single_run_start_time = 0

    # DEBUG
    #print("Finished at %08x" % mu.reg_read(UC_X86_REG_RIP))

    return emu_success
