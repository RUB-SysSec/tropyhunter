from unicorn import *
from unicorn.x86_const import *
from .core import InitialMemoryObject, RuntimeMemoryObject, RuntimeMemoryObjectType
import os
import struct
import time

from .core import EmulatorEnv, EmulationHeapMemoryObject


def register_lib_emulations(emu_env: EmulatorEnv) -> None:
    """
    Registers all emulation functions that emulate a certain library function (e.g., syscall() in libc)

    :param emu_env: Emulation environment.
    """
    emu_env.lib_wrapper_funcs["syscall"] = emu_libc_syscall
    emu_env.lib_wrapper_funcs["strlen"] = emu_libc_strlen
    emu_env.lib_wrapper_funcs["malloc"] = emu_libc_malloc
    emu_env.lib_wrapper_funcs["memset"] = emu_libc_memset
    emu_env.lib_wrapper_funcs["getpid"] = emu_libc_getpid
    emu_env.lib_wrapper_funcs["open"] = emu_libc_open
    emu_env.lib_wrapper_funcs["open64"] = emu_libc_open
    emu_env.lib_wrapper_funcs["fopen"] = emu_libc_fopen
    emu_env.lib_wrapper_funcs["read"] = emu_libc_read
    emu_env.lib_wrapper_funcs["fread"] = emu_libc_fread
    emu_env.lib_wrapper_funcs["close"] = emu_libc_close
    emu_env.lib_wrapper_funcs["fclose"] = emu_libc_fclose
    emu_env.lib_wrapper_funcs["setvbuf"] = emu_libc_setvbuf
    emu_env.lib_wrapper_funcs["time"] = emu_libc_time
    emu_env.lib_wrapper_funcs["gettimeofday"] = emu_libc_gettimeofday
    emu_env.lib_wrapper_funcs["__errno_location"] = emu_core_errno_location
    emu_env.lib_wrapper_funcs["__fxstat"] = emu_libc_fxstat
    emu_env.lib_wrapper_funcs["memcpy"] = emu_libc_memcpy


def emu_read(mu: Uc, emu_env: EmulatorEnv, fd: int, dst_ptr: int, size: int):
    """
    Emulates read syscall functionality.
    """
    if fd not in emu_env.emu_fd_open.keys():
        mu.reg_write(UC_X86_REG_RAX, -1)
    else:
        file_name = emu_env.emu_fd_open[fd]
        if file_name in [b"/dev/urandom", b"/dev/random"]:
            data = os.urandom(size)
            mu.mem_write(dst_ptr, data)
        else:
            size = 0 # return EOF
        mu.reg_write(UC_X86_REG_RAX, size)


def emu_open(mu: Uc, emu_env: EmulatorEnv, file_ptr: int):
    """
    Emulates open syscall functionality.
    """
    file_name = b''
    curr_byte = mu.mem_read(file_ptr, 1)
    while curr_byte != b'\x00':
        file_name += curr_byte
        file_ptr += 1
        curr_byte = mu.mem_read(file_ptr, 1)

    new_fd = emu_env.emu_fd_next
    emu_env.emu_fd_next += 1
    emu_env.emu_fd_open[new_fd] = file_name
    mu.reg_write(UC_X86_REG_RAX, new_fd)


def emu_close(mu: Uc, emu_env: EmulatorEnv, fd: int):
    """
    Emulates close syscall functionality.
    """
    if fd not in emu_env.emu_fd_open.keys():
        mu.reg_write(UC_X86_REG_RAX, -1)
    else:
        del emu_env.emu_fd_open[fd]
        mu.reg_write(UC_X86_REG_RAX, 0)


def emu_fstat(mu: Uc, emu_env: EmulatorEnv, fd: int, dst_ptr: int):
    """
    Emulates fstat syscall functionality.
    """
    if fd not in emu_env.emu_fd_open.keys():
        # error
        mu.reg_write(UC_X86_REG_RAX, -1)
    else:
        file_name = emu_env.emu_fd_open[fd]

        # We only care for our random block devices (checked for example by openssl before used).
        if file_name in [b"/dev/urandom", b"/dev/random"]:

            # TODO architecture specific
            # Offsets taken from x86-64 Ubuntu machine.
            st_dev = 6  # 8 Bytes 0x0
            st_ino = 11  # 8 Bytes 0x8
            st_nlink = 1  # 8 Bytes 0x10
            st_mode = 8630  # 4 Bytes (otcal 20666) 0x18
            st_uid = 0  # 4 Bytes 0x1c
            st_gid = 0  # 4 Bytes 0x20
            st_rdev = 265  # 8 Bytes 0x28
            st_size = 0  # 8 Bytes 0x30
            st_blksize = 4096  # 8 Bytes 0x38
            st_blocks = 0  # 8 Bytes 0x40
            st_atime = 1550134027  # 8 Bytes 0x48
            st_mtime = 1550134027  # 8 Bytes 0x58
            st_ctime = 1550134027  # 8 Bytes 0x68

            data = b""
            data += struct.pack("Q", st_dev)  # 0x0 -> 0x8
            data += struct.pack("Q", st_ino)  # 0x8 -> 0x10
            data += struct.pack("Q", st_nlink)  # 0x10 -> 0x18
            data += struct.pack("I", st_mode)  # 0x18 -> 0x1c
            data += struct.pack("I", st_uid)  # 0x1c -> 0x20
            data += struct.pack("I", st_gid)  # 0x20 -> 0x24
            data += b'\x00' * 4  # 0x24 -> 0x28
            data += struct.pack("Q", st_rdev)  # 0x28 -> 0x30
            data += struct.pack("Q", st_size)  # 0x30 -> 0x38
            data += struct.pack("Q", st_blksize)  # 0x38 -> 0x40
            data += struct.pack("Q", st_blocks)  # 0x40 -> 0x48
            data += struct.pack("Q", st_atime)  # 0x48 -> 0x50
            data += b'\x00' * 8  # 0x50 -> 0x58
            data += struct.pack("Q", st_mtime)  # 0x58 -> 0x60
            data += b'\x00' * 8  # 0x60 -> 0x68
            data += struct.pack("Q", st_ctime)  # 0x68 -> 0x70
            data += b'\x00' * 8  # 0x70 -> 0x78

            mu.mem_write(dst_ptr, data)

        elif emu_env.debug_output:
            print("fstat functionality not implemented for '%s'." % file_name)

        mu.reg_write(UC_X86_REG_RAX, 0)


def emu_poll(mu: Uc, emu_env: EmulatorEnv, poll_fd_ptr: int, num: int, timeout: int):
    """
    Emulates poll syscall functionality.
    """
    mu.reg_write(UC_X86_REG_RAX, -1)

    # TODO architecture specific
    for i in range(num):
        struct_pollfd = mu.mem_read(poll_fd_ptr + (i * 8), 8)
        fd = struct.unpack("I", struct_pollfd[0:4])[0]
        events = struct.unpack("H", struct_pollfd[4:6])[0]
        ctr_succ = 0

        if fd in emu_env.emu_fd_open.keys():
            ctr_succ += 1
            file_name = emu_env.emu_fd_open[fd]

            # We only implement POLLIN at the moment.
            if events == 0x1:
                mu.mem_write(poll_fd_ptr + (i * 8) + 6, b"\x01\x00")

            elif emu_env.debug_output:
                print("poll functionality '%d' not implemented for '%s'." % (events, file_name))

        # On success the number of structures which have nonzero revents fields is returned.
        mu.reg_write(UC_X86_REG_RAX, ctr_succ)


def emu_getpid(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates getpid syscall functionality.
    """
    pid = os.getpid()
    mu.reg_write(UC_X86_REG_RAX, pid)


def emu_getuid(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates getuid syscall functionality.
    """
    uid = os.getuid()
    mu.reg_write(UC_X86_REG_RAX, uid)


def emu_time(mu: Uc, emu_env: EmulatorEnv, dst_ptr):
    """
    Emulates time syscall functionality.
    """
    curr_time = int(time.time())
    if dst_ptr != 0:
        data = struct.pack("I", curr_time)
        mu.mem_write(dst_ptr, data)
    mu.reg_write(UC_X86_REG_RAX, curr_time)


def emu_sys_getrandom(mu: Uc, emu_env: EmulatorEnv, dst_ptr: int, count: int, flags: int):
    """
    Emulates sys_getrandom syscall functionality.
    """
    data = os.urandom(count)
    mu.mem_write(dst_ptr, data)
    mu.reg_write(UC_X86_REG_RAX, count)


def emu_libc_syscall(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc syscall functionality.
    """
    syscall_id = mu.reg_read(UC_X86_REG_RDI)

    # read
    if syscall_id == 0x0:
        fd = mu.reg_read(UC_X86_REG_RSI)
        dst_ptr = mu.reg_read(UC_X86_REG_RDX)
        size = mu.reg_read(UC_X86_REG_RCX)
        emu_read(mu, emu_env, fd, dst_ptr, size)

    # open
    elif syscall_id == 0x2:
        file_ptr = mu.reg_read(UC_X86_REG_RSI)
        emu_open(mu, emu_env, file_ptr)

    # close
    elif syscall_id == 0x3:
        fd = mu.reg_read(UC_X86_REG_RSI)
        emu_close(mu, emu_env, fd)

    # fstat
    elif syscall_id == 0x5:
        fd = mu.reg_read(UC_X86_REG_RSI)
        dst_ptr = mu.reg_read(UC_X86_REG_RDX)
        emu_fstat(mu, emu_env, fd, dst_ptr)

    # poll
    elif syscall_id == 0x7:
        poll_fd_ptr = mu.reg_read(UC_X86_REG_RSI)
        num = mu.reg_read(UC_X86_REG_RDX)
        timeout = mu.reg_read(UC_X86_REG_RCX)
        emu_poll(poll_fd_ptr, num, timeout)

    # getpid
    elif syscall_id == 0x27:
        emu_getpid(mu, emu_env)

    # getuid
    elif syscall_id == 0x66:
        emu_getuid(mu, emu_env)

    # time
    elif syscall_id == 0xc9:
        dst_ptr = mu.reg_read(UC_X86_REG_RSI)
        emu_time(mu, emu_env, dst_ptr)

    # sys_getrandom
    elif syscall_id == 0x13e:
        dst_ptr = mu.reg_read(UC_X86_REG_RSI)
        count = mu.reg_read(UC_X86_REG_RDX)
        flags = mu.reg_read(UC_X86_REG_RCX)
        emu_sys_getrandom(mu, emu_env, dst_ptr, count, flags)

    else:
        print("Instruction address: %08x (emulation function) Unknown syscall: %d" % (mu.reg_read(UC_X86_REG_RIP), syscall_id))


def emu_libc_strlen(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc strlen functionality.
    """
    ctr = 0
    buf_ptr = mu.reg_read(UC_X86_REG_RDI)
    curr_byte = mu.mem_read(buf_ptr, 1)
    while curr_byte != b'\x00':
        buf_ptr += 1
        ctr += 1
        curr_byte = mu.mem_read(buf_ptr, 1)
    mu.reg_write(UC_X86_REG_RAX, ctr)


def emu_libc_malloc(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates a memory allocator by creating a 4kB aligned heap object.
    """
    size = mu.reg_read(UC_X86_REG_RDI)
    size_4kb_aligned = (int(size / 4096) + 1) * 4096

    mem_obj = EmulationHeapMemoryObject(emu_env.emu_heap_next_addr, size, size_4kb_aligned)
    mu.mem_map(mem_obj.address, mem_obj.size_aligned)
    emu_env.emu_heap_objs[mem_obj.address] = mem_obj
    emu_env.emu_heap_next_addr = mem_obj.address + mem_obj.size_aligned

    mu.reg_write(UC_X86_REG_RAX, mem_obj.address)


def emu_libc_memset(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc memset functionality.
    """
    dst_ptr = mu.reg_read(UC_X86_REG_RDI)
    fill_byte = struct.pack("B", mu.reg_read(UC_X86_REG_RSI))
    size = mu.reg_read(UC_X86_REG_RDX)
    mu.mem_write(dst_ptr, fill_byte * size)

    mu.reg_write(UC_X86_REG_RAX, dst_ptr)


def emu_libc_getpid(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc getpid functionality.
    """
    emu_getpid(mu, emu_env)


def emu_libc_open(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc open functionality.
    """
    file_ptr = mu.reg_read(UC_X86_REG_RDI)
    emu_open(mu, emu_env, file_ptr)


def emu_libc_fopen(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc fopen functionality.
    """
    file_ptr = mu.reg_read(UC_X86_REG_RDI)

    # Create file descriptor for file.
    file_name = b''
    curr_byte = mu.mem_read(file_ptr, 1)
    while curr_byte != b'\x00':
        file_name += curr_byte
        file_ptr += 1
        curr_byte = mu.mem_read(file_ptr, 1)

    new_fd = emu_env.emu_fd_next
    emu_env.emu_fd_next += 1
    emu_env.emu_fd_open[new_fd] = file_name

    # We do not care about the internals of the FILE struct because
    # it changes depending on the used libc, therefore, we just create our own.
    # struct FILE {
    #     qword fd;
    # }
    file_struct = struct.pack("Q", new_fd)

    # Misuse heap for FILE struct location.
    mem_obj = EmulationHeapMemoryObject(emu_env.emu_heap_next_addr, 4096, 4096)
    emu_env.emu_heap_objs[mem_obj.address] = mem_obj
    emu_env.emu_heap_next_addr = mem_obj.address + mem_obj.size_aligned

    mu.mem_map(mem_obj.address, mem_obj.size_aligned)
    mu.mem_write(mem_obj.address, file_struct)
    mu.reg_write(UC_X86_REG_RAX, mem_obj.address)


def emu_libc_read(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc read functionality.
    """
    fd = mu.reg_read(UC_X86_REG_RDI)
    dst_ptr = mu.reg_read(UC_X86_REG_RSI)
    size = mu.reg_read(UC_X86_REG_RDX)
    emu_read(mu, emu_env, fd, dst_ptr, size)


def emu_libc_fread(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc fread functionality.
    """
    dst_ptr = mu.reg_read(UC_X86_REG_RDI)
    size = mu.reg_read(UC_X86_REG_RSI)
    nmemb = mu.reg_read(UC_X86_REG_RDX)
    file_struct_ptr = mu.reg_read(UC_X86_REG_RCX)

    # Remember, we created our own FILE struct.
    fd = struct.unpack("Q", mu.mem_read(file_struct_ptr, 8))[0]

    # Use internal read implementation and convert return value.
    emu_read(mu, emu_env, fd, dst_ptr, nmemb * size)
    size_read = mu.reg_read(UC_X86_REG_RAX)
    number_items = int(size_read / size)
    mu.reg_write(UC_X86_REG_RAX, number_items)


def emu_libc_close(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc close functionality.
    """
    fd = mu.reg_read(UC_X86_REG_RDI)
    emu_close(mu, emu_env, fd)


def emu_libc_fclose(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc close functionality.
    """
    file_struct_ptr = mu.reg_read(UC_X86_REG_RDI)

    # Remember, we created our own FILE struct.
    fd = struct.unpack("Q", mu.mem_read(file_struct_ptr, 8))[0]

    emu_close(mu, emu_env, fd)


def emu_libc_setvbuf(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc setvbuf functionality.
    """

    # We ignore the functionality of setvbuf and just return success.
    mu.reg_write(UC_X86_REG_RAX, 0)


def emu_libc_time(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc time functionality.
    """
    dst_ptr = mu.reg_read(UC_X86_REG_RDI)
    emu_time(mu, emu_env, dst_ptr)


def emu_libc_gettimeofday(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc gettimeofday functionality.
    """
    dst_ptr = mu.reg_read(UC_X86_REG_RDI)
    # We ignore the timezone since we only want to set some rough values.
    # timezone = mu.reg_read(UC_X86_REG_RSI)
    curr_time = int(time.time())
    data = struct.pack("Q", curr_time) # TODO architecture specific
    # Write the time_t field.
    mu.mem_write(dst_ptr, data)
    # Write the suseconds_t field.
    mu.mem_write(dst_ptr+8, data) # TODO architecture specific
    mu.reg_write(UC_X86_REG_RAX, 0)


def emu_libc_fxstat(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc __fxstat functionality.
    """
    fd = mu.reg_read(UC_X86_REG_RSI)
    dst_ptr = mu.reg_read(UC_X86_REG_RDX)
    emu_fstat(mu, emu_env, fd, dst_ptr)


def emu_libc_memcpy(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates libc memcpy functionality.
    """
    dst_ptr = mu.reg_read(UC_X86_REG_RDI)
    src_ptr = mu.reg_read(UC_X86_REG_RSI)
    size = mu.reg_read(UC_X86_REG_RDX)

    data = mu.mem_read(src_ptr, size)
    mu.mem_write(dst_ptr, bytes(data))
    mu.reg_write(UC_X86_REG_RAX, dst_ptr)

def emu_core_errno_location(mu: Uc, emu_env: EmulatorEnv):
    """
    Emulates Linux core binary function __errno_location.
    """

    # Search errno memory object.
    errno_mem_obj = None
    for mem_obj in emu_env.special_mem_list:
        if mem_obj.name == "errno":
            errno_mem_obj = mem_obj
            break

    # If errno memory object does not exist, create one.
    if errno_mem_obj is None:
        errno_start_addr = emu_env.special_start_addr + (emu_env.special_ctr * emu_env.special_size)
        mu.mem_map(errno_start_addr, emu_env.special_size)
        init_mem = InitialMemoryObject(errno_start_addr, emu_env.special_size, b'\x00' * emu_env.special_size)
        errno_mem_obj = RuntimeMemoryObject(errno_start_addr,
                                      errno_start_addr + emu_env.special_size,
                                      RuntimeMemoryObjectType.Special,
                                      name="errno",
                                      init_mem_obj=init_mem)
        emu_env.runtime_memory_objs.append(errno_mem_obj)
        emu_env.special_mem_list.append(errno_mem_obj)
        emu_env.special_ctr += 1

    # Return address of errno memory object.
    mu.reg_write(UC_X86_REG_RAX, errno_mem_obj.start_addr)



