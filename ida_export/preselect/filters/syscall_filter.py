from .filter import FunctionFilter
from ..utils import func_instructions, instructions
from ..mnemonics import CALL_X86

from lib.shovel.instruction import Instruction, Operand
from lib.shovel.cfg import Function
from lib.back import track_data_flow_back

import idautils
import idaapi
import idc


# syscalls that are related to gathering randomness.
RANDOMNESS_SYSCALLS_LINUX = [
    318, # getrandom
]

class SyscallFilter(FunctionFilter):
    """
    Looks for interesting syscalls or libc _syscall()s.
    """
    def __init__(self, debug=False):
        FunctionFilter.__init__(self, debug=debug)
        self.syscalls = RANDOMNESS_SYSCALLS_LINUX
        self.call_mnemonics = CALL_X86
        self.syscall_functions = ['.syscall', 'syscall']

    def decide(self, func_addr):
        for instr_addr in func_instructions(func_addr):
            mnemonic = idc.GetMnem(instr_addr)
            if self.is_x64_syscall(mnemonic) or self.is_x86_syscall(mnemonic, instr_addr):
                self.log('0x{:x} has a syscall instruction at 0x{:x}'.format(func_addr, instr_addr))
                num = self.find_value(func_addr, instr_addr, 'ax')
            elif self.is_libc_syscall(mnemonic, instr_addr):
                self.log('0x{:x} has a libc syscall call at 0x{:x}'.format(func_addr, instr_addr))
                num = self.find_value(func_addr, instr_addr, 'di')
            else:
                continue

            # if the syscall number could not be determined or it is
            # one of those we are looking for, return True
            if num is None:
                self.log('0x{:x} has a syscall at 0x{:x} but we could not find the number so we include it'.format(func_addr, instr_addr))
                return True
            elif num in self.syscalls:
                self.log('0x{:x} has a syscall at 0x{:x} that we are looking for ({})'.format(func_addr, instr_addr, num))
                return True
            else:
                self.log('0x{:x} has a syscall at 0x{:x} but it is NOT what are looking for ({})'.format(func_addr, instr_addr, num))

        return False

    def is_x86_syscall(self, mnemonic, instr_addr):
        """
        Is it a syscall instruction (int 0x80)?
        """
        return (mnemonic == 'int') and (idc.get_operand_value(instr_addr, 0) == 0x80)

    def is_x64_syscall(self, mnemonic):
        """
        Is it a syscall instruction (syscall)?
        """
        return mnemonic == 'syscall'

    def is_libc_syscall(self, mnemonic, instr_addr):
        """
        Is it a libc _syscall()?
        """
        if mnemonic in self.call_mnemonics:
            target = idc.get_operand_value(instr_addr, 0)
            target_name = idc.GetFunctionName(target)
            return target_name in self.syscall_functions

    def find_value(self, func_addr, instr_addr, register):
        """
        Attempts to resolve the value of the given register at the given address.
        If the value cannot be resolved, None is returned.
        """
        reg_num = idaapi.ph_get_regnames().index(register)

        # go back from the current instruction to the start of the function
        for instr_addr in list(instructions(func_addr, instr_addr))[::-1]:
            # look for instrucations that move a value into the desired register
            mnemonic = idc.GetMnem(instr_addr)
            if mnemonic == 'mov':

                op1_type = idc.get_operand_type(instr_addr, 0)
                op1_value = idc.get_operand_value(instr_addr, 0)
                
                if op1_type == idc.o_reg and op1_value == reg_num:
                    op2_type = idc.get_operand_type(instr_addr, 1)
                    op2_value = idc.get_operand_value(instr_addr, 1)

                    # if this instruction sets the register to an immediate value
                    if op2_type == idc.o_imm:
                        # return that value
                        return op2_value
                    else:
                        # it is not an immediate value, so we say we cannot
                        # resolve the value
                        return None

        # we did not find an allocation of the register,
        # so we return None to indicate that
        return None
