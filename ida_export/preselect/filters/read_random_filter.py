from .filter import FunctionFilter
from ..utils import func_instructions
from ..mnemonics import CALL_X86, JUMP_X86

import idc
import idaapi
import idautils

class ReadRandomFilter(FunctionFilter):
    """
    Checks if a function gathers randomness via read("/dev/urandom").
    """
    def __init__(self, debug=False):
        FunctionFilter.__init__(self, debug=debug)
        self.call_mnemonics = CALL_X86
        self.jump_mnemonics = JUMP_X86
        self.read_functions = ['.read', '.fread']
        self.random_strings = ['/dev/urandom', '/dev/random']

    def decide(self, func_addr):
        references_dev_random = False
        calls_read = False

        for instr_addr in func_instructions(func_addr):
            references_dev_random = references_dev_random or self.has_random_string_reference(instr_addr)
            if references_dev_random:
                self.log('0x{:x} references /dev/(u)random'.format(func_addr))
            
            calls_read = calls_read or self.does_call_read(instr_addr)
            if calls_read:
                self.log('0x{:x} calls read'.format(func_addr))

            if references_dev_random and calls_read:
                return True

        return False

    def does_call_read(self, instr_addr):
        """
        Checks if the given instruction is a call to a read() function.
        """
        if self.is_function_call(instr_addr):
            for code_ref in idautils.CodeRefsFrom(instr_addr, True):
                name = idc.GetFunctionName(code_ref)
                if name in self.read_functions:
                    return True

        return False

    def is_function_call(self, instr_addr):
        """
        Checks if the given instruction is a call.
        """
        menmonic = idc.GetMnem(instr_addr)
        if menmonic in self.call_mnemonics:
            return True
        elif menmonic in self.jump_mnemonics:
            # TODO: check if target is a function
            #op_type = idc.get_operand_type(instr_addr, 0)
            #op_value = idc.get_operand_value(instr_addr, 0)
            return True
        else:
            return False

    def has_random_string_reference(self, instr_addr):
        """
        Check if the given instruction references a string that looks
        like a randomness-file path.
        Example: /dev/urandom
        """
        for data_ref in idautils.DataRefsFrom(instr_addr):
            s = idc.GetString(data_ref)

            if s is None:
                continue

            if s in self.random_strings:
                return True

        return False
