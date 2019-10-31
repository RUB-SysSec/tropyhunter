from .post_processor import PostProcessor
from ..filters import ArithmeticFilter, InstructionFilter, ReadRandomFilter, SyscallFilter
from ..utils import func_instructions, count_mnemonics
from ..mnemonics import CALL_X86, JUMP_X86, JUMP_UNCONDITIONAL_X86

import idc
import idaapi
import idautils


class CallGraphPostProcessor(PostProcessor):
    """
    Looks for candidates found by the ArithmeticFilter and adds all functions that
    call those as well.
    """

    def __init__(self, debug=False):
        PostProcessor.__init__(self, debug=debug)

        # ignore all functions except when found by one of these
        self.filter_names = [
            ArithmeticFilter.__name__,
            InstructionFilter.__name__,
            ReadRandomFilter.__name__,
            SyscallFilter.__name__,
        ]
        self.call_instrs = CALL_X86 + JUMP_X86
        self.tail_jmp_instrs = JUMP_UNCONDITIONAL_X86
        self.call_depth = 2

    def process(self, func_addr, filter_name):
        # make sure it is a filter we want
        if filter_name not in self.filter_names:
            return []

        # iterate over code refs
        additional_funcs = set()
        for code_ref in self.get_real_code_refs_to(func_addr, depth=self.call_depth):
            mnemonic = idc.GetMnem(code_ref)
            
            # make sure it is a call
            if mnemonic not in self.call_instrs:
                continue

            # get the function start and add it
            ref_func_addr = self.get_func_addr(code_ref)
            if ref_func_addr is not None:
                additional_funcs.add(ref_func_addr)
        
        return list(additional_funcs)


    def get_real_code_refs_to(self, addr, depth=1, results=None):
        """
        Looks for code references to the given address.
        When a reference comes from the PLT, the code references to that PLT entry are used instead.
        This function also looks for data references from the GOT, which are then resolved like code
        references from the PLT.
        """
        if results is None:
            results = set()

        self.log('results_len={}'.format(len(results)))

        # abort the recursion
        func_addr = self.get_func_addr(addr)
        if (depth <= 0) or (addr in results) or (func_addr in results):
            return results

        is_wrapper_func = self.is_wrapper_func(func_addr)

        # check all code refs to the function
        for code_ref_to_func in idautils.CodeRefsTo(addr, True):
            if self.is_in_plt(code_ref_to_func):
                self.log('PLT ref to func: 0x{:x}'.format(code_ref_to_func))
                # PLT refs do not count depth-wise
                self.get_real_code_refs_to(self.get_func_addr(code_ref_to_func), depth=depth, results=results)
            else:
                self.log('code ref to func: 0x{:x}'.format(code_ref_to_func))

                # recursivley get references to the reference
                ref_func = self.get_func_addr(code_ref_to_func)
                if ref_func is not None and ref_func != addr and code_ref_to_func not in results and ref_func not in results:
                    results.add(code_ref_to_func)

                    if self.is_tail_jump(code_ref_to_func):
                        # tail jumps do not count depth-wise
                        self.log("it's a tail jump")
                        next_depth = depth
                    elif is_wrapper_func:
                        # wrapper functions do not count depth-wise
                        self.log("it's a wrapper function")
                        next_depth = depth
                    else:
                        self.log("it's a normal call/jump")
                        next_depth = depth - 1
                    
                    self.get_real_code_refs_to(ref_func, depth=next_depth, results=results)
        
        for data_ref_to_func in idautils.DataRefsTo(addr):
            # is this a GOT entry?
            if self.is_in_got(data_ref_to_func):
                self.log('GOT ref to func: 0x{:x}'.format(data_ref_to_func))
                # check all references to it, should come from PLT
                for data_ref_to_got in idautils.DataRefsTo(data_ref_to_func):
                    # is it actually a reference from PLT?
                    if self.is_in_plt(data_ref_to_got):
                        self.log('PLT ref to GOT: 0x{:x}'.format(data_ref_to_got))

                        # # PLT refs do not count depth-wise
                        self.get_real_code_refs_to(self.get_func_addr(data_ref_to_got), depth=depth, results=results)
        
        return results

    def get_func_addr(self, addr):
        func = idaapi.get_func(addr)
        if func is None:
            return None

        return func.startEA

    def is_in_plt(self, addr):
        """
        Checks whether or not an address is in the PLT section.
        """
        return idc.SegName(addr) == '.plt'

    def is_in_got(self, addr):
        """
        Checks whether or not an address is in the GOT section.
        """
        return idc.SegName(addr) == '.got.plt'

    def is_tail_jump(self, addr):
        # TODO: this is naive, maybe use a better check
        return idc.GetMnem(addr) in self.tail_jmp_instrs

    def is_wrapper_func(self, func_addr):
        instructions = list(func_instructions(func_addr))
        last_instruction = instructions[-1]

        low_instr_count = len(instructions) <= 10
        only_one_call = count_mnemonics(func_addr, last_instruction, CALL_X86) == 1

        return low_instr_count and only_one_call
