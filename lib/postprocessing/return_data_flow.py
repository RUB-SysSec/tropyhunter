from lib.ssa import ssa_function
from lib.ssa import ssa_block
from lib.ssa import ssa_instruction
from lib.emulation.core import FunctionOutputType, FunctionOutput
from lib.arch.x64 import RegistersX64
from typing import Dict, Set, Optional


def import_xrefs(file_base: str) -> Dict[int, Set[int]]:
    file_base = file_base + "_xrefs.txt"
    functions_xrefs = dict()
    with open(file_base, 'r') as fp:
        for line in fp:
            splitted_line = line.strip().split(" ")
            func_addr = int(splitted_line[0], 16)
            functions_xrefs[func_addr] = set()
            for i in range(1, len(splitted_line)):
                functions_xrefs[func_addr].add(int(splitted_line[i], 16))
    return functions_xrefs


def get_used_return_registers(func_addr: int,
                              functions_ssa: Dict[int, ssa_function.FunctionSSA],
                              functions_xrefs: Dict[int, Set[int]]) -> Optional[Set[int]]:
    """
    Returns used return registers.

    :param func_addr: function address to check.
    :param functions_ssa: all function ssa representations.
    :param functions_xrefs: all function xrefs.
    :return: Outputs a set of register indexes which were used (or empty set if none was used) or None if it could not be determined.
    """

    used_return_registers = set()

    # Just return if we do not know any xrefs.
    if func_addr not in functions_xrefs.keys() or not functions_xrefs[func_addr]:
        return None

    for xref_addr in functions_xrefs[func_addr]:

        # Get corresponding ssa form of the function.
        function_ssa = None
        for _, temp_function_ssa in functions_ssa.items():
            if temp_function_ssa.has_address(xref_addr):
                function_ssa = temp_function_ssa
                break
        if function_ssa is None:
            continue

        # Get the cconv instructions for the call (and make sure it is a call instruction).
        bb = function_ssa.get_containing_basicblock(xref_addr)  # type: ssa_block.BlockSSA
        instrs = bb.get_containing_instructions(xref_addr)
        cconv_instrs = list()
        is_call = False
        for instr in instrs:
            if type(instr) == ssa_instruction.InstructionSSA and instr.is_call:
                is_call = True
            elif type(instr) == ssa_instruction.CallingConventionSSA:
                cconv_instrs.append(instr)
        if not is_call:
            continue

        for cconv_instr in cconv_instrs:
            dest_op = cconv_instr.definitions[0]
            use_instrs = function_ssa.uses_map[dest_op]

            # Just do a superficial data-flow check of the return register.
            return_uses = False
            for use_instr in use_instrs:
                # Check if return operand goes directly into a xor that nulls it.
                if use_instr.mnemonic in ["xor", "pxor"]:
                    for use_op in use_instr.uses:
                        if use_op != dest_op:
                            return_uses = True
                else:
                    return_uses = True

            if return_uses:
                used_return_registers.add(dest_op.index)

    return used_return_registers


def check_return_register_usage(func_addr: int,
                                output_dst: FunctionOutput,
                                functions_ssa: Dict[int, ssa_function.FunctionSSA],
                                functions_xrefs: Dict[int, Set[int]]) -> bool:

    # If output destination is return register, check if it is used afterwards.
    if output_dst.output_type == FunctionOutputType.Register:
        output_reg_idx = RegistersX64.from_unicorn(output_dst.register)
        if output_reg_idx in [RegistersX64.rax, RegistersX64.xmm0]: # TODO architecture specific
            return_reg_usages = get_used_return_registers(func_addr,
                                                          functions_ssa,
                                                          functions_xrefs)
            if return_reg_usages is None:
                return True
            if not output_reg_idx in return_reg_usages:
                return False
    return True
