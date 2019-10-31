from .emulation.core import FunctionEnds, FunctionEnd, EndInstructionType
from .ssa.ssa_function import FunctionSSA
from .ssa.ssa_block import BlockSSA
from .ssa.ssa_operand import ConstantSSA
from typing import Dict


def get_function_ends(functions_ssa: Dict[int, FunctionSSA],
                      function_ssa: FunctionSSA,
                      call_depth: int = 1) -> FunctionEnds:
    """
    Extracts function ends of the given function.

    :param functions_ssa: All functions in SSA form.
    :param function_ssa: The target function in SSA form.
    :param call_depth: How deep we follow tail jumps.
    :return: FunctionEnds of the given function.
    """

    # Get the last address of the function end address.
    # TODO: for now, just consider all not 'ret' function endings as not valid.
    function_ends = FunctionEnds()
    bb_end_ssa = function_ssa.basic_blocks[BlockSSA.ID_EXIT_BLOCK_SSA]
    for bb_addr in bb_end_ssa.predecessors:
        bb = function_ssa.basic_blocks[bb_addr]
        last_instr = bb.instructions[-1]
        if last_instr.is_ret:
            fct_end = FunctionEnd(last_instr.address,
                                  EndInstructionType.Ret,
                                  True)
        elif last_instr.is_call:
            fct_end = FunctionEnd(last_instr.address,
                                  EndInstructionType.Call,
                                  False)
        elif last_instr.is_unconditional_jmp:

            # If the tail jump instruction is resolvable, consider the ends of this function as function end
            # instead of the tail jump (and also if the call depth is not exceeded).
            target = last_instr.uses[0]
            if isinstance(target, ConstantSSA) and call_depth > 0:
                addr = target.value
                if addr in functions_ssa.keys():
                    new_function_ssa = functions_ssa[addr]
                    sub_fct_ends = get_function_ends(functions_ssa, new_function_ssa, call_depth-1)
                    function_ends.extend(sub_fct_ends)
                    continue

            fct_end = FunctionEnd(last_instr.address,
                                  EndInstructionType.Jmp,
                                  False)
        else:
            raise ValueError("Expected last instruction to be a return, call or jmp instruction, but found '%s'."
                             % str(last_instr))
        function_ends.add(fct_end)

    return function_ends
