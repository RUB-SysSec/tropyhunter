from amoco.cas.mapper import mapper
from amoco.code import block
from amoco.cas.expressions import cst as amoco_cst
from amoco.cas.expressions import ptr as amoco_ptr
from amoco.cas.expressions import mem as amoco_mem
from amoco.cas.expressions import slc as amoco_slc
from amoco.cas.expressions import op as amoco_op
from amoco.cas.expressions import reg as amoco_reg
from amoco.cas.expressions import exp as amoco_exp
from amoco.cas.expressions import comp as amoco_comp
from amoco.cas.expressions import OP_ADD, OP_MUL
from typing import Any, List, Tuple, Dict, Optional
from .ssa import ssa_operand, ssa_block
from .arch import RegistersX64
import random

def sym_exec_path(bb: block,
                  input_values: Any,
                  output_addrs_amoco_ops: Any) -> Any:
    """
    Executes a given basic block symbolically and returns the created mapper.
    :param bb: amoco basic block.
    :param input_values: TODO
    :return: a map that contains the results of the symbolic execution,
    """

    # Ignore aliasing in order to simplify final mapper.
    mapper.assume_no_aliasing = True

    base_map = mapper()  # type: mapper

    output_addrs_eval_ops = list()

    # Set beginning input values if exist.
    for addr, op_amoco, value_amoco in input_values:
        if addr == 0x0:
            base_map[op_amoco] = value_amoco

    # Execute basic block.
    for instr in bb.instr:

        # Set input values for corresponding instruction if exist.
        for addr, op_amoco, value_amoco in input_values:
            if addr == instr.address:

                # Evaluate current left hand expression before inserting the given value.
                op_amoco_eval = op_amoco.eval(base_map)
                base_map[op_amoco_eval] = value_amoco
                break

        base_map.update(instr)

        # If the defining instruction of the memory/pointer output is executed,
        # extract the evaluated form of this expression to extract the final result
        # at the end.
        for addr, _, op_amoco in output_addrs_amoco_ops:
            if instr.address == addr:
                output_addrs_eval_ops.append((addr, op_amoco, op_amoco.eval(base_map)))
                break

    return base_map, output_addrs_eval_ops


def convert_to_amoco_expr_lh(op: ssa_operand.OperandSSA) -> amoco_exp:

    # Handle registers.
    if isinstance(op, ssa_operand.RegisterSSA):
        if type(op) == ssa_operand.RegisterX64SSA:
            return RegistersX64.to_amoco(op.index)

        else:
            raise NotImplementedError("Unknown register type.")

    # Handle constants.
    elif isinstance(op, ssa_operand.ConstantSSA):
        if type(op) == ssa_operand.ConstantX64SSA:
            return amoco_ptr(amoco_cst(op.value, 64))

        else:
            raise NotImplementedError("Unknown constant type.")

    # Handle memory.
    elif isinstance(op, ssa_operand.MemorySSA):
        if type(op) == ssa_operand.MemoryX64SSA:
            base = RegistersX64.to_amoco(op.base.index)

            if op.has_index and op.has_index_factor:
                index = RegistersX64.to_amoco(op.index.index)
                index_factor = amoco_cst(op.index_factor.value, 64)
                temp_op = amoco_op(OP_MUL, index, index_factor)
                temp_op = amoco_op(OP_ADD, base, temp_op)
                temp_ptr = amoco_ptr(temp_op, disp=op.offset.value)
                return temp_ptr

            elif op.has_index:
                index = RegistersX64.to_amoco(op.index.index)
                temp_op = amoco_op(OP_ADD, base, index)
                temp_ptr = amoco_ptr(temp_op, disp=op.offset.value)
                return temp_ptr

            elif op.has_index_factor:
                index_factor = amoco_cst(op.index_factor.value, 64)
                temp_op = amoco_op(OP_MUL, base, index_factor)
                temp_ptr = amoco_ptr(temp_op, disp=op.offset.value)
                return temp_ptr

            else:
                temp_ptr = amoco_ptr(base, disp=op.offset.value)
                return temp_ptr

        else:
            raise NotImplementedError("Unknown constant type.")

    else:
        raise ValueError("Unknown operand type.")


def get_random_input():
    return random.randint(-1000, 1000)


def generate_input_output_pair(bb: block,
                               input_addrs_ops: List[Tuple[int, ssa_operand.OperandSSA]],
                               output_addrs_ops: List[Tuple[int, ssa_operand.OperandSSA]],
                               input_ops_values: Optional[Dict[ssa_operand.OperandSSA, int]] = None,
                               debug_print: bool = False):

    # Convert address/operand tuple into address/amoco_operand tuple.
    input_addrs_amoco_ops = list()
    for addr, op_ssa in input_addrs_ops:
        input_addrs_amoco_ops.append((addr, op_ssa, convert_to_amoco_expr_lh(op_ssa)))

    # Convert output ssa operands to amoco operands.
    output_addrs_amoco_ops = list()
    for addr, op_ssa in output_addrs_ops:
        output_addrs_amoco_ops.append((addr, op_ssa, convert_to_amoco_expr_lh(op_ssa)))

    # TODO generate input values (pointer values for registers that usually hold pointer?)
    # Prepare input list for symbolic execution.
    input_values = list()
    if input_ops_values is None:
        input_ops_values = dict()
        for addr, op_ssa, op_amoco in input_addrs_amoco_ops:
            temp_value = get_random_input()
            input_ops_values[op_ssa] = temp_value
            input_values.append((addr, op_amoco, amoco_cst(temp_value, 64)))
    else:
        for addr, op_ssa, op_amoco in input_addrs_amoco_ops:
            input_values.append((addr, op_amoco, amoco_cst(input_ops_values[op_ssa], 64)))

    base_map, output_addrs_eval_ops = sym_exec_path(bb, input_values, output_addrs_amoco_ops)

    if debug_print:
        print("Mapper:")
        print(base_map)

    output_ops_results = list()
    for addr, op_ssa, op_amoco in output_addrs_amoco_ops:
        if type(op_amoco) == amoco_reg:
            result = base_map[op_amoco]
            result = result.eval(base_map)
            output_ops_results.append((addr, op_ssa, op_amoco, op_amoco, result))
        elif type(op_amoco) == amoco_ptr:
            op_amoco_eval = None
            for addr2, op_amoco2, op_amoco2_eval in output_addrs_eval_ops:
                if addr == addr2 and op_amoco == op_amoco2:
                    op_amoco_eval = op_amoco2_eval
                    break

            # Use direct access to memory map in order to bypass size check.
            result = base_map.R(op_amoco_eval)
            result = result.eval(base_map)
            output_ops_results.append((addr, op_ssa, op_amoco, op_amoco_eval, result))
        else:
            raise NotImplementedError("Unknown type %s not implemented for output extraction." % type(op_amoco))

    if debug_print:
        print("\nInput values:")
        for op_ssa, value in input_ops_values.items():
            first = "%s" % op_ssa
            first = first.ljust(50)
            print(first + "<- " + str(value))

        print("\nOutput values:")
        for addr, op_ssa, op_amoco, op_amoco_eval, result in output_ops_results:
            first = "%08x (%s)" % (addr, op_ssa)
            first = first.ljust(50)
            second = "%s (-> %s)" % (op_amoco, op_amoco_eval)
            second = second.ljust(50)
            third = "<- %s" % result
            print(first + second + third)

    return {"input": input_ops_values, "output": output_ops_results}


def generate_bb_signature(amoco_obj, bb: ssa_block.BlockSSA, debug_print=False) -> Dict[List, List]:

    input_ops = bb.get_inputs()
    output_ops = bb.get_outputs()

    if debug_print:
        print("Generating signature for basic block at address: %08x" % bb.address)

        print(bb)
        print("Input operands:")
        for op in input_ops:
            print(op)
        print("")

        print("Output operands:")
        for op in output_ops:
            print(op)
        print("")

    # Get the instruction addresses of the first usage
    # of the memory operand (other operands get address 0x0).
    input_addrs_ops = list()
    for op in input_ops:
        if not isinstance(op, ssa_operand.MemorySSA):
            if type(op) == ssa_operand.RegisterX64SSA:
                input_addrs_ops.append((0x0, op))
            else:
                raise ValueError("Unknown operand type.")
        else:
            for instr in bb.instructions:
                if op in instr.uses:
                    input_addrs_ops.append((instr.address, op))
                    break

    # Get the instruction addresses of the definition
    # of the memory operand (other operands get address 0x0).
    output_addrs_ops = list()
    for op in output_ops:
        if not isinstance(op, ssa_operand.MemorySSA):
            if type(op) == ssa_operand.RegisterX64SSA:
                output_addrs_ops.append((0x0, op))
            else:
                raise ValueError("Unknown operand type.")
        else:
            for instr in bb.instructions:
                if op in instr.definitions:
                    output_addrs_ops.append((instr.address, op))
                    break

    # Convert basic block to amoco basic block.
    amoco_bb = amoco_obj.getblock(bb.address)
    amoco_bb_end = amoco_bb.address + amoco_bb.length
    if bb.last_address < amoco_bb_end:
        amoco_bb.cut(bb.last_address)

    io_pair = generate_input_output_pair(amoco_bb, input_addrs_ops, output_addrs_ops, debug_print=debug_print)

    # Extract concrete input value.
    input_simple_list = list()
    for op_ssa, value in io_pair["input"].items():
        input_simple_list.append(value)

    # Extract concrete output value.
    output_simple_list = list()
    output_complex_list = list()
    for addr, op_ssa, op_amoco, op_amoco_eval, result in io_pair["output"]:
        is_handled = True
        if type(result) == amoco_cst:
            output_simple_list.append(result.value)

        # In cases like this:
        # { | [0:32]->(0x130e983eb)[0:32] | [32:64]->0xffffffff | }
        # we have an address stored and want extract it.
        elif type(result) == amoco_comp and len(result.parts) == 2:
            for _, part in result.parts.items():
                if type(part) == amoco_cst:
                    # Ignore sign and zero extension.
                    if part.value == 0 or part.value == 0xffffffff:
                        continue
                    # We do not know how to handle other constants here.
                    else:
                        is_handled = False
                        break
                elif type(part) == amoco_slc:
                    if type(part.x) == amoco_ptr and type(part.x.base) == amoco_cst:
                        output_complex_list.append(part.x)

                # We do not know how to handle other types here.
                else:
                    is_handled = False
                    break


        else:
            is_handled = False

        if not is_handled:
            raise ValueError("Output '%s' is not concrete with type %s" % (result, type(result)))

    simple_io_pair = dict()
    simple_io_pair["input"] = input_simple_list
    simple_io_pair["output"] = output_simple_list
    simple_io_pair["output_complex"] = output_complex_list

    return simple_io_pair