from . import ssa_export_pb2
from . import ssa_instruction
from . import ssa_operand
from typing import Set, List


class BlockSSA(object):

    ID_ENTRY_BLOCK_SSA = 0xffffffff
    ID_EXIT_BLOCK_SSA = 0xfffffffe

    def __init__(self, bb_ssa: ssa_export_pb2.BasicBlock):
        self.address = bb_ssa.address

        # Address of the last instruction in the basic block.
        self.last_address = bb_ssa.end

        # Hold a set of instructions and addresses to have a
        # efficient way to check if an instruction is inside the basic block.
        self.addresses_set = set()
        self.instructions_set = set()

        self.instructions = list()
        self.definitions = list()
        self.uses = list()
        for instr_ssa in bb_ssa.instructions:
            if instr_ssa.HasField("calling_convention"):
                instr = ssa_instruction.CallingConventionSSA(instr_ssa.calling_convention)
            elif instr_ssa.HasField("instruction"):
                instr = ssa_instruction.InstructionSSA(instr_ssa.instruction)
            elif instr_ssa.HasField("phi_node"):
                instr = ssa_instruction.PhiNodeSSA(instr_ssa.phi_node)
            else:
                raise ValueError("Unknown type of instruction.")

            self.instructions.append(instr)
            self.addresses_set.add(instr.address)
            self.instructions_set.add(instr)

            # Add operand uses and defs.
            for op in instr.uses:
                self.uses.append(op)
            for op in instr.definitions:
                self.definitions.append(op)

        self.predecessors = set()
        for pred in bb_ssa.predecessors:
            self.predecessors.add(pred)

        self.successors = set()
        for succ in bb_ssa.successors:
            self.successors.add(succ)

    def __str__(self):
        result = "Basic Block: %08x\n" % self.address
        for instr in self.instructions:
            result += "%s\n" % instr
        return result

    def has_address(self, address: int) -> bool:
        """
        Checks if the address resides in the basic block.
        :return: True or False
        """
        return address in self.addresses_set

    def has_instruction(self, instruction: ssa_instruction.BaseInstructionSSA) -> bool:
        """
        Checks if the instruction resides in the basic block.
        :return: True or False
        """
        return instruction in self.instructions_set

    def get_containing_instructions(self, address: int) -> List[ssa_instruction.BaseInstructionSSA]:
        """
        Gets all instructions that have the given address.
        :return: List of all instructions having the given address.
        """
        if not self.has_address(address):
            raise ValueError("Basic block does not have instructions containing address %08x" % address)
        result = list()
        for instr in self.instructions:
            if instr.address == address:
                result.append(instr)
        return result

    def get_inputs(self) -> Set[ssa_operand.OperandSSA]:
        """
        Generates all input operands of this basic block.
        :return: Set of OperandSSA that represent all input operands.
        """
        inputs_set = set(self.uses) - set(self.definitions)

        # Remove register entries hat only differ in the phi index.
        temp_list = list(inputs_set)
        to_remove = set()
        for i in range(len(temp_list)):
            for j in range(i+1, len(temp_list)):
                op1 = temp_list[i]
                op2 = temp_list[j]
                if type(op1) != type(op2):
                    continue
                if isinstance(op1, ssa_operand.RegisterSSA):
                    if op1.index == op2.index:
                        to_remove.add(op2)
        # Remove constant and address operands:
        for op in inputs_set:
            if isinstance(op, ssa_operand.ConstantSSA):
                to_remove.add(op)
        for op in to_remove:
            inputs_set.remove(op)

        # Check order of memory usage. If in a basic block a
        # memory operand is used and in a subsequent instruction (or the same)
        # defined, then we also have to consider them as input.
        to_add = set()
        union_set = set(self.uses) & set(self.definitions)
        for op in union_set:
            if not isinstance(op, ssa_operand.MemorySSA):
                continue
            found_def = False
            found_use = False
            for instr in self.instructions:
                for def_op in instr.definitions:
                    if def_op == op:
                        found_def = True
                        break
                for use_op in instr.uses:
                    if use_op == op:
                        found_use = True
                        break
                if found_def and found_use:
                    to_add.add(op)
                    break
                elif found_use:
                    to_add.add(op)
                    break
                elif found_def:
                    break
        for op in to_add:
            inputs_set.add(op)

        # TODO does removing call instruction from operand inputs make problems?
        # Remove all operands that belong to a call instruction.
        instr = self.instructions[-1]
        if instr.is_call:
            for op in instr.operands:
                if op in inputs_set:
                    inputs_set.remove(op)

        return inputs_set

    def get_outputs(self) -> Set[ssa_operand.OperandSSA]:
        """
        Generates all output operands of this basic block.
        :return: Set of OperandSSA that represent all output operands.
        """
        outputs_set = set(self.definitions)

        # TODO does removing call instruction from operand outputs make problems?
        # Remove all definitions that belong to a call instruction or are overwritten by it.
        instr = self.instructions[-1]
        if instr.is_call:
            for def_op in instr.definitions:
                for op in set(outputs_set):
                    if type(def_op) != type(op):
                        continue
                    if def_op.index == op.index:
                        outputs_set.remove(op)

        # Remove register entries hat only differ in the phi index.
        temp_list = list(outputs_set)
        to_remove = set()
        for i in range(len(temp_list)):
            for j in range(i+1, len(temp_list)):
                op1 = temp_list[i]
                op2 = temp_list[j]
                if type(op1) != type(op2):
                    continue
                if isinstance(op1, ssa_operand.RegisterSSA):
                    if op1.index == op2.index:
                        to_remove.add(op2)
        # Remove constant and address operands:
        for op in outputs_set:
            if isinstance(op, ssa_operand.ConstantSSA):
                to_remove.add(op)
        for op in to_remove:
            outputs_set.remove(op)

        return outputs_set