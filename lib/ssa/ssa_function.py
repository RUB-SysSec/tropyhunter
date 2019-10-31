from . import ssa_block
from . import ssa_operand
from collections import defaultdict
from typing import Set
import networkx as nx

class FunctionSSA(object):

    def __init__(self, address: int, calling_convention):
        self.address = address
        self.basic_blocks = dict()
        self.calling_convention = calling_convention

        # Map operand -> set(instructions)
        self.definitions_map = defaultdict(set)
        self.uses_map = defaultdict(set)

        self._cfg = nx.DiGraph()
        self.initialized = False

    def __str__(self):
        if not self.initialized:
            raise ValueError("Function object not initialized.")

        result = "Function: %08x\n" % self.address
        for bb in self.basic_blocks:
            result += "%s\n" % bb
        return result

    @property
    def cfg(self):
        if not self.initialized:
            raise ValueError("Function object not initialized.")
        return self._cfg

    def add_basic_block(self, bb: ssa_block.BlockSSA):
        self.basic_blocks[bb.address] = bb

        # Build definitions/uses map.
        for instr in bb.instructions:
            for def_op in instr.definitions:
                self.definitions_map[def_op].add(instr)

                # Add the base as uses.
                if def_op.is_memory:
                    if type(def_op) == ssa_operand.MemoryX64SSA:
                        self.uses_map[def_op.base].add(instr)
                    else:
                        raise NotImplementedError("Architecture not implemented.")

            for use_op in instr.uses:
                self.uses_map[use_op].add(instr)

                # Add the base and index also as uses.
                if use_op.is_memory:
                    if type(use_op) == ssa_operand.MemoryX64SSA:
                        self.uses_map[use_op.base].add(instr)
                        if use_op.has_index:
                            self.uses_map[use_op.index].add(instr)
                    else:
                        raise NotImplementedError("Architecture not implemented.")

    def finalize(self):

        # Add all basic blocks as node to cfg.
        for _, bb in self.basic_blocks.items():
            self._cfg.add_node(bb)

        # Add all edges of the basic blocks to the cfg.
        for addr, src_bb in self.basic_blocks.items():
            for succ in src_bb.successors:
                dst_bb = self.basic_blocks[succ]
                self._cfg.add_edge(src_bb, dst_bb)

        self.initialized = True

    def has_address(self, address):
        if not self.initialized:
            raise ValueError("Function object not initialized.")
        for _, bb in self.basic_blocks.items():
            if bb.has_address(address):
                return True
        return False

    def get_containing_basicblock(self, address):
        if not self.initialized:
            raise ValueError("Function object not initialized.")
        for _, bb in self.basic_blocks.items():
            if bb.has_address(address):
                return bb
        raise ValueError("Function does not have basic block containing address %08x" % address)

    def get_reg_inputs(self) -> Set[ssa_operand.OperandSSA]:
        """
        Returns all input register operands belonging to this function.
        :return: Set of OperandSSA that represent all input memory input operands.
        """
        if not self.initialized:
            raise ValueError("Function object not initialized.")

        begin_addr = ssa_block.BlockSSA.ID_ENTRY_BLOCK_SSA
        end_addr = ssa_block.BlockSSA.ID_EXIT_BLOCK_SSA

        fct_input_ops_set = set()

        # Iterate through CFG in a BFS manner.
        start_bb = self.basic_blocks[begin_addr]
        work_list = list()
        work_list.extend(start_bb.successors)
        already_processed = set()
        already_processed.add(end_addr)
        while work_list:
            curr_bb_addr = work_list[0]
            work_list.pop(0)
            if curr_bb_addr in already_processed:
                continue
            already_processed.add(curr_bb_addr)
            curr_bb = self.basic_blocks[curr_bb_addr]

            for succ_bb_addr in curr_bb.successors:
                if succ_bb_addr in already_processed:
                    continue
                work_list.append(succ_bb_addr)

            # Extract register inputs of the function.
            input_ops_set = curr_bb.get_inputs()
            for op_ssa in input_ops_set:
                if isinstance(op_ssa, ssa_operand.RegisterSSA):
                    if op_ssa.phi_index == 0 and self.calling_convention.check(op_ssa.index):
                        fct_input_ops_set.add(op_ssa)

        return fct_input_ops_set

    def get_mem_inputs(self) -> Set[ssa_operand.OperandSSA]:
        """
        Returns all input memory operands belonging to this function.
        :return: Set of OperandSSA that represent all input memory input operands.
        """
        if not self.initialized:
            raise ValueError("Function object not initialized.")

        begin_addr = ssa_block.BlockSSA.ID_ENTRY_BLOCK_SSA
        end_addr = ssa_block.BlockSSA.ID_EXIT_BLOCK_SSA

        fct_input_ops_set = set()

        # Iterate through CFG in a BFS manner.
        start_bb = self.basic_blocks[begin_addr]
        work_list = list()
        work_list.extend(start_bb.successors)
        already_processed = set()
        already_processed.add(end_addr)
        while work_list:
            curr_bb_addr = work_list[0]
            work_list.pop(0)
            if curr_bb_addr in already_processed:
                continue
            already_processed.add(curr_bb_addr)
            curr_bb = self.basic_blocks[curr_bb_addr]

            for succ_bb_addr in curr_bb.successors:
                if succ_bb_addr in already_processed:
                    continue
                work_list.append(succ_bb_addr)

            # Extract memory inputs of the function.
            input_ops_set = curr_bb.get_inputs()
            for op_ssa in input_ops_set:
                if isinstance(op_ssa, ssa_operand.MemorySSA):
                    fct_input_ops_set.add(op_ssa)

        return fct_input_ops_set
