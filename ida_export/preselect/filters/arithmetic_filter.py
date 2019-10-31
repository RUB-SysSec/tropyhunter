from .filter import FunctionFilter
from ..utils import basic_blocks, instructions, func_instructions
from ..mnemonics import ARITHMETIC_X86, BITWISE_X86

import idautils
import idaapi
import idc


def can_be_ignored(instr_addr):
    """
    Checks whether or not an instruction can be ignored.
    An instruction can be ignored if it does not actually an arithmetic or bitwise computation,
    although it has a mnemonic that falls into that category.
    Example: xor eax, eax
    """
    # ignore instructions that are "abused" for non-arithmetic purposes
    if idc.GetMnem(instr_addr) in ['xor', 'sub']:
        same_op_type = idc.get_operand_type(instr_addr, 0) == idc.get_operand_type(instr_addr, 1)
        same_op_value = idc.get_operand_value(instr_addr, 0) == idc.get_operand_value(instr_addr, 1)
        if same_op_type and same_op_value:
            return True
        
        return False


class ArithmeticFilter(FunctionFilter):
    """
    Checks for heavy usage of arithmetic/bitwise instructions
    which might be an indicator for cryptographic operations.
    """
    def __init__(self, debug=False):
        FunctionFilter.__init__(self, debug=debug)
        self.mnemonics = set(ARITHMETIC_X86 + BITWISE_X86)

        # category 1 params
        self.cat1_ratio_threshold = 0.30
        self.cat1_min_instrs = 25
        self.cat1_bb_min_arith = 10
        self.cat1_min_bbs = 1

        # category 2 params
        self.cat2_ratio_threshold = 0.40
        self.cat2_min_instrs = 10
        self.cat2_bb_min_arith = 7
        self.cat2_min_bbs = 3

    def decide(self, func_addr):
        cat1_counter = 0
        cat2_counter = 0

        for bb_start, bb_end in basic_blocks(func_addr):
            bb_info = self.ratio(instructions(bb_start, bb_end))
            bb_ratio, bb_arith_count, bb_instr_count = bb_info

            self.log('0x{:x}-0x{:x}: intrs={} ariths={} ratio={}'.format(bb_start, bb_end, bb_instr_count, bb_arith_count, bb_ratio))

            if self.fulfills_cat1(bb_info):
                cat1_counter += 1
            if self.fulfills_cat2(bb_info):
                cat2_counter += 1

        return cat1_counter >= self.cat1_min_bbs or cat2_counter >= self.cat2_min_bbs

    def ratio(self, instructions):
        """
        Computes the ratio of arithemtic instructions.
        Formula: (arithmetic + bitwise) / total

        Returns ratio, arithmetic_count, total_count
        """
        count = 0
        total_count = 0
        for instr_addr in instructions:
            total_count += 1
            if can_be_ignored(instr_addr):
                continue

            mnemonic = idc.GetMnem(instr_addr)
            if mnemonic in self.mnemonics:
                count += 1

        ratio = 0 if total_count == 0 else float(count) / float(total_count)
        return ratio, count, total_count

    def fulfills_cat1(self, bb_info):
        """
        Checks whether or not a basic block falls into category 1.
        A category 1 BB has a high instruction count and a ratio above a certain threshold.
        """
        bb_ratio, bb_arith_count, _ = bb_info

        good_arith_count = bb_arith_count >= self.cat1_bb_min_arith
        good_ratio = bb_ratio >= self.cat1_ratio_threshold

        return good_arith_count and good_ratio

    def fulfills_cat2(self, bb_info):
        """
        Checks whether or not a basic block falls into category 2.
        A category 2 BB has a medium instruction count (below the cat1 count)
        and a ratio above a certain threshold.
        """
        bb_ratio, _, bb_instr_count = bb_info

        good_count = self.cat2_min_instrs <= bb_instr_count < self.cat1_min_instrs
        good_ratio = bb_ratio > self.cat2_ratio_threshold

        return good_count and good_ratio
