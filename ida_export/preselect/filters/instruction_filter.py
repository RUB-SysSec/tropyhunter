from .filter import FunctionFilter
from ..utils import func_mnemonics
from ..mnemonics import RANDOMNESS_X86, CRYPTO_X86

import idautils
import idaapi
import idc


class InstructionFilter(FunctionFilter):
    """
    Looks for randomness-related instructions.
    Example: rdrand on x86_64.
    """

    def __init__(self, debug=False):
        FunctionFilter.__init__(self, debug=debug)
        self.mnemonics = RANDOMNESS_X86 + CRYPTO_X86

    def decide(self, func_addr):
        for mnemonic in func_mnemonics(func_addr):
            if mnemonic in self.mnemonics:
                return True
        
        return False
