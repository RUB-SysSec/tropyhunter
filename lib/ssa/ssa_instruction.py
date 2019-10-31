from . import ssa_export_pb2
from . import ssa_operand


class BaseInstructionSSA(object):

    def __init__(self, address: int, mnemonic: str):
        self.address = address
        self.mnemonic = mnemonic
        self.operands = list()
        self.definitions = list()
        self.uses = list()

    def add_operand(self, op_ssa: ssa_export_pb2.Operand):

        if op_ssa.HasField("register"):
            if op_ssa.register.HasField("register_x64"):
                op = ssa_operand.RegisterX64SSA.from_pb2(op_ssa.register.register_x64)
            else:
                raise ValueError("Unknown register type.")
        elif op_ssa.HasField("constant"):
            if op_ssa.constant.HasField("constant_x64"):
                op = ssa_operand.ConstantX64SSA.from_pb2(op_ssa.constant.constant_x64)
            elif op_ssa.constant.HasField("address_x64"):
                op = ssa_operand.AddressX64SSA.from_pb2(op_ssa.constant.address_x64)
            else:
                raise ValueError("Unknown constant type.")
        elif op_ssa.HasField("memory"):
            if op_ssa.memory.HasField("memory_x64"):
                op = ssa_operand.MemoryX64SSA.from_pb2(op_ssa.memory.memory_x64)
            else:
                raise ValueError("Unknown memory type.")
        else:
            raise ValueError("Unknown operand type.")

        self.operands.append(op)

        # Add use and defs.
        if op.is_read():
            self.uses.append(op)
        if op.is_written():
            self.definitions.append(op)

    def __str__(self):
        result = "%08x %s" % (self.address, self.mnemonic)
        for op in self.operands:
            result += " %s" % op
        return result


class InstructionSSA(BaseInstructionSSA):

    def __init__(self, instr_ssa: ssa_export_pb2.BaseInstruction):
        super().__init__(instr_ssa.address, instr_ssa.mnemonic)

        self.is_call = False
        self.is_unconditional_jmp = False
        self.is_ret = False

        # TODO at the moment x86 specific
        if instr_ssa.mnemonic == "call":
            self.is_call = True
        elif instr_ssa.mnemonic == "jmp":
            self.is_unconditional_jmp = True
        elif instr_ssa.mnemonic == "ret" or instr_ssa.mnemonic == "retn":
            self.is_ret = True

        for op_ssa in instr_ssa.operands:
            super().add_operand(op_ssa)


class PhiNodeSSA(BaseInstructionSSA):

    def __init__(self, instr_ssa: ssa_export_pb2.PhiNode):
        super().__init__(instr_ssa.address, instr_ssa.mnemonic)

        for op_ssa in instr_ssa.operands:
            super().add_operand(op_ssa)


class CallingConventionSSA(BaseInstructionSSA):

    def __init__(self, instr_ssa: ssa_export_pb2.CallingConvention):
        super().__init__(instr_ssa.address, instr_ssa.mnemonic)

        for op_ssa in instr_ssa.operands:
            super().add_operand(op_ssa)