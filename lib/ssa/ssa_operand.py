from . import ssa_export_pb2
from .. import RegistersX64


class OperandAccessType(object):
    Unknown = 0
    Read = 1
    Write = 2
    ReadWrite = 3


class OperandSSA(object):

    def __init__(self, access_type: OperandAccessType):
        self.access_type = access_type
        self.is_constant = False
        self.is_memory = False
        self.is_register = False

    def is_written(self) -> bool:
        return (self.access_type == OperandAccessType.Write
                or self.access_type == OperandAccessType.ReadWrite)

    def is_read(self) -> bool:
        return (self.access_type == OperandAccessType.Read
                or self.access_type == OperandAccessType.ReadWrite)

    def contains(self, other) -> bool:
        raise NotImplementedError("Function not implemented.")

    def contains_coarse(self, other) -> bool:
        raise NotImplementedError("Function not implemented.")


class RegisterSSA(OperandSSA):

    def __ne__(self, o: object) -> bool:
        return not self.__eq__(o)

    def __eq__(self, o: object) -> bool:
        if type(self) != type(o):
            return False
        if (self.index == o.index
            and self.phi_index == o.phi_index):
            return True
        return False

    def __hash__(self) -> int:
        return hash((self.index, self.phi_index))

    def __init__(self, index: int, phi_index: int, access_type: OperandAccessType):

        super().__init__(access_type)

        self.index = index
        if phi_index == -1:
            self.phi_index = None
        else:
            self.phi_index = phi_index

        self.is_register = True


class RegisterX64SSA(RegisterSSA):

    def __ne__(self, o: object) -> bool:
        return super().__ne__(o)

    def __eq__(self, o: object) -> bool:
        return super().__eq__(o)

    def __hash__(self) -> int:
        return super().__hash__()

    def __init__(self, index: int, phi_index: int, access_type: OperandAccessType):
        super().__init__(index, phi_index, access_type)

    @classmethod
    def from_pb2(cls, op_ssa: ssa_export_pb2.RegisterX64):
        if op_ssa.access_type == ssa_export_pb2.UNKNOWN:
            access_type = OperandAccessType.Unknown
        elif op_ssa.access_type == ssa_export_pb2.READ:
            access_type = OperandAccessType.Read
        elif op_ssa.access_type == ssa_export_pb2.WRITE:
            access_type = OperandAccessType.Write
        elif op_ssa.access_type == ssa_export_pb2.READWRITE:
            access_type = OperandAccessType.ReadWrite
        else:
            raise ValueError("Unkown access type.")
        return cls(op_ssa.index, op_ssa.phi_index, access_type)

    def __str__(self):
        if self.phi_index is not None:
            return "%s_%d" % (RegistersX64.to_str(self.index), self.phi_index)
        else:
            return RegistersX64.to_str(self.index)

    def contains(self, other: OperandSSA) -> bool:
        return self == other

    def contains_coarse(self, other: OperandSSA) -> bool:
        if type(other) != RegisterX64SSA:
            return False
        else:
            return self.index == other.index


class ConstantSSA(OperandSSA):

    def __init__(self, value: int, access_type: OperandAccessType):
        super().__init__(access_type)

        self.value = value
        self.is_constant = True

    def __ne__(self, o: object) -> bool:
        return not self.__eq__(o)

    def __eq__(self, o: object) -> bool:
        if type(self) != type(o):
            return False
        if self.value == o.value:
            return True
        return False

    def __hash__(self) -> int:
        return hash(self.value)


class ConstantX64SSA(ConstantSSA):

    def __ne__(self, o: object) -> bool:
        return super().__ne__(o)

    def __eq__(self, o: object) -> bool:
        return super().__eq__(o)

    def __hash__(self) -> int:
        return super().__hash__()

    def __init__(self, value: int, access_type: OperandAccessType):
        super().__init__(value, access_type)

    @classmethod
    def from_pb2(cls, op_ssa: ssa_export_pb2.ConstantX64):
        if op_ssa.access_type == ssa_export_pb2.UNKNOWN:
            access_type = OperandAccessType.Unknown
        elif op_ssa.access_type == ssa_export_pb2.READ:
            access_type = OperandAccessType.Read
        elif op_ssa.access_type == ssa_export_pb2.WRITE:
            access_type = OperandAccessType.Write
        elif op_ssa.access_type == ssa_export_pb2.READWRITE:
            access_type = OperandAccessType.ReadWrite
        else:
            raise ValueError("Unkown access type.")
        return cls(op_ssa.value, access_type)

    def __str__(self):
        if self.value < 0:
            return "#-%x" % (self.value * (-1))
        else:
            return "#%x" % self.value

    def contains(self, other: OperandSSA) -> bool:
        return self == other

    def contains_coarse(self, other: OperandSSA) -> bool:
        return self == other


class AddressX64SSA(ConstantSSA):

    def __ne__(self, o: object) -> bool:
        return super().__ne__(o)

    def __eq__(self, o: object) -> bool:
        return super().__eq__(o)

    def __hash__(self) -> int:
        return super().__hash__()

    def __init__(self, value: int, access_type: OperandAccessType):
        super().__init__(value, access_type)

    @classmethod
    def from_pb2(cls, op_ssa: ssa_export_pb2.AddressX64):
        if op_ssa.access_type == ssa_export_pb2.UNKNOWN:
            access_type = OperandAccessType.Unknown
        elif op_ssa.access_type == ssa_export_pb2.READ:
            access_type = OperandAccessType.Read
        elif op_ssa.access_type == ssa_export_pb2.WRITE:
            access_type = OperandAccessType.Write
        elif op_ssa.access_type == ssa_export_pb2.READWRITE:
            access_type = OperandAccessType.ReadWrite
        else:
            raise ValueError("Unkown access type.")
        return cls(op_ssa.value, access_type)

    def __str__(self):
        return "%%%x" % self.value

    def contains(self, other: OperandSSA) -> bool:
        return self == other

    def contains_coarse(self, other: OperandSSA) -> bool:
        return self == other


class MemorySSA(OperandSSA):

    def __ne__(self, o: object) -> bool:
        return not self.__eq__(o)

    def __init__(self, access_type: OperandAccessType):
        super().__init__(access_type)


class MemoryX64SSA(MemorySSA):

    def __eq__(self, o: object) -> bool:
        if type(self) != type(o):
            return False
        if (self.base == o.base
            and self.offset == o.offset
            and self.has_index == o.has_index
            and self.has_index_factor == o.has_index_factor):

            if self.has_index:
                if self.index == o.index:
                    if self.has_index_factor:
                        if self.index_factor == o.index_factor:
                            return True
                    else:
                        return True
            else:
                return True
        return False

    def __hash__(self) -> int:
        temp = hash((self.base, self.offset, self.has_index, self.has_index_factor))
        if self.has_index:
            temp = hash((temp, self.index))
        if self.has_index_factor:
            temp = hash((temp, self.index_factor))
        return temp

    def __init__(self,
                 base: RegisterX64SSA,
                 offset: ConstantX64SSA,
                 index: RegisterX64SSA,
                 index_factor: ConstantX64SSA,
                 access_type: OperandAccessType):
        super().__init__(access_type)

        self.base = base
        self.offset = offset

        self.has_index = False
        if index is not None:
            self.index = index
            self.has_index = True

        self.has_index_factor = False
        if index_factor is not None:
            self.index_factor = index_factor
            self.has_index_factor = True

        self.is_memory = True

    @classmethod
    def from_pb2(cls, op_ssa: ssa_export_pb2.MemoryX64):
        if op_ssa.access_type == ssa_export_pb2.UNKNOWN:
            access_type = OperandAccessType.Unknown
        elif op_ssa.access_type == ssa_export_pb2.READ:
            access_type = OperandAccessType.Read
        elif op_ssa.access_type == ssa_export_pb2.WRITE:
            access_type = OperandAccessType.Write
        elif op_ssa.access_type == ssa_export_pb2.READWRITE:
            access_type = OperandAccessType.ReadWrite
        else:
            raise ValueError("Unkown access type.")

        base = RegisterX64SSA.from_pb2(op_ssa.base.register_x64)
        offset = ConstantX64SSA.from_pb2(op_ssa.offset.constant_x64)

        index = None
        if op_ssa.HasField("index"):
            index = RegisterX64SSA.from_pb2(op_ssa.index.register_x64)

        index_factor = None
        if op_ssa.HasField("index_factor"):
            index_factor = ConstantX64SSA.from_pb2(op_ssa.index_factor.constant_x64)

        return cls(base, offset, index, index_factor, access_type)

    def __str__(self):
        result = "[%s" % self.base
        if self.has_index:
            result += "+%s" % self.index
        if self.has_index_factor:
            result += "*%s" % self.index_factor
        result += "]%s" % self.offset
        return result

    def contains(self, other: OperandSSA) -> bool:
        if type(other) == RegisterX64SSA:
            is_index = self.has_index and self.index.contains(other)
            return self.base.contains(other) or is_index
        elif type(other) == ConstantX64SSA:
            is_index = self.has_index_factor and self.index_factor.contains(other)
            return self.offset.contains(other) or is_index
        elif type(other) == MemoryX64SSA:
            return self == other
        else:
            return False

    def contains_coarse(self, other: OperandSSA) -> bool:
        if type(other) == RegisterX64SSA:
            is_index = self.has_index and self.index.contains_coarse(other)
            return self.base.contains_coarse(other) or is_index
        elif type(other) == ConstantX64SSA:
            is_index = self.has_index_factor and self.index_factor.contains_coarse(other)
            return self.offset.contains_coarse(other) or is_index
        elif type(other) == MemoryX64SSA:
            return self == other
        else:
            return False