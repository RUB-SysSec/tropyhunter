from typing import Dict, Any, List, DefaultDict, Optional, Set
from collections import defaultdict
from ..arch.x64 import RegistersX64, CallingConventionX64

class RegisterInputType(object):
    Unknown = 0
    Value = 1
    Memory = 2

    possible_for_unknown = [Value, Memory]

    _to_str = {
        Unknown: "Unknown",
        Value: "Value",
        Memory: "Memory",
    }

    @staticmethod
    def to_str(input_type):
        return RegisterInputType._to_str[input_type]


class RegisterInput(object):
    def __init__(self, uc_reg: int, input_type: int, init_data_type: int):
        self.uc_reg = uc_reg # type: int
        self.input_type = input_type # type: int
        self.value = None # type: Optional[int]
        self.init_data_type = init_data_type # type: int

    @staticmethod
    def from_obj(obj):
        """
        Creates a RegisterInput object from the given RegisterInput object (some kind of copy constructor).

        :param obj: RegisterInput object to copy.
        :return: new RegisterInput object created from given parameter.
        """
        temp = RegisterInput(obj.uc_reg, obj.input_type, obj.init_data_type)
        temp.set_value(obj.value)
        return temp

    def set_value(self, value: int):
        self.value = value

    def del_value(self):
        self.value = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the RegisterInput object into a dict.

        :return: Dict representing the RegisterInput object.
        """
        temp = dict()
        temp["uc_reg"] = self.uc_reg
        temp["input_type"] = self.input_type
        temp["init_data_type"] = self.init_data_type
        if self.value is not None:
            temp["value"] = self.value
        return temp

    @staticmethod
    def from_dict(input_reg_dict: Dict[str, Any]):
        """
        Creates a RegisterInput object from the given dict (the dict needs the same
        structure the `to_dict` function creates).

        :param input_reg_dict: RegisterInput object as dict.
        :return: new RegisterInput object created from given parameter.
        """
        temp = RegisterInput(int(input_reg_dict["uc_reg"]),
                             int(input_reg_dict["input_type"]),
                             int(input_reg_dict["init_data_type"]))
        if "value" in input_reg_dict.keys():
            temp.set_value(input_reg_dict["value"])
        return temp


class EndInstructionType(object):
    Ret = 0
    Call = 1
    Jmp = 2

    _to_str = {
        Ret: "Ret",
        Call: "Call",
        Jmp: "Jmp",
    }

    @staticmethod
    def to_str(end_type):
        return EndInstructionType._to_str[end_type]


class FunctionEnd(object):
    """
    Describes a function end.
    """

    def __init__(self, addr: int, end_type: int, valid: bool):
        self.addr = addr
        self.end_type = end_type # type: EndInstructionType
        self.valid = valid

    @staticmethod
    def from_dict(fct_end_dict: Dict[str, Any]):
        """
        Creates a FunctionEnd object from the given dict (the dict needs the same
        structure the `to_dict` function creates).

        :param fct_end_dict: FunctionEnd object as dict.
        :return: new FunctionEnd object created from given parameter.
        """
        new_obj = FunctionEnd(int(fct_end_dict["addr"]),
                              int(fct_end_dict["end_type"]),
                              bool(fct_end_dict["valid"]))
        return new_obj

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the FunctionEnd object into a dict.

        :return: Dict representing the FunctionEnd object.
        """
        return {"addr": self.addr,
                "end_type": self.end_type,
                "valid": self.valid}


class FunctionEnds(object):
    """
    Wrapper class to describe all function ends.
    """

    def __init__(self):
        self.fct_ends = dict() # type: Dict[int, FunctionEnd]

    @staticmethod
    def copy(orig_fct_ends):
        """
        Creates a copy of a FunctionEnds object.

        :param orig_fct_ends: FunctionEnds object to copy.
        :return: new FunctionEnds object copied from given parameter.
        """
        new_obj = FunctionEnds()
        for _, fct_end_obj in orig_fct_ends.fct_ends.items():
            new_fct_end = FunctionEnd(fct_end_obj.addr, fct_end_obj.end_type, fct_end_obj.valid)
            new_obj.add(new_fct_end)
        return new_obj

    @staticmethod
    def from_dict(fct_ends_dict: Dict[str, Any]):
        """
        Creates a FunctionEnds object from the given dict (the dict needs the same
        structure the `to_dict` function creates).

        :param fct_ends_dict: FunctionEnds object as dict.
        :return: new FunctionEnds object created from given parameter.
        """
        new_obj = FunctionEnds()
        for addr, fct_end_dict in fct_ends_dict["fct_ends"].items():
            fct_end_obj = FunctionEnd.from_dict(fct_end_dict)
            new_obj.fct_ends[addr] = fct_end_obj
        return new_obj

    def add(self, fct_end: FunctionEnd):
        """
        Add a function end.

        :param fct_end: function end object.
        """
        self.fct_ends[fct_end.addr] = fct_end

    def extend(self, fct_ends):
        """
        Extend the function ends with all given ones.

        :param fct_ends: FunctionEnds object.
        """
        for addr, fct_end in fct_ends.fct_ends.items():
            self.fct_ends[addr] = fct_end

    def end_valid(self, addr: int) -> bool:
        if self.end_exists(addr):
            return self.fct_ends[addr].valid
        return False

    def end_exists(self, addr: int) -> bool:
        return addr in self.fct_ends.keys()

    def rebase(self, rebase_addr: int):
        """
        Rebase all registered function ends.
        :param rebase_addr: rebase address to add to the actual address.
        """
        temp = dict()
        for _, fct_end in self.fct_ends.items():
            fct_end.addr += rebase_addr
            temp[fct_end.addr] = fct_end
        self.fct_ends = temp

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the FunctionEnds object into a dict.

        :return: Dict representing the FunctionEnds object.
        """
        fct_ends = dict()
        for addr, fct_end in self.fct_ends.items():
            fct_ends[addr] = fct_end.to_dict()
        return {"fct_ends": fct_ends}


class RuntimeMemoryObjectType(object):
    Section = 0
    Argument = 1
    Runtime = 2
    Stack = 3
    Special = 4


class EmulatorEnv(object):
    """
    Environment for a function emulation.
    """

    def __init__(self):
        self.rebase_addr = 0
        self.stack_addr = None
        self.stack_size = None
        self.stack_reg = None
        self.return_regs = None
        self.uc_arch = None
        self.uc_mode = None
        self.dyn_mem_obj_start_addr = None
        self.dyn_mem_obj_ctr = 0
        self.dyn_mem_obj_size = 32 * 1024
        self.runtime_memory_objs = list() # type: List[RuntimeMemoryObject]
        self.fct_ends = None # type: FunctionEnds
        self.relocation_addrs = set() # type: Set[int]
        self.addr_ret_instr = None
        self.capstone = None

        # Dict of plt functions (address to name).
        self.plt_functions = dict() # type: Dict[int, str]
        self.lib_wrapper_funcs = dict() # type: Dict[str, Any]

        # List of changes to the memory that are performed during the initialization of the memory.
        self.runtime_memory_changes = set() # type: Set[FuzzingMemoryLocation]

        # A set of addresses which basic blocks were reached.
        self.basic_block_coverage = set()

        # Special memory locations (like fs register under Linux x86_64) in order to have them
        # not mapped to address 0x0.
        self.special_start_addr = None
        self.special_size = 4 * 1024
        self.special_ctr = 0
        self.special_reg_map = dict() # type: Dict[int, int]
        self.special_mem_list = list()  # type: List[RuntimeMemoryObject]

        # Timeout in seconds for a single emulation (needed to prevent infinity loops).
        self.single_run_timeout = 0 # type: int
        self.single_run_start_time = 0 # type: int
        self.single_run_is_timeout = False

        # Timeout in seconds for the fuzzing (otherwise it can be endless if we fuzz a crypto algorithm).
        self.fuzzing_timeout = 0 # type: int
        self.fuzzing_start_time = 0 # type: int
        self.fuzzing_is_timeout = False
        self.fuzzing_used_coverage = False
        self.fuzzing_used_end_point = False

        # Information needed to emulate heap memory.
        self.emu_heap_start_addr = None
        self.emu_heap_next_addr = None
        self.emu_heap_objs = dict() # type: Dict[int, EmulationHeapMemoryObject]

        # Information needed to emulate file descriptors.
        self.emu_fd_start = None
        self.emu_fd_next = None
        self.emu_fd_open = dict() # type: Dict[int, str]

        # TODO Debugger flags that should be removed afterwards.
        self.debug_instr_trace = False
        self.debug_bb_trace = False
        self.debug_output = False
        self.debug_disable_fuzzing_end_point = False
        self.debug_disable_fuzzing_coverage = False
        self.debug_dyn_breakpoints = set([])

    def reset(self):
        self.single_run_is_timeout = False
        self.fuzzing_is_timeout = False

        for mem_obj in self.runtime_memory_objs:
            mem_obj.read_accesses.clear()
            mem_obj.write_accesses.clear()

        self.emu_heap_objs.clear()
        self.emu_heap_next_addr = self.emu_heap_start_addr
        self.emu_fd_open.clear()
        self.emu_fd_next = self.emu_fd_start


class EmulationHeapMemoryObject(object):
    """
    Objects describing the created heap memory object (created during library function emulation).
    """

    def __init__(self, address, size, size_aligned):
        self.address = address
        self.size = size
        self.size_aligned = size_aligned


class InitialMemoryObject(object):
    """
    The initial content of a memory object before the emulation.
    """

    def __init__(self, addr: int, size: int, data: bytes, ):
        self.data = data # type: bytes
        self.addr = addr # type: int
        self.size = size # type: int

    def contains_addr(self, addr: int) -> bool:
        return self.addr <= addr <= (self.addr + self.size)

    def get_data(self, addr: int, size: int) -> Optional[bytes]:
        if not self.contains_addr(addr):
            return None
        offset = addr - self.addr
        return self.data[offset:offset+size]

    def change_data(self, addr: int, data: bytes) -> bool:
        if not self.contains_addr(addr):
            return False
        if (addr + len(data)) > (addr + len(self.data)):
            return False

        offset = addr - self.addr
        new_data = self.data[0:offset]
        new_data += data
        new_data += self.data[offset+len(data):]
        self.data = new_data
        return True


class MemoryAccess(object):
    """
    Access to a memory location.
    """

    def __init__(self,
                 addr: int,
                 size: int,
                 data,
                 instr_addr: int,
                 is_read: bool,
                 is_write: bool,
                 is_read_before_write: bool = False):
        self.addr = addr
        self.size = size
        self.data = data
        self.instr_addr = instr_addr
        self.is_read = is_read
        self.is_write = is_write
        if is_read:
            self.is_read_before_write = is_read_before_write
        else:
            self.is_read_before_write = False

    def __str__(self):
        return "at %08x -> %08x:%d" % (self.instr_addr, self.addr, self.size)


class RuntimeMemoryObject(object):
    """
    The metadata for a memory object.
    """

    def __init__(self,
                 start_addr: int,
                 end_addr: int,
                 mem_type: int,
                 name: str="",
                 init_mem_obj: Optional[InitialMemoryObject]=None):
        self.start_addr = start_addr # type: int
        self.end_addr = end_addr # type: int
        self.mem_type = mem_type # type: int
        self.name = name # type: str
        self.init_mem_obj = init_mem_obj # type: Optional[InitialMemoryObject]
        self.read_accesses = defaultdict(list) # type: DefaultDict[int, List[MemoryAccess]]
        self.write_accesses = defaultdict(list) # type: DefaultDict[int, List[MemoryAccess]]

    def contains_addr(self, addr: int) -> bool:
        return self.start_addr <= addr <= self.end_addr

    def add_mem_read_obj(self, obj: MemoryAccess):
        if obj.addr not in self.write_accesses.keys():
            obj.is_read_before_write = True
        self.read_accesses[obj.addr].append(obj)

    def add_mem_read(self, addr: int, size: int, data: bytes, instr_addr: int):
        obj = MemoryAccess(addr, size, data, instr_addr, True, False)
        self.add_mem_read_obj(obj)

    def add_mem_write_obj(self, obj: MemoryAccess):
        self.write_accesses[obj.addr].append(obj)

    def add_mem_write(self, addr: int, size: int, data: bytes, instr_addr: int):
        obj = MemoryAccess(addr, size, data, instr_addr, False, True)
        self.add_mem_write_obj(obj)

    def get_init_data(self, addr: int, size: int) -> Optional[bytes]:
        if self.init_mem_obj is None:
            return None
        if self.init_mem_obj.contains_addr(addr):
            return self.init_mem_obj.get_data(addr, size)
        return None

    def change_init_data(self, addr: int, data: bytes) -> bool:
        if self.init_mem_obj is None:
            return False
        return self.init_mem_obj.change_data(addr, data)


class InputDataTypeRule(object):
    Zero = 0
    One = 1
    RandomPlus = 2
    RandomMinus = 3
    Random = 4
    RandomPlus8Small = 5
    RandomPlus4Small = 6
    RandomMinus8Small = 7
    RandomMinus4Small = 8

    _to_str = {
        Zero: "Zero",
        One: "One",
        RandomPlus: "RandomPlus",
        RandomMinus: "RandomMinus",
        Random: "Random",
        RandomPlus8Small: "RandomPlus8Small",
        RandomPlus4Small: "RandomPlus4Small",
        RandomMinus8Small: "RandomMinus8Small",
        RandomMinus4Small: "RandomMinus4Small",
    }

    @staticmethod
    def to_str(input_type):
        return InputDataTypeRule._to_str[input_type]


class InputDataTypeRuleGenerator(object):
    """
    A generator for input data type rules.
    """

    def __init__(self):
        self.input_round_rules = [InputDataTypeRule.Zero,
                                  InputDataTypeRule.Random,
                                  InputDataTypeRule.RandomPlus8Small,  # Sets small positive integers 8 bytes aligned
                                  InputDataTypeRule.RandomPlus4Small,  # Sets small positive integers 4 bytes aligned
                                  # InputDataTypeRule.RandomMinus8Small,  # Sets small negative integers 8 bytes aligned
                                  # InputDataTypeRule.RandomMinus4Small,  # Sets small negative integers 4 bytes aligned
                                  InputDataTypeRule.RandomPlus, ]
                                  # InputDataTypeRule.RandomMinus]
        self.curr_idx = 0

    def get_current(self) -> Optional[int]:
        """
        Returns the current input data type rule.

        :return: input data type rule or None if none is available.
        """
        if self.curr_idx < len(self.input_round_rules):
            return self.input_round_rules[self.curr_idx]
        else:
            return None

    def next(self):
        """
        Switches to the next input data type rule.
        """
        self.curr_idx += 1


class FuzzingMemoryLocation(object):
    """
    A memory location that is fuzzed.
    """

    def __init__(self, addr: int, size: int):
        self.addr = addr
        self.size = size
        self.fuzz_type = None

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if (self.addr == other.addr
           and self.size == other.size):
            return True
        return False

    def __hash__(self):
        return hash((self.addr, self.size))

    def __str__(self):
        if self.fuzz_type is None:
            return "%08x:%d" % (self.addr, self.size)
        else:
            return "%08x:%d -> %d" % (self.addr, self.size, self.fuzz_type)


class FunctionOutputType(object):
    Register = 0
    Pointer = 1

    _to_str = {
        Register: "reg",
        Pointer: "ptr",
    }

    @staticmethod
    def to_str(type_idx: int):
        if type_idx not in FunctionOutputType._to_str:
            raise NotImplementedError('Unknown type index %d.' %
                                      type_idx)
        return FunctionOutputType._to_str[type_idx]


class FunctionOutput(object):
    """
    A function output candidate.
    """

    def __init__(self, fct_addr: int, output_type: int, register: int):
        self.fct_addr = fct_addr
        self.output_type = output_type
        self.register = register
        self.data = b''
        self.data_buckets = defaultdict(int)
        self.data_file = ""
        self.is_data_in_obj = True
        self.dieharder_results = {"PASSED": [], "WEAK": [], "FAILED": []}
        self.inferred_input_regs = dict()  # type: Dict[int, RegisterInput]
        self.used_input_regs = dict()  # type: Dict[int, RegisterInput]
        self.dyn_size = False
        self.maybe_prng = False
        self.maybe_hash = False
        self.maybe_enc = False
        self.args_conclusive = False
        self.fuzzing_used_coverage = False
        self.fuzzing_used_end_point = False

    def __hash__(self):
        return hash((self.output_type, self.register))

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if (self.output_type == other.output_type
           and self.register == other.register):
            return True
        return False

    def __str__(self):
        result = "%08x" % self.fct_addr
        result += " %s" % RegistersX64.from_unicorn_to_str(self.register)
        result += " (%s)" % FunctionOutputType.to_str(self.output_type)
        result += "\nDIEHARDER: PASSED: %s; WEAK: %s; FAILED: %s;" % (self.dieharder_results["PASSED"],
                                                                      self.dieharder_results["WEAK"],
                                                                      self.dieharder_results["FAILED"])
        result += "\nDYN_SIZE: %s;" % str(self.dyn_size)
        result += "\nMAYBE_PRNG: %s;" % str(self.maybe_prng)
        result += "\nMAYBE_HASH: %s;" % str(self.maybe_hash)
        result += "\nMAYBE_ENC: %s;" % str(self.maybe_enc)
        result += "\nARGS_CONCLUSIVE: %s;" % str(self.args_conclusive)

        temp_inferred = ""
        temp_used = ""
        for ida_reg in CallingConventionX64.system_v: # TODO architecture specific
            unicorn_reg = RegistersX64.to_unicorn(ida_reg)
            if unicorn_reg in self.inferred_input_regs.keys():
                inferred_input_reg = self.inferred_input_regs[unicorn_reg]
                temp_inferred += RegistersX64.to_str(ida_reg) + ": "
                temp_inferred += RegisterInputType.to_str(inferred_input_reg.input_type) + "; "

                used_input_reg = self.used_input_regs[unicorn_reg]
                temp_used += RegistersX64.to_str(ida_reg) + ": "
                temp_used += RegisterInputType.to_str(used_input_reg.input_type)
                if used_input_reg.input_type == RegisterInputType.Memory:
                    temp_used += " (" + InputDataTypeRule.to_str(used_input_reg.init_data_type) + ")"
                temp_used += "; "
        result += "\nINFERRED_ARGS: " + temp_inferred
        result += "\nUSED_ARGS: " + temp_used
        result += "\nFUZZING_USED_END_POINT: %s;" % str(self.fuzzing_used_end_point)
        result += "\nFUZZING_USED_COVERAGE: %s;" % str(self.fuzzing_used_coverage)

        if not self.is_data_in_obj:
            result += "\ndata in file '%s'" % self.data_file
        result += "\n"
        return result

    @staticmethod
    def from_dict(fct_output_dict: Dict[str, Any]):
        """
        Creates a FunctionOutput object from the given dict (the dict needs the same
        structure the `to_dict` function creates).

        :param fct_output_dict: FunctionOutput object as dict.
        :return: new FunctionOutput object created from given parameter.
        """
        new_obj = FunctionOutput(int(fct_output_dict["fct_addr"]),
                                 int(fct_output_dict["output_type"]),
                                 int(fct_output_dict["register"]))
        new_obj.data_file = str(fct_output_dict["data_file"])
        new_obj.is_data_in_obj = bool(fct_output_dict["is_data_in_obj"])

        new_obj.dieharder_results = fct_output_dict["dieharder_results"]
        new_obj.dyn_size = fct_output_dict["dyn_size"]
        new_obj.maybe_prng = fct_output_dict["maybe_prng"]
        new_obj.maybe_hash = fct_output_dict["maybe_hash"]
        new_obj.maybe_enc = fct_output_dict["maybe_enc"]
        new_obj.args_conclusive = fct_output_dict["args_conclusive"]
        new_obj.fuzzing_used_end_point = fct_output_dict["fuzzing_used_end_point"]
        new_obj.fuzzing_used_coverage = fct_output_dict["fuzzing_used_coverage"]

        for reg_idx, input_reg_dict in fct_output_dict["inferred_input_regs"].items():
            new_obj.inferred_input_regs[int(reg_idx)] = RegisterInput.from_dict(input_reg_dict)

        for reg_idx, input_reg_dict in fct_output_dict["used_input_regs"].items():
            new_obj.used_input_regs[int(reg_idx)] = RegisterInput.from_dict(input_reg_dict)

        return new_obj

    def add_data(self, data: bytes):
        """
        Adds outputted data.

        :param data: bytes that are outputted by the function.
        """
        if not self.is_data_in_obj:
            raise NotImplementedError("Load data from file into object not implemented yet.")

        self.data += data
        self.data_buckets[data] += 1

    def data_threshold_reached(self, threshold):
        """
        Checks if any data is outputted multiple times to reach the threshold.

        :param threshold: threshold to reach.
        :return: True if the threshold is reached by any outputted data.
        """
        if not self.is_data_in_obj:
            raise NotImplementedError("Load data from file into object not implemented yet.")

        return any(map(lambda x: x[1] >= threshold, self.data_buckets.items()))

    def set_file_location(self, file_location):
        """
        Sets location to store the data.

        :param file_location: file location where to store the data.
        """
        self.data_file = file_location

    def store_to_file(self):
        """
        Stores data to file and clears the local data cache.
        """
        if self.data_file == "":
            raise ValueError("File location not set.")

        if self.is_data_in_obj:
            # Store data to file.
            with open(self.data_file, 'wb') as fp:
                fp.write(self.data)

            self.data_buckets.clear()
            self.data = b''
            self.is_data_in_obj = False

    def is_data_cached(self) -> bool:
        """
        Checks if FunctionOutput object has data.

        :return: returns True if object has data.
        """
        return self.is_data_in_obj

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the FunctionOutput object into a dict.

        :return: Dict representing the FunctionOutput object.
        """
        self.store_to_file()
        temp = dict()
        temp["fct_addr"] = self.fct_addr
        temp["output_type"] = self.output_type
        temp["register"] = self.register
        temp["data_file"] = self.data_file
        temp["is_data_in_obj"] = self.is_data_in_obj
        temp["dieharder_results"] = self.dieharder_results
        temp["dyn_size"] = self.dyn_size
        temp["maybe_prng"] = self.maybe_prng
        temp["maybe_hash"] = self.maybe_hash
        temp["maybe_enc"] = self.maybe_enc
        temp["args_conclusive"] = self.args_conclusive
        temp["fuzzing_used_end_point"] = self.fuzzing_used_end_point
        temp["fuzzing_used_coverage"] = self.fuzzing_used_coverage

        temp["inferred_input_regs"] = dict()
        for reg_idx, input_reg in self.inferred_input_regs.items():
            temp["inferred_input_regs"][reg_idx] = input_reg.to_dict()

        temp["used_input_regs"] = dict()
        for reg_idx, input_reg in self.used_input_regs.items():
            temp["used_input_regs"][reg_idx] = input_reg.to_dict()

        return temp

    def size_data(self) -> int:
        """
        Gives the size of the stored output data.

        :return: size of output data.
        """
        return len(self.data)