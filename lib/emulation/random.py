from elftools.elf.elffile import ELFFile, RelocationSection
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from .fuzzing import fuzzing_end_point, fuzzing_coverage
from .emulation import *
from .core import FunctionOutput, FunctionOutputType, FunctionEnds, InputDataTypeRuleGenerator, RegisterInput
from .lib_emulation import register_lib_emulations
from ..entropy.entropy import check_entropy
from typing import Set, Tuple

class CandidateErrorCodes(object):
    SUCCESS = 0
    FUZZING_FAILED = 1
    NO_OUTPUT_DSTS = 2
    TIMEOUT_SINGLE_RUN = 3
    FUZZING_FAILED_TIMEOUT = 4


def init_output_dsts(emu_env: EmulatorEnv, fct_addr: int, input_regs: Dict[int, RegisterInput]) -> Set[FunctionOutput]:

    # Initialize possible output destinations.
    output_dsts = set()
    # Add return registers as possible output destination.
    for return_reg in emu_env.return_regs:
        output_dsts.add(FunctionOutput(fct_addr, FunctionOutputType.Register, return_reg))
    # Add all pointer registers as possible output destinations.
    for uc_input_reg in input_regs.keys():
        if input_regs[uc_input_reg].input_type == RegisterInputType.Memory:
            output_dsts.add(FunctionOutput(fct_addr, FunctionOutputType.Pointer, uc_input_reg))

    return output_dsts


def init_emulator_env(fct_ends: FunctionEnds,
                      single_run_timeout,
                      fuzzing_timeout) -> EmulatorEnv:

    emu_env = EmulatorEnv()
    emu_env.stack_addr = 0x7fffffff0000 # TODO architecture specific
    emu_env.emu_heap_start_addr = 0x2000000 # TODO architecture specific
    emu_env.stack_size = 1024 * 1024
    emu_env.special_start_addr = 0x4000 # TODO architecture specific
    emu_env.stack_reg = UC_X86_REG_RSP # TODO architecture specific
    emu_env.uc_arch = UC_ARCH_X86 # TODO architecture specific
    emu_env.uc_mode = UC_MODE_64 # TODO architecture specific
    emu_env.capstone = Cs(CS_ARCH_X86, CS_MODE_64)
    emu_env.return_regs = [UC_X86_REG_RAX, UC_X86_REG_XMM0] # TODO architecture specific
    emu_env.fct_ends = FunctionEnds.copy(fct_ends)
    emu_env.single_run_timeout = single_run_timeout
    emu_env.fuzzing_timeout = fuzzing_timeout
    emu_env.emu_fd_start = 10
    return emu_env


def load_binary(binary_file: str,
                emu_env: EmulatorEnv) -> List[InitialMemoryObject]:

    # Import plt functions if exist.
    plt_fct_map = dict()
    if os.path.isfile(binary_file + "_plt.txt"):
        with open(binary_file + "_plt.txt", 'r') as fp:
            for line in fp:
                line_split = line.split(" ")
                addr = int(line_split[0], 16)
                name = line_split[1].strip()
                plt_fct_map[name] = addr

    # Extract segments to load from the binary file.
    memory_objects = list()
    with open(binary_file, 'rb') as fp:
        elf_file = ELFFile(fp) # TODO architecture specific

        # Set rebase address if we process position independent code.
        if elf_file.header["e_type"] == "ET_DYN":
            emu_env.rebase_addr = 0x400000
            emu_env.fct_ends.rebase(emu_env.rebase_addr)
            for name, addr in plt_fct_map.items():
                plt_fct_map[name] = addr + emu_env.rebase_addr

        # Get .dynsym section to resolve symbols.
        dynsym_section = None
        for section in elf_file.iter_sections():
            if section.name == ".dynsym":
                dynsym_section = section
                break

        # Get relocations from sections for loading of file.
        # IMPORTANT NOTE: sections are optional and can also be forged with wrong information. Using sections
        # here is more a convenience thing since the relocation information is also available using the segments
        # (since the loader needs them).
        relocations = dict() # type: Dict[int, bytes]
        for section in elf_file.iter_sections():
            if type(section) == RelocationSection:
                for relocation in section.iter_relocations():
                    if relocation.is_RELA():
                        info_type = relocation["r_info_type"]
                        mem_addr = relocation["r_offset"] + emu_env.rebase_addr
                        addend = relocation["r_addend"]

                        if info_type == 7: # R_X86_64_JUMP_SLO
                            symbol_no = relocation["r_info_sym"]
                            if dynsym_section and section.name == ".rela.plt":
                                symbol = dynsym_section.get_symbol(symbol_no)
                                value = symbol["st_value"]
                                if value != 0:
                                    value += emu_env.rebase_addr

                                    # Remove plt function entry if we have a relocation entry for it.
                                    if symbol.name in plt_fct_map.keys():
                                        plt_import_value = plt_fct_map[symbol.name]
                                        # Ignore each plt relocation entry that writes the same address as
                                        # the plt entry already has.
                                        if value == plt_import_value:
                                            continue
                                        del plt_fct_map[symbol.name]

                                    relocations[mem_addr] = struct.pack("Q", value)

                        elif info_type == 6: # R_X86_64_GLOB_DAT
                            symbol_no = relocation["r_info_sym"]
                            if dynsym_section and section.name == ".rela.dyn":
                                symbol = dynsym_section.get_symbol(symbol_no)
                                value = symbol["st_value"]
                                if value != 0:
                                    value += emu_env.rebase_addr

                                    # Remove plt function entry if we have a relocation entry for it.
                                    if symbol.name in plt_fct_map.keys():
                                        plt_import_value = plt_fct_map[symbol.name]
                                        # Ignore each plt relocation entry that writes the same address as
                                        # the plt entry already has.
                                        if value == plt_import_value:
                                            continue
                                        del plt_fct_map[symbol.name]

                                    relocations[mem_addr] = struct.pack("Q", value)

                        elif info_type == 37: # R_X86_64_IRELATIVE
                            relocations[mem_addr] = struct.pack("Q", addend)
                    else:
                        raise NotImplementedError("Relocations that are not RELA not impemented yet.")

        for segment in elf_file.iter_segments():

            # We are only interested in the data that is loaded into memory.
            if segment.header.p_type != "PT_LOAD":
                continue

            mem_addr = segment.header.p_vaddr + emu_env.rebase_addr
            mem_size = segment.header.p_memsz

            # Extract data from file since elftools seems to fuckup streams.
            file_offset = segment.header.p_offset
            file_size = segment.header.p_filesz
            fp.seek(file_offset)
            data = fp.read(file_size)
            init_mem_obj = InitialMemoryObject(mem_addr, mem_size, data)

            # Modify memory to load with relocations.
            for relocation_addr, relocation_data in relocations.items():
                if mem_addr <= relocation_addr <= (mem_addr + mem_size):
                    init_mem_obj.change_data(relocation_addr, relocation_data)
                    emu_env.relocation_addrs.add(relocation_addr)

            memory_objects.append(init_mem_obj)

    # Store imported plt functions.
    for name, addr in plt_fct_map.items():
        emu_env.plt_functions[addr] = name

    return memory_objects


def create_candidate_data_emulation(binary_file: str,
                                    mu: Uc,
                                    emu_env: EmulatorEnv,
                                    fct_start: int,
                                    input_regs: Dict[int, RegisterInput],
                                    min_size_data: int,
                                    output_threshold: int,
                                    fuzzing_max_attempts: int) -> Tuple[int, Set[FunctionOutput]]:

    # Reset usage of fuzzing.
    emu_env.fuzzing_used_end_point = False
    emu_env.fuzzing_used_coverage = False

    # Rebase start address before run.
    fct_start += emu_env.rebase_addr

    # Initialize possible output destinations.
    output_dsts = init_output_dsts(emu_env, fct_start, input_regs)

    # Check if we have a argument given as value which we consider as size argument.
    is_size_arg_given = False
    for _, input_reg in input_regs.items():
        if input_reg.input_type == RegisterInputType.Value:
            is_size_arg_given = True
            break

    error_code = CandidateErrorCodes.SUCCESS
    ctr = 0
    fuzzing_ctr = 0
    max_rounds = int(min_size_data / 4) + 1
    percent_ctr = int(max_rounds / 10) + 1
    while ctr < max_rounds:

        if ctr == 0:
            print("Starting emulation process to generate random data.")

        ctr += 1
        if ctr % percent_ctr == 0:
            print("%d%% of rounds are finished." % (int(ctr / percent_ctr) * 10))

            # Check if every output destination has already created the minimum number of bytes
            # we want to extract and stop emulation if we have.
            is_min_data_reached = True
            for output_dst in output_dsts:
                if output_dst.size_data() < min_size_data:
                    is_min_data_reached = False
                    break
            if is_min_data_reached:
                print("Minimum output data of %d bytes reached for each output destination. Stopping emulation."
                      % min_size_data)
                break

        emulate_function(mu, emu_env, fct_start, input_regs)

        # Abort if we had a timeout of a single run (most likely we hit an infinity loop).
        if emu_env.single_run_is_timeout:
            error_code = CandidateErrorCodes.TIMEOUT_SINGLE_RUN
            return (error_code, set())

        # Check if emulation ended at an instruction we wanted it to end.
        # If not we search for data read from the memory that holds still the initial
        # value and mark it for changing.
        last_end_addr = mu.reg_read(UC_X86_REG_RIP)
        if emu_env.fct_ends.end_valid(last_end_addr):

            error_code = CandidateErrorCodes.SUCCESS

            # Extract output data.
            for output_dst in output_dsts:

                # Extract output from the register as destination.
                if output_dst.output_type == FunctionOutputType.Register:
                    reg_data = mu.reg_read(output_dst.register)

                    # Always consider output to be 4 bytes (because we do not know if the PRNG
                    # works on int32.
                    if output_dst.register == UC_X86_REG_XMM0:
                        curr_output = struct.pack("d", reg_data)
                    elif reg_data > 4294967295:
                        curr_output = struct.pack("Q", reg_data)
                    else:
                        curr_output = struct.pack("I", reg_data)
                    output_dst.add_data(curr_output[0:4])

                # Extract output from a memory region given as input pointer.
                elif output_dst.output_type == FunctionOutputType.Pointer:
                    addr = input_regs[output_dst.register].value

                    # Extract 8 bytes if we have an argument which we consider as size argument.
                    if is_size_arg_given:
                        curr_output = mu.mem_read(addr, 8)

                    # If we do not have a size argument, let us play safe and only consider 4 bytes as output.
                    else:
                        curr_output = mu.mem_read(addr, 4)
                    output_dst.add_data(bytes(curr_output))

                else:
                    raise NotImplementedError("Do not know type of output destination.")

            # When the same output occurs more often than the given threshold we remove the
            # output destination as possible target.
            if (ctr % output_threshold) == 0:
                for output_dst in set(output_dsts):
                    if output_dst.data_threshold_reached(output_threshold):
                        output_dsts.remove(output_dst)

            # If we do not have any possible output targets anymore we can abort the emulation
            # as unsuccessful.
            if not output_dsts:

                # Perhaps some initial state has to be set to reach the correct basic block. Perform coverage
                # guided fuzzing in order to find new ways to reach a basic block.
                print("Ended with no output destination candidate. Starting coverage fuzzing process.")

                if fuzzing_ctr < fuzzing_max_attempts:
                    fuzzing_ctr += 1
                    if fuzzing_coverage(mu, emu_env, fct_start, input_regs):
                        # Reset emulation loop in order to retry finding suitable output destinations.
                        output_dsts = init_output_dsts(emu_env, fct_start, input_regs)
                        error_code = CandidateErrorCodes.SUCCESS
                        ctr = 0
                        continue
                else:
                    print("Maximal number of fuzzing attempts reached. Skipping fuzzing process.")

                print("No new coverage found for output generation.")
                error_code = CandidateErrorCodes.NO_OUTPUT_DSTS
                break

        else:
            # Start fuzzing of the function to find a memory configuration that leads to a
            # valid end instruction. If we have found one, continue emulation.
            print("Ended in wrong function end %08x. Starting fuzzing process." % last_end_addr)

            if fuzzing_ctr < fuzzing_max_attempts:
                fuzzing_ctr += 1
                if fuzzing_end_point(mu, emu_env, fct_start, input_regs):
                    ctr -= 1
                    continue
            else:
                print("Maximal number of fuzzing attempts reached. Skipping fuzzing process.")

            if emu_env.fuzzing_is_timeout:
                error_code = CandidateErrorCodes.FUZZING_FAILED_TIMEOUT
                print("Fuzzing timeout.")
            else:
                error_code = CandidateErrorCodes.FUZZING_FAILED
                print("Fuzzing failed to find a memory configuration to get to a desired function end.")
            break

    # Finalize function output objects.
    if error_code == CandidateErrorCodes.SUCCESS:
        for output_dst in output_dsts:
            # Set fuzzing usage.
            output_dst.fuzzing_used_end_point = emu_env.fuzzing_used_end_point
            output_dst.fuzzing_used_coverage = emu_env.fuzzing_used_coverage

            # Create output file location.
            output_file = os.path.dirname(binary_file) + "/rng_%08x_" % fct_start
            if output_dst.output_type == FunctionOutputType.Register:
                output_file += "reg_%s.bin" % RegistersX64.from_unicorn_to_str(output_dst.register)
            elif output_dst.output_type == FunctionOutputType.Pointer:
                output_file += "ptr_%s.bin" % RegistersX64.from_unicorn_to_str(output_dst.register)
            else:
                raise NotImplementedError("Do not know type of output destination.")
            output_dst.set_file_location(output_file)

    return (error_code, output_dsts)


def create_candidate_data_preparation(binary_file: str,
                                      fct_start: int,
                                      fct_ends: FunctionEnds,
                                      single_run_timeout: int,
                                      fuzzing_timeout: int) -> Tuple[Uc, EmulatorEnv]:

    # Create emulator environment.
    emu_env = init_emulator_env(fct_ends, single_run_timeout, fuzzing_timeout)

    # Load binary into memory.
    memory_objects = load_binary(binary_file, emu_env)

    # Register all lib emulation functions.
    register_lib_emulations(emu_env)

    # Initialize emulator.
    mu = init_emulator(memory_objects, emu_env)

    # Hooks for unmapped read/writes
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_unmapped_read, user_data=emu_env)
    mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_unmapped_write, user_data=emu_env)

    # Hooks for memory read/writes
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read, user_data=emu_env)
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write, user_data=emu_env)

    # Hook syscalls.
    mu.hook_add(UC_HOOK_INSN, hook_syscall, emu_env, 1, 0, UC_X86_INS_SYSCALL)

    mu.hook_add(UC_HOOK_CODE, hook_code, user_data=emu_env)

    # Trace all reached basic blocks.
    mu.hook_add(UC_HOOK_BLOCK, hook_block, user_data=emu_env)

    # Sanity check if artificial return address is set.
    if emu_env.addr_ret_instr is None:
        raise ValueError("Need valid return instruction address.")

    return mu, emu_env


def create_candidate_data_run(binary_file: str,
                              fct_start: int,
                              fct_ends: FunctionEnds,
                              input_regs: Dict[int, RegisterInput],
                              min_size_data: int=400000,
                              output_threshold: int=5,
                              single_run_timeout: int=15,
                              fuzzing_timeout:int=20,
                              fuzzing_max_attempts: int = 500) -> Tuple[int, Set[FunctionOutput]]:

    mu, emu_env = create_candidate_data_preparation(binary_file,
                                                    fct_start,
                                                    fct_ends,
                                                    single_run_timeout,
                                                    fuzzing_timeout)

    return create_candidate_data_emulation(binary_file,
                                           mu,
                                           emu_env,
                                           fct_start,
                                           input_regs,
                                           min_size_data,
                                           output_threshold,
                                           fuzzing_max_attempts)


def create_candidate_data(binary_file: str,
                          fct_start: int,
                          fct_ends: FunctionEnds,
                          input_regs: Dict[int, RegisterInput],
                          min_size_data: int = 400000,
                          output_threshold: int=5,
                          single_run_timeout: int=20,
                          fuzzing_timeout: int=20,
                          fuzzing_max_attempts: int=500,
                          input_data_type_rule_gen: InputDataTypeRuleGenerator=None) -> Tuple[Set[FunctionOutput], InputDataTypeRuleGenerator]:
    """
    Tries to create output data for the given function address.

    :param binary_file: path to the binary executable.
    :param fct_start: address of the function to test.
    :param fct_ends: Function endings.
    :param input_regs: input registers (cannot contain "Unknown" input type).
    :param min_size_data: minimum of data in bytes the emulation should create.
    :param output_threshold: number of times the output can be duplicated before it is dismissed.
    :param single_run_timeout: timeout in seconds a single run has.
    :param fuzzing_timeout: timeout in seconds the fuzzing process has.
    :param fuzzing_max_attempts: maximal number of fuzzing attempts (in order to prevent infinity loops).
    :param input_data_type_rule_gen: generator for the input data type rule.
    :return: Set of FunctionOutput.
    """

    # Create an input data type rule generator if none is given.
    if input_data_type_rule_gen is None:
        input_data_type_rule_gen = InputDataTypeRuleGenerator()

    # Only run emulation if a sane input round index is given
    input_round_rule = input_data_type_rule_gen.get_current()
    if input_round_rule is None:
        print("Start input data rule generator no rules left.")
        return (set(), input_data_type_rule_gen)

    while True:
        input_round_rule = input_data_type_rule_gen.get_current()
        if input_round_rule is None:
            break

        print("Starting output generation with rule: %s" % InputDataTypeRule.to_str(input_round_rule))

        for unicorn_op in input_regs.keys():
            if input_regs[unicorn_op].input_type == RegisterInputType.Memory:
                input_regs[unicorn_op].init_data_type = input_round_rule
                input_regs[unicorn_op].del_value()

        # Try an emulation.
        error_code, output_dsts = create_candidate_data_run(binary_file,
                                                            fct_start,
                                                            fct_ends,
                                                            input_regs,
                                                            min_size_data=min_size_data,
                                                            output_threshold=output_threshold,
                                                            single_run_timeout=single_run_timeout,
                                                            fuzzing_max_attempts=fuzzing_max_attempts,
                                                            fuzzing_timeout=fuzzing_timeout)

        if error_code == CandidateErrorCodes.SUCCESS:
            return (output_dsts, input_data_type_rule_gen)

        # If we did not find any output destination candidates, redo emulation with a randomized initial state.
        # (Since we often encountered signed comparisons and the random data could produce a negative value,
        # we retry multiple times also with positive random values and negative ones)
        elif error_code in [CandidateErrorCodes.NO_OUTPUT_DSTS,
                          CandidateErrorCodes.TIMEOUT_SINGLE_RUN,
                          CandidateErrorCodes.FUZZING_FAILED,
                          CandidateErrorCodes.FUZZING_FAILED_TIMEOUT]:
            print("Not able to generate output. Possible restart with different input.")
            input_data_type_rule_gen.next()
            continue

        else:
            print("Not able to generate output. No restart different input.")
            break

    return (set(), input_data_type_rule_gen)


def create_entropy_data(binary_file: str,
                        fct_start: int,
                        fct_ends: FunctionEnds,
                        input_regs: Dict[int, RegisterInput],
                        min_size_data: int=400000,
                        output_threshold: int=5,
                        single_run_timeout: int=20,
                        fuzzing_timeout: int=20,
                        fuzzing_max_attempts: int=500) -> Set[FunctionOutput]:
    """
    Tries to create output data for the given function address which passes the entropy check.

    :param binary_file: path to the binary executable.
    :param fct_start: address of the function to test.
    :param fct_ends: Function endings.
    :param input_regs: input registers (cannot contain "Unknown" input type).
    :param min_size_data: minimum of data in bytes the emulation should create.
    :param output_threshold: number of times the output can be duplicated before it is dismissed.
    :param single_run_timeout: timeout in seconds a single run has.
    :param fuzzing_timeout: timeout in seconds the fuzzing process has.
    :param fuzzing_max_attempts: maximal number of fuzzing attempts (in order to prevent infinity loops).
    :return: Set of FunctionOutput.
    """

    entropy_output_dsts = set()
    input_data_type_rule_gen = InputDataTypeRuleGenerator()
    while True:

        output_dsts, input_data_type_rule_gen = create_candidate_data(binary_file,
                                                                      fct_start,
                                                                      fct_ends,
                                                                      input_regs,
                                                                      min_size_data=min_size_data,
                                                                      output_threshold=output_threshold,
                                                                      single_run_timeout=single_run_timeout,
                                                                      fuzzing_timeout=fuzzing_timeout,
                                                                      fuzzing_max_attempts=fuzzing_max_attempts,
                                                                      input_data_type_rule_gen=input_data_type_rule_gen)

        if output_dsts:

            # If we could generate random looking data, check if it has enough entropy
            # to be a PRNG.
            for output_dst in output_dsts:
                if check_entropy(output_dst):
                    entropy_output_dsts.add(output_dst)
            # If we could generae random looking data, but the entropy check failed, perhaps
            # the PRNG was wrongly seeded (such is the case for rc4 in libtomcrypt). Retry data
            # generation with the next input rule.
            if not entropy_output_dsts:
                input_data_type_rule_gen.next()
                continue

            # Store the setting of input arguments.
            for entropy_output_dst in entropy_output_dsts:
                for unicorn_op, input_reg_obj in input_regs.items():
                    entropy_output_dst.used_input_regs[unicorn_op] = RegisterInput.from_obj(input_reg_obj)

        # If we could not generate any random looking data, do not further attempt to generate it.
        break

    return entropy_output_dsts
