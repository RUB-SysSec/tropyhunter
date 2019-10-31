import itertools
import time
from typing import Dict, Any, List, DefaultDict, Optional, Tuple
from unicorn.x86_const import *
from unicorn import Uc, UC_HOOK_BLOCK
from .core import EmulatorEnv, FuzzingMemoryLocation, InputDataTypeRule, RegisterInput
from .emulation import emulate_function


def fuzzing_generate_rounds(fuzzing_mem_locations_list: List[FuzzingMemoryLocation]) -> Any:
    """
    Generate different fuzzing rounds for each memory location.

    :param fuzzing_mem_locations_list: a list of all memory locations for fuzzing.
    :return: a generator for fuzzing rounds.
    """

    fuzzing_rules = [InputDataTypeRule.Zero,
                     InputDataTypeRule.One,
                     InputDataTypeRule.RandomPlus,
                     InputDataTypeRule.RandomMinus]
    fuzzing_rounds = itertools.product(fuzzing_rules, repeat=len(fuzzing_mem_locations_list))

    return fuzzing_rounds


def fuzzing_generate_mem_locations(emu_env: EmulatorEnv,
                                   fuzzing_mem_locations_list: List[FuzzingMemoryLocation]) -> List[FuzzingMemoryLocation]:
    """
    Generate different fuzzing rounds for each memory location read from.

    :param emu_env: emulation environment.
    :param fuzzing_mem_locations_list: a list of all memory locations for fuzzing.
    :return: a list of all memory locations for fuzzing.
    """

    fuzzing_mem_locations_set = set(fuzzing_mem_locations_list)

    # Extract fuzzing locations for read memory locations.
    for runtime_mem_obj in emu_env.runtime_memory_objs:

        for mem_read_addr, mem_read_objs in runtime_mem_obj.read_accesses.items():

            # Ignore reads from relocation entries to not fuck up the execution
            # (e.g., changing a function pointer the GOT).
            if mem_read_addr in emu_env.relocation_addrs:
                continue

            # Get largest memory read object that is read before it was written.
            candidate_mem_read_objs = list(filter(lambda x: x.is_read_before_write, mem_read_objs))
            if not candidate_mem_read_objs:
                continue
            mem_read_obj = candidate_mem_read_objs[0]
            for temp_mem_read_obj in candidate_mem_read_objs:
                if temp_mem_read_obj.size > mem_read_obj.size:
                    mem_read_obj = temp_mem_read_obj

            # TODO this can also change parts of read-only data (code, rodata, ...) we have to check for this

            fuzzing_mem_locations_set.add(FuzzingMemoryLocation(mem_read_addr, mem_read_obj.size))

    # Generate fuzzing rounds from the set of rules.
    fuzzing_mem_locations_list = list(fuzzing_mem_locations_set)

    return fuzzing_mem_locations_list


def fuzzing_end_point(mu: Uc, emu_env: EmulatorEnv, fct_start: int, input_regs: Dict[int, RegisterInput]) -> bool:
    """
    Performs fuzzing of the memory locations to reach a valid function end point.

    :param mu: unicorn instance.
    :param emu_env: emulation environment.
    :param fct_start: function start address.
    :param input_regs: input registers.
    :return: returns True if a valid function end point was reached.
    """
    if emu_env.debug_disable_fuzzing_end_point:
        return False

    fuzzing_last_end_addrs = set()
    fuzzing_curr_mem_locations_list = list()
    fuzzing_next_mem_locations_list = list()
    last_end_addr = mu.reg_read(UC_X86_REG_RIP)

    emu_env.fuzzing_start_time = int(time.time())
    emu_env.fuzzing_is_timeout = False
    emu_env.fuzzing_used_end_point = True

    do_fuzzing = True
    while do_fuzzing:
        do_fuzzing = False

        # Generate fuzzing rules.
        old_number_mem_objs = len(fuzzing_curr_mem_locations_list)
        fuzzing_curr_mem_locations_list = fuzzing_generate_mem_locations(emu_env, fuzzing_next_mem_locations_list)
        fuzzing_rounds = fuzzing_generate_rounds(fuzzing_curr_mem_locations_list)

        # Start fuzzing the actual function with the provided rules.
        emu_env.runtime_memory_changes = set()
        for fuzzing_round in fuzzing_rounds:

            # Check if we run our fuzzing approach for too long.
            curr_time = int(time.time())
            if (curr_time - emu_env.fuzzing_start_time) > emu_env.fuzzing_timeout:
                print("Fuzzing timeout limit reached. Stopping it.")
                emu_env.fuzzing_is_timeout = True
                return False

            for i in range(len(fuzzing_round)):
                fuzz_mem_obj = fuzzing_curr_mem_locations_list[i]
                fuzz_rule_type = fuzzing_round[i]
                fuzz_mem_obj.fuzz_type = fuzz_rule_type
                emu_env.runtime_memory_changes.add(fuzz_mem_obj)

            emu_success = emulate_function(mu, emu_env, fct_start, input_regs)
            fuzzing_next_mem_locations_list = fuzzing_generate_mem_locations(emu_env, fuzzing_next_mem_locations_list)

            # Continue fuzzing if emulation was not successful.
            if not emu_success:
                continue

            # Stop fuzzing rounds if we ended up in an instruction we did not fuzz before.
            last_end_addr = mu.reg_read(UC_X86_REG_RIP)
            if last_end_addr not in fuzzing_last_end_addrs:
                break

        # Check if the current memory configuration ended in a valid end instruction.
        if emu_env.fct_ends.end_valid(last_end_addr):
            return True

        # If we do not have reached this end address before or we have found new memory read locations
        # we did not have seen before start fuzzing.
        if (last_end_addr not in fuzzing_last_end_addrs
                or len(fuzzing_curr_mem_locations_list) > old_number_mem_objs):
            fuzzing_last_end_addrs.add(last_end_addr)
            do_fuzzing = True

    return False


def fuzzing_coverage(mu: Uc, emu_env: EmulatorEnv, fct_start: int, input_regs: Dict[int, RegisterInput]):
    """
    Performs fuzzing of the memory locations to reach at least one new basic block.

    :param mu: unicorn instance.
    :param emu_env: emulation environment.
    :param fct_start: function start address.
    :param input_regs: input registers.
    :return: returns True if a new basic block was discovered.
    """
    if emu_env.debug_disable_fuzzing_coverage:
        return False

    # Store old basic block coverage result of our previous fuzzing runs.
    old_fuzzing_basic_blocks = set(emu_env.basic_block_coverage)
    fuzzing_curr_mem_locations_list = list()
    fuzzing_next_mem_locations_list = list()

    emu_env.fuzzing_start_time = int(time.time())
    emu_env.fuzzing_is_timeout = False
    emu_env.fuzzing_used_coverage = True

    do_fuzzing = True
    while do_fuzzing:
        do_fuzzing = False

        # Generate fuzzing rules.
        old_number_mem_objs = len(fuzzing_curr_mem_locations_list)
        fuzzing_curr_mem_locations_list = fuzzing_generate_mem_locations(emu_env, fuzzing_next_mem_locations_list)
        fuzzing_rounds = fuzzing_generate_rounds(fuzzing_curr_mem_locations_list)

        # Start fuzzing the actual function with the provided rules.
        emu_env.runtime_memory_changes = set()
        for fuzzing_round in fuzzing_rounds:

            # Check if we run our fuzzing approach for too long.
            curr_time = int(time.time())
            if (curr_time - emu_env.fuzzing_start_time) > emu_env.fuzzing_timeout:
                print("Fuzzing timeout limit reached. Stopping it.")
                emu_env.fuzzing_is_timeout = True
                return False

            for i in range(len(fuzzing_round)):
                fuzz_mem_obj = fuzzing_curr_mem_locations_list[i]
                fuzz_rule_type = fuzzing_round[i]
                fuzz_mem_obj.fuzz_type = fuzz_rule_type
                emu_env.runtime_memory_changes.add(fuzz_mem_obj)

            emu_success = emulate_function(mu, emu_env, fct_start, input_regs)
            fuzzing_next_mem_locations_list = fuzzing_generate_mem_locations(emu_env, fuzzing_next_mem_locations_list)

            # Continue fuzzing if emulation was not successful.
            if not emu_success:
                continue

            # Stop fuzzing rounds if we ended up using a new basic block.
            if len(emu_env.basic_block_coverage) > len(old_fuzzing_basic_blocks):
                return True

        # If we have found new memory read locations
        # we did not have seen before start fuzzing.
        if len(fuzzing_curr_mem_locations_list) > old_number_mem_objs:
            do_fuzzing = True

    return False



