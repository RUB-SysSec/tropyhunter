from .emulation.random import create_entropy_data
from .emulation.core import RegisterInputType, InputDataTypeRule, RegisterInput, FunctionEnds, FunctionOutput
from .arch.x64 import RegistersX64
from typing import Dict, Set
import itertools


def execute_function(binary_file: str,
                     fct_addr: int,
                     fct_ends: FunctionEnds,
                     input_args: Dict[int, int],
                     min_size_data: int = 400000,
                     output_threshold: int = 5,
                     single_run_timeout: int = 20,
                     fuzzing_timeout: int = 20,
                     fuzzing_max_attempts: int = 500) -> Set[FunctionOutput]:
    """
    Tries to create output data for the given function address which passes the entropy check for the
    given input arguments (can contain "Unknown" input type).

    :param binary_file: path to the binary executable.
    :param fct_addr: address of the function to test.
    :param fct_ends: Function endings.
    :param input_args: input registers (can contain "Unknown" input type).
    :param min_size_data: minimum of data in bytes the emulation should create.
    :param output_threshold: number of times the output can be duplicated before it is dismissed.
    :param single_run_timeout: timeout in seconds a single run has.
    :param fuzzing_timeout: timeout in seconds the fuzzing process has.
    :param fuzzing_max_attempts: maximal number of fuzzing attempts (in order to prevent infinity loops).
    :return: Set of FunctionOutput.
    """
    # Count number of "Unknown" argument types.
    input_reg_str = ""
    num_unknown = 0
    for arg_reg_unicorn, access_type in input_args.items():
        input_reg_str += RegistersX64.from_unicorn_to_str(arg_reg_unicorn)
        input_reg_str += " (%s); " % RegisterInputType.to_str(access_type)
        if access_type == RegisterInputType.Unknown:
            num_unknown += 1
    print("Processing input registers: %s" % input_reg_str)

    # Create all possible combinations for registers with the type "Unknown".
    # IMPORTANT: if no "Unknown" type exists, a list with an empty tuple is returned which results
    # in a one time emulation of the function (exactly what we want).
    unknown_types = list(itertools.product(RegisterInputType.possible_for_unknown, repeat=num_unknown))
    for unknown_type_idx in range(len(unknown_types)):
        unknown_type = unknown_types[unknown_type_idx]

        # Create register input rules for the current round of emulation.
        emu_input_regs = dict()  # type: Dict[int, RegisterInput]
        unknown_reg_idx = 0
        input_reg_str = ""
        for unicorn_op, access_type in input_args.items():
            if unicorn_op not in emu_input_regs.keys():
                if access_type == RegisterInputType.Unknown:
                    access_type = unknown_type[unknown_reg_idx]
                    unknown_reg_idx += 1
                emu_input_regs[unicorn_op] = RegisterInput(unicorn_op, access_type, InputDataTypeRule.Zero)
                input_reg_str += RegistersX64.from_unicorn_to_str(unicorn_op)
                input_reg_str += " (%s); " % RegisterInputType.to_str(access_type)

        # Create random data stream.
        print("Starting function emulation (minimum %d bytes) with input arguments: %s"
              % (min_size_data, input_reg_str))

        output_dsts = create_entropy_data(binary_file,
                                          fct_addr,
                                          fct_ends,
                                          emu_input_regs,
                                          min_size_data=min_size_data,
                                          output_threshold=output_threshold,
                                          single_run_timeout=single_run_timeout,
                                          fuzzing_timeout=fuzzing_timeout,
                                          fuzzing_max_attempts=fuzzing_max_attempts)

        print("Finished function emulation.")

        if output_dsts:
            for output_dst in output_dsts:
                # Store all data into file.
                output_dst.store_to_file()

                # Store the originally inferred input registers.
                for unicorn_op, access_type in input_args.items():
                    output_dst.inferred_input_regs[unicorn_op] = RegisterInput(unicorn_op, access_type, InputDataTypeRule.Zero)

            return output_dsts
    return set()
