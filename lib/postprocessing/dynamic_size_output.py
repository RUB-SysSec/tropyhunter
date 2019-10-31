from ..emulation.random import create_candidate_data_preparation, create_candidate_data_emulation, CandidateErrorCodes
from ..emulation.core import FunctionEnds, FunctionOutput
from ..emulation.emulation import *
from typing import Dict


def set_dynamic_size_output(binary_file: str,
                            fct_addr: int,
                            fct_ends: FunctionEnds,
                            input_regs: Dict[int, RegisterInput],
                            target_output_dst: FunctionOutput,
                            single_run_timeout: int = 20,
                            fuzzing_timeout: int = 20,
                            fuzzing_max_attempts: int = 500):
    """
    Returns if an output destination has a dynamic size.

    :param binary_file: path to the binary executable.
    :param fct_addr: address of the function to test.
    :param fct_ends: Function endings.
    :param input_regs: input registers (cannot contain "Unknown" input type).
    :param target_output_dst: output destination we want to test.
    :param single_run_timeout: timeout in seconds a single run has.
    :param fuzzing_timeout: timeout in seconds the fuzzing process has.
    :param fuzzing_max_attempts: maximal number of fuzzing attempts (in order to prevent infinity loops).
    :return: Returns True if the given output destination has a size argument.
    """

    print("Checking for dynamic size output.")

    # Get all possible size arguments.
    possible_length_args = list()
    for _, input_arg in input_regs.items():
        if input_arg.input_type == RegisterInputType.Value:
            possible_length_args.append(input_arg)
    if not possible_length_args:
        return False

    # Create a working emulator environment and memory layout.
    for _ in range(20):
        mu, emu_env = create_candidate_data_preparation(binary_file,
                                                        fct_addr,
                                                        fct_ends,
                                                        single_run_timeout,
                                                        fuzzing_timeout)

        # Reset input arguments.
        for _, input_arg in input_regs.items():
            input_arg.del_value()

        error_code, output_dsts = create_candidate_data_emulation(binary_file,
                                                                  mu,
                                                                  emu_env,
                                                                  fct_addr,
                                                                  input_regs,
                                                                  1000,
                                                                  5,
                                                                  fuzzing_max_attempts)

        if error_code != CandidateErrorCodes.SUCCESS:
            print("Creating working memory layout failed (error code). Retrying.")
            continue

        correct_output = False
        for output_dst in output_dsts:
            if (output_dst.register == target_output_dst.register
               and output_dst.output_type == target_output_dst.output_type):
                correct_output = True
                break
        if not correct_output:
            print("Creating working memory layout failed (wrong output destination). Retrying.")
            continue

        print("Successfully created working memory layout.")
        break

    # Check different sizes in order to see if we have a dynamic size argument.
    test_sizes = [8, 16, 32, 64, 128, 256, 512, 1024]
    for test_size in test_sizes:

        print("Test dynamic size of: %d" % test_size)

        # Set the size we want to generate.
        for input_arg in possible_length_args:
            input_arg.set_value(test_size)

        has_dyn_size = check_dynamic_size(mu,
                                          emu_env,
                                          fct_addr,
                                          input_regs,
                                          target_output_dst,
                                          test_size)
        if not has_dyn_size:
            target_output_dst.dyn_size = False
            return

    target_output_dst.dyn_size = True


def check_dynamic_size(mu: Uc,
                       emu_env: EmulatorEnv,
                       fct_addr: int,
                       input_regs: Dict[int, RegisterInput],
                       target_output_dst: FunctionOutput,
                       target_size: int) -> bool:

    # Rebase address (if needed).
    fct_addr += emu_env.rebase_addr

    # Extract memory content before emulation.
    addr = input_regs[target_output_dst.register].value
    output_before = mu.mem_read(addr, target_size)
    behind_output_before = mu.mem_read(addr+target_size, 8)

    # Extract memory content after emulation.
    emulate_function(mu, emu_env, fct_addr, input_regs)
    output_after = mu.mem_read(addr, target_size)
    behind_output_after = mu.mem_read(addr + target_size, 8)

    # Check if something was written directly behind output destination pointer (meaning ptr addr + size)
    # in order to see we could give a size.
    if behind_output_before != behind_output_after:
        print("Data behind destination changed.")
        return False

    # Check if we have too many equal bytes in the same position.
    equal_ctr = 0
    for i in range(target_size):
        if output_before[i] == output_after[i]:
            equal_ctr += 1
    if equal_ctr > (target_size/2):
        print("Too few bytes have changed.")
        return False

    return True
