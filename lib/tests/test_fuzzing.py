from lib.ssa import ssa_operand
from lib.arch.x64 import RegistersX64
from lib.emulation.core import RegisterInputType, EndInstructionType, FunctionEnds, FunctionEnd, InputDataTypeRule, RegisterInput
from lib.emulation.random import create_candidate_data_run, CandidateErrorCodes


def test_regression_fuzzing() -> bool:
    """
    Tests the fuzzing capability of the emulation.
    """

    print("Testing fuzzing.")

    test_cases = list()
    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/fuzzing_regression_tests/test_O0",
        "function_addr": 0x400661,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory},
        "function_ends": {0x40067D: {"valid": False,
                                     "type": EndInstructionType.Ret
                                     },
                          0x4006CB: {"valid": False,
                                     "type": EndInstructionType.Ret
                                     },
                          0x4006C1: {"valid": False,
                                     "type": EndInstructionType.Ret
                                     },
                          0x4006D1: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     }
                          }
        })
    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/fuzzing_regression_tests/test_O3",
        "function_addr": 0x400720,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory},
        "function_ends": {0x40075F: {"valid": False,
                                     "type": EndInstructionType.Ret
                                     },
                          0x400755: {"valid": False,
                                     "type": EndInstructionType.Ret
                                     },
                          0x40074B: {"valid": False,
                                     "type": EndInstructionType.Ret
                                     },
                          0x400745: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     }
                          }
        })
    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/nettle/test_cases/yarrow",
        "function_addr": 0x400E00,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 0x10},
        "function_ends": {0x400F23: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          0x400F7A: {"valid": False,
                                     "type": EndInstructionType.Call
                                     },
                          0x400F75: {"valid": False,
                                     "type": EndInstructionType.Call
                                     }
                          }
        })

    failed_tests = list()
    for test_case in test_cases:
        binary_file = test_case["binary_file"]

        print("\nTesting binary '%s'" % binary_file)

        function_addr = test_case["function_addr"]
        print("Testing function %08x" % function_addr)

        # Parse function ends.
        function_ends = FunctionEnds()
        for addr, fct_end_dict in test_case["function_ends"].items():
            fct_end = FunctionEnd(addr, fct_end_dict["type"], fct_end_dict["valid"])
            function_ends.add(fct_end)

        # Set emulator input registers.
        emu_input_regs = dict() # type: Dict[int, RegisterInput]
        for arg_reg_ssa, input_type in test_case["input_regs"].items():
            unicorn_op = RegistersX64.to_unicorn(arg_reg_ssa.index)
            emu_input_regs[unicorn_op] = RegisterInput(unicorn_op, input_type, InputDataTypeRule.Zero)

            if "values" in test_case.keys():
                if arg_reg_ssa in test_case["values"].keys():
                    emu_input_regs[unicorn_op].set_value(test_case["values"][arg_reg_ssa])

        error_code, output_dsts = create_candidate_data_run(binary_file,
                                                            function_addr,
                                                            function_ends,
                                                            emu_input_regs,
                                                            min_size_data=4)
        if error_code == CandidateErrorCodes.SUCCESS:
            print("Test passed.")
            continue

        print("Test failed.")
        failed_tests.append((function_addr, binary_file))

    if failed_tests:
        print("Overall failed tests for fuzzing.")
        for failed_test in failed_tests:
            print("%08x - %s" % (failed_test[0], failed_test[1]))
        return False
    return True
