from lib.emulation.core import RegisterInputType, EndInstructionType, FunctionEnds, FunctionEnd, InputDataTypeRule, RegisterInput
from lib.ssa import ssa_operand
from lib.arch.x64 import RegistersX64
from lib.emulation.random import create_entropy_data
from typing import Dict


def test_regression_entropy():
    """
    Tests entropy checking for some candidates.
    """

    print("Testing entropy of candidates.")

    test_cases = list()

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/randomc/binary_o3/ex-ran",
        "function_addr": 0x400CE0,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory
                       },
        "function_ends": {0x400DE4: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     }
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/randomc/binary_o3/ex-ran",
        "function_addr": 0x400DF0,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory
                       },
        "function_ends": {0x400F03: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     }
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/randomc/binary_o3/ex-ran",
        "function_addr": 0x400F10,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 0,
                   ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read): 0x0fffffff
                   },
        "function_ends": {0x401075: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          0x400F1C: {"valid": False,
                                     "type": EndInstructionType.Ret
                                     }
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
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
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 8
                   },
        "function_ends": {0x400F23: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          0x400F7A: {"valid": False,
                                     "type": EndInstructionType.Call
                                     },
                          0x400F75: {"valid": False,
                                     "type": EndInstructionType.Call
                                     }
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/mongodb-3.2.4+vtv/mongod",
        "function_addr": 0x212DDD0,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory
                       },
        "function_ends": {0x212DE28: {"valid": True,
                                      "type": EndInstructionType.Ret
                                      },
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/fortuna/fortuna",
        "function_addr": 0x401830,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 8
                   },
        "function_ends": {0x401AF4: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          0x401D5F: {"valid": False,
                                     "type": EndInstructionType.Call
                                     },
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/chacha20/chacha20",
        "function_addr": 0x401070,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 8
                   },
        "function_ends": {0x4010B9: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          0x401091: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/rc4/rc4",
        "function_addr": 0x4010E0,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 8
                   },
        "function_ends": {0x401101: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          0x401129: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/sober128/sober128",
        "function_addr": 0x401050,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 8
                   },
        "function_ends": {0x401071: {"valid": False,
                                     "type": EndInstructionType.Ret
                                     },
                          0x401099: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 20,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libsodium/test_cases/random",
        "function_addr": 0x401C50,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 8
                   },
        "function_ends": {0x401D41: {"valid": False,
                                     "type": EndInstructionType.Call
                                     },
                          0x401CE1: {"valid": False,
                                     "type": EndInstructionType.Call
                                     },
                          0x401D07: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          0x401CCD: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x6E3810,  # php_random_bytes
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 8
                   },
        "function_ends": {0x6E39A0: {"valid": False,
                                     "type": EndInstructionType.Call
                                     },
                          0x6E38FC: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x5084F0,  # unixRandomness
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 8
                   },
        "function_ends": {0x5085C1: {"valid": False,
                                     "type": EndInstructionType.Call
                                     },
                          0x50858D: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x6A9670,  # php_mt_rand
        "input_regs": {},
        "values": {},
        "function_ends": {0x6A96DB: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x69DDA0,  # php_combined_lcg
        "input_regs": {},
        "values": {},
        "function_ends": {0x69DE73: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          0x69DF04: {"valid": False,
                                     "type": EndInstructionType.Call
                                     },
                          },
        "single_run_timeout": 5,
        "fuzzing_timeout": 5,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libgcrypt/test_cases/libgcrypt.so.20.2.4",
        "function_addr": 0xC81A0,  # mix_pool
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        "values": {},
        "function_ends": {0xC8341: {"valid": True,
                                    "type": EndInstructionType.Ret
                                    },
                          0xC83F0: {"valid": False,
                                    "type": EndInstructionType.Call
                                    },
                          0xC83C8: {"valid": False,
                                    "type": EndInstructionType.Call
                                    },
                          },
        "single_run_timeout": 20,
        "fuzzing_timeout": 20,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/openssl/test_cases/libcrypto/libcrypto.so.1.1",
        "function_addr": 0x190440,  # OPENSSL_ia32_rdrand_bytes
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read): 8
                   },
        "function_ends": {0x190496: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          },
        "single_run_timeout": 20,
        "fuzzing_timeout": 20,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/botan/test_cases/pdrand/pdrand",
        "function_addr": 0x401570,  # HMAC_DRBG::randomize
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       },
        "values": {ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read): 8
                   },
        "function_ends": {0x4015C7: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          0x401604: {"valid": True,
                                     "type": EndInstructionType.Ret
                                     },
                          },
        "single_run_timeout": 20,
        "fuzzing_timeout": 20,
    })

    min_size_data = 400000

    failed_tests = list()
    for test_case in test_cases:
        binary_file = test_case["binary_file"]
        fct_start = test_case["function_addr"]
        single_run_timeout = test_case["single_run_timeout"]
        fuzzing_timeout = test_case["fuzzing_timeout"]

        print("\nTesting function %08x of binary '%s'." % (fct_start, binary_file))

        # Parse function ends.
        function_ends = FunctionEnds()
        for addr, fct_end_dict in test_case["function_ends"].items():
            fct_end = FunctionEnd(addr, fct_end_dict["type"], fct_end_dict["valid"])
            function_ends.add(fct_end)

        # Set emulator input registers.
        emu_input_regs = dict()  # type: Dict[int, RegisterInput]
        for arg_reg_ssa, input_type in test_case["input_regs"].items():
            unicorn_op = RegistersX64.to_unicorn(arg_reg_ssa.index)
            emu_input_regs[unicorn_op] = RegisterInput(unicorn_op, input_type, InputDataTypeRule.Zero)

            if "values" in test_case.keys():
                if arg_reg_ssa in test_case["values"].keys():
                    emu_input_regs[unicorn_op].set_value(test_case["values"][arg_reg_ssa])

        output_dsts = create_entropy_data(binary_file,
                                          fct_start,
                                          function_ends,
                                          emu_input_regs,
                                          min_size_data=min_size_data,
                                          single_run_timeout=single_run_timeout,
                                          fuzzing_timeout=fuzzing_timeout)

        if output_dsts:
            print("Test passed.")
        else:
            print("Test failed (emulation).")
            failed_tests.append((fct_start, binary_file))

    if failed_tests:
        print("Overall failed tests for entropy of candidates.")
        for failed_test in failed_tests:
            print("%08x - %s" % (failed_test[0], failed_test[1]))
        return False
    return True
