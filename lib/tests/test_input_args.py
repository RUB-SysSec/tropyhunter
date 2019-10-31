from playground2 import get_input_regs
from lib.arch.x64 import RegistersX64
from lib import import_ssa
from lib.ssa import ssa_operand
from lib.emulation.core import RegisterInputType


def test_regression_input_args() -> bool:
    """
    Regression test for input argument extraction.
    """

    print("Testing input argument extraction.")

    test_cases = list()

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
        })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/randomc/binary_o3/ex-ran",
        "function_addr": 0x400DF0,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                          RegisterInputType.Memory
                      },
        })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/randomc/binary_o3/ex-ran",
        "function_addr": 0x400CE0,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                          RegisterInputType.Memory
                      },
        })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/randomc/binary/ex-ran",
        "function_addr": 0x40097C,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                          RegisterInputType.Memory
                      },
        })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/mongodb-3.2.4+vtv/mongod",
        "function_addr": 0x212DDD0,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                          RegisterInputType.Memory,
                     },
        })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/openssl/test_cases/rand_pseudo_bytes",
        "function_addr": 0x401710,
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Unknown,
                       ssa_operand.RegisterX64SSA(RegistersX64.rcx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Unknown,
                       },
        })
    
    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/openssl/test_cases/libcrypto/libcrypto.so.1.1",
        "function_addr": 0x190440,  # OPENSSL_ia32_rdrand_bytes
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       },
        })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/nettle/test_cases/yarrow",
        "function_addr": 0x400E00,  # nettle_yarrow256_random
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libgcrypt/test_cases/libgcrypt.so.20.2.4",
        "function_addr": 0xC81A0,  # mix_pool
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x5084F0,  # unixRandomness
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Unknown, # Since the first argument is not used in the function
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/chacha20/chacha20",
        "function_addr": 0x4020D0,  # chacha_crypt
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rcx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/fortuna/fortuna",
        "function_addr": 0x401830,  # fortuna_read
        "input_regs": {ssa_operand.RegisterX64SSA(RegistersX64.rdi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       ssa_operand.RegisterX64SSA(RegistersX64.rsi, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Value,
                       ssa_operand.RegisterX64SSA(RegistersX64.rdx, 0, ssa_operand.OperandAccessType.Read):
                           RegisterInputType.Memory,
                       },
        })

    failed_tests = list()
    for test_case in test_cases:
        binary_file = test_case["binary_file"]

        print("\nTesting binary '%s'" % binary_file)

        # Import SSA data.
        functions_ssa = import_ssa(binary_file)

        function_addr = test_case["function_addr"]
        print("Testing function %08x" % function_addr)

        function_ssa = functions_ssa[function_addr]
        input_args = get_input_regs(binary_file, function_ssa)
        gt_input_args = test_case["input_regs"]

        # Check if argument registers and access type are correct.
        failed = False
        for arg_reg_ssa, access_type in input_args.items():
            if arg_reg_ssa not in gt_input_args.keys():
                failed = True
                break
            if access_type != gt_input_args[arg_reg_ssa]:
                failed = True
                break

        if not failed:
            print("Test passed.")
            continue
        else:
            failed_tests.append((function_addr, binary_file))

        # Prepare input registers.
        input_reg_str = ""
        for arg_reg_ssa, access_type in input_args.items():
            input_reg_str += str(arg_reg_ssa)
            input_reg_str += " (%s); " % RegisterInputType.to_str(access_type)

        gt_input_reg_str = ""
        for arg_reg_ssa, access_type in gt_input_args.items():
            gt_input_reg_str += str(arg_reg_ssa)
            gt_input_reg_str += " (%s); " % RegisterInputType.to_str(access_type)

        print("Test failed.")
        print("Found input registers: %s" % input_reg_str)
        print("Needed input registers: %s" % gt_input_reg_str)

    if failed_tests:
        print("Overall failed tests for argument extraction.")
        for failed_test in failed_tests:
            print("%08x - %s" % (failed_test[0], failed_test[1]))
        return False
    return True
