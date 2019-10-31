from lib.postprocessing.dynamic_size_output import set_dynamic_size_output
from lib import import_ssa
from lib.function_end_extraction import get_function_ends
from lib.emulation.core import RegisterInput, InputDataTypeRule, RegisterInputType, FunctionOutput, FunctionOutputType
from unicorn.x86_const import *

def test_regression_dyn_size():
    """
    Tests dynamic size evaluation.
    """

    print("Testing dynamic size evaluation of candidates.")

    test_cases = list()

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/botan/test_cases/pdrand/pdrand",
        "function_addr": 0x401570,  # HMAC_DRBG::randomize
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Value, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0x401570, FunctionOutputType.Pointer, UC_X86_REG_RSI),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/libtomcrypt/libtomcrypt.so.1.0.1",
        "function_addr": 0x9A650, # sober128_read
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.RandomPlus8Small),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Memory, InputDataTypeRule.RandomPlus8Small),
                       ],
        "output_dst": FunctionOutput(0x9A650, FunctionOutputType.Pointer, UC_X86_REG_RDI),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/libtomcrypt/libtomcrypt.so.1.0.1",
        "function_addr": 0x98FE0, # fortuna_read
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.RandomPlus8Small),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Memory, InputDataTypeRule.RandomPlus8Small),
                       ],
        "output_dst": FunctionOutput(0x98FE0, FunctionOutputType.Pointer, UC_X86_REG_RDI),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/libtomcrypt/libtomcrypt.so.1.0.1",
        "function_addr": 0x99740, # rc4_read
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Random),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Memory, InputDataTypeRule.Random),
                       ],
        "output_dst": FunctionOutput(0x99740, FunctionOutputType.Pointer, UC_X86_REG_RDI),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/libtomcrypt/libtomcrypt.so.1.0.1",
        "function_addr": 0x975D0, # chacha20_prng_read
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.RandomPlus8Small),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Memory, InputDataTypeRule.RandomPlus8Small),
                       ],
        "output_dst": FunctionOutput(0x975D0, FunctionOutputType.Pointer, UC_X86_REG_RDI),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x6E3810,  # php_random_bytes
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Value, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0x6E3810, FunctionOutputType.Pointer, UC_X86_REG_RDI),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x5084F0,  # unixRandomness
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0x5084F0, FunctionOutputType.Pointer, UC_X86_REG_RDX),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libgcrypt/test_cases/libgcrypt.so.20.2.4",
        "function_addr": 0xC81A0,  # mix_pool
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0x190440, FunctionOutputType.Pointer, UC_X86_REG_RDI),
        "expected_result": False,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/openssl/test_cases/libcrypto/libcrypto.so.1.1",
        "function_addr": 0x190440,  # OPENSSL_ia32_rdrand_bytes
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0x190440, FunctionOutputType.Pointer, UC_X86_REG_RDI),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/ruby/test_cases/ruby",
        "function_addr": 0xF5620,  # genrand_int32
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Random),
                       ],
        "output_dst": FunctionOutput(0xF5620, FunctionOutputType.Pointer, UC_X86_REG_RDI),
        "expected_result": False,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/ruby/test_cases/ruby",
        "function_addr": 0xF7340,  # ruby_fill_random_bytes
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Value, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0xF7340, FunctionOutputType.Pointer, UC_X86_REG_RDI),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/wolfssl/test_cases/libwolfssl.so.19.1.0",
        "function_addr": 0xC9C0,  # Hash_DRBG_Generate
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Value, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0xC9C0, FunctionOutputType.Pointer, UC_X86_REG_RSI),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libsodium/test_cases/libsodium/libsodium.so.23.1.0",
        "function_addr": 0x2C4C0, # randombytes_sysrandom_buf
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0x2C4C0, FunctionOutputType.Pointer, UC_X86_REG_RDI),
        "expected_result": True,
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/nettle/test_cases/libnettle/libnettle.so.6.4",
        "function_addr": 0x16600, # nettle_knuth_lfib_random
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.RandomPlus8Small),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Memory, InputDataTypeRule.RandomPlus8Small),
                       ],
        "output_dst": FunctionOutput(0x16600, FunctionOutputType.Pointer, UC_X86_REG_RDX),
        "expected_result": True,
    })
    
    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/nettle/test_cases/libnettle/libnettle.so.6.4",
        "function_addr": 0x25EB0, # nettle_yarrow256_random
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Value, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0x25EB0, FunctionOutputType.Pointer, UC_X86_REG_RDX),
        "expected_result": True,
    })

    '''
    test_cases.append({ # Fails because too many bits are equal when reaching 512 and 1024 bytes.
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libgcrypt/test_cases/libgcrypt.so.20.2.4",
        "function_addr": 0xccbd3,  # jent_read_entropy
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.RandomPlus8Small),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Value, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0xccbd3, FunctionOutputType.Pointer, UC_X86_REG_RSI),
        "expected_result": True,
    })
    
    
    test_cases.append({ # TODO does not work
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/botan/test_cases/libbotan/libbotan-2.so.8",
        "function_addr": 0x336E00,  # HMAC_DRBG::randomize_with_input
        "input_regs": [RegisterInput(UC_X86_REG_RDI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RSI, RegisterInputType.Memory, InputDataTypeRule.Zero),
                       RegisterInput(UC_X86_REG_RDX, RegisterInputType.Value, InputDataTypeRule.Zero),
                       ],
        "output_dst": FunctionOutput(0x336E00, FunctionOutputType.Pointer, UC_X86_REG_RSI),
        "expected_result": True,
    })
    '''

    ssa_loaded_for_file = ""
    failed_tests = list()
    functions_ssa = dict()
    for test_case in test_cases:
        binary_file = test_case["binary_file"]
        fct_start = test_case["function_addr"]
        output_dst = test_case["output_dst"]
        input_regs = dict()
        for input_reg in test_case["input_regs"]:
            input_regs[input_reg.uc_reg] = input_reg
        expected_result = test_case["expected_result"]

        print("\nTesting function %08x of binary '%s'." % (fct_start, binary_file))

        # Import SSA. However, to speed it up check if the last processed binary is
        # the same as the current one.
        if ssa_loaded_for_file != binary_file or not functions_ssa:
            functions_ssa = import_ssa(binary_file)
        else:
            print("SSA data already loaded. Skipping import.")
        ssa_loaded_for_file = binary_file

        function_ssa = functions_ssa[fct_start]

        # Get function ends.
        function_ends = get_function_ends(functions_ssa, function_ssa)

        set_dynamic_size_output(binary_file,
                                function_ssa.address,
                                function_ends,
                                input_regs,
                                output_dst)

        if expected_result == output_dst.dyn_size:
            print("Test passed.")
        else:
            print("Test failed (emulation).")
            failed_tests.append((fct_start, binary_file))

    if failed_tests:
        print("Overall failed tests for dynamic size evaluation of candidates.")
        for failed_test in failed_tests:
            print("%08x - %s" % (failed_test[0], failed_test[1]))
        return False
    return True
