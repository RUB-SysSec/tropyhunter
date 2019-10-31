from lib.input_args_extraction import get_input_regs, convert_input_args_ssa_to_unicorn
from lib.executer import execute_function
from lib import import_ssa
from lib.function_end_extraction import get_function_ends


def test_regression_execution():
    """
    Tests automatic execution of candidates.
    """

    print("Testing automatic execution of candidates.")

    test_cases = list()

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/randomc/binary_o3/ex-ran",
        "function_addr": 0x400CE0, # CRandomMersenne::BRandom
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/randomc/binary_o3/ex-ran",
        "function_addr": 0x400DF0, # CRandomMersenne::Random
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/nettle/test_cases/libnettle/libnettle.so.6.4",
        "function_addr": 0x16600, # nettle_knuth_lfib_random
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/nettle/test_cases/libnettle/libnettle.so.6.4",
        "function_addr": 0x25EB0, # nettle_yarrow256_random
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/mongodb-3.2.4+vtv/mongod",
        "function_addr": 0x212DDD0, # _wt_random
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/fortuna/fortuna",
        "function_addr": 0x401830, # fortuna_read
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/chacha20/chacha20",
        "function_addr": 0x401070, # chacha20_prng_read
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/rc4/rc4",
        "function_addr": 0x4010E0, # rc4_read
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/sober128/sober128",
        "function_addr": 0x401050, # sober128_read
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/libtomcrypt/libtomcrypt.so.1.0.1",
        "function_addr": 0x9A650, # sober128_read
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/libtomcrypt/libtomcrypt.so.1.0.1",
        "function_addr": 0x98FE0, # fortuna_read
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/libtomcrypt/libtomcrypt.so.1.0.1",
        "function_addr": 0x99740, # rc4_read
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libtomcrypt/test_cases/libtomcrypt/libtomcrypt.so.1.0.1",
        "function_addr": 0x975D0, # chacha20_prng_read
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libsodium/test_cases/random",
        "function_addr": 0x401C50, # randombytes_sysrandom_buf
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libsodium/test_cases/libsodium/libsodium.so.23.1.0",
        "function_addr": 0x2C4C0, # randombytes_sysrandom_buf
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x6E3810,  # php_random_bytes
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x5084F0,  # unixRandomness
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x6A9670,  # php_mt_rand
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/php7/test_case/php",
        "function_addr": 0x69DDA0,  # php_combined_lcg
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libgcrypt/test_cases/libgcrypt.so.20.2.4",
        "function_addr": 0xC81A0,  # mix_pool
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/openssl/test_cases/libcrypto/libcrypto.so.1.1",
        "function_addr": 0x190440,  # OPENSSL_ia32_rdrand_bytes
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/botan/test_cases/pdrand/pdrand",
        "function_addr": 0x401570,  # HMAC_DRBG::randomize
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/ruby/test_cases/ruby",
        "function_addr": 0xF5620,  # genrand_int32
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/ruby/test_cases/ruby",
        "function_addr": 0xF7340,  # ruby_fill_random_bytes
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/wolfssl/test_cases/libwolfssl.so.19.1.0",
        "function_addr": 0xC9C0,  # Hash_DRBG_Generate
    })

    test_cases.append({
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libsodium/test_cases/libsodium/libsodium.so.23.1.0",
        "function_addr": 0x2C4C0, # randombytes_sysrandom_buf
    })

    '''
    test_cases.append({ # execution takes 15h to finish
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/libgcrypt/test_cases/libgcrypt.so.20.2.4",
        "function_addr": 0xccbd3,  # jent_read_entropy
    })
    
    test_cases.append({ # TODO does not work :(
        "binary_file": "/home/sqall/work/2018-binary-prngs/tests/botan/test_cases/libbotan/libbotan-2.so.8",
        "function_addr": 0x336E00,  # HMAC_DRBG::randomize_with_input
    })
    '''

    min_size_data = 400000
    ssa_loaded_for_file = ""
    failed_tests = list()
    functions_ssa = dict()
    for test_case in test_cases:
        binary_file = test_case["binary_file"]
        fct_start = test_case["function_addr"]

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

        # Get input arguments for the current function.
        input_args_ssa = get_input_regs(binary_file, function_ssa)
        input_args_unicorn = convert_input_args_ssa_to_unicorn(input_args_ssa)

        output_dsts = execute_function(binary_file,
                                       fct_start,
                                       function_ends,
                                       input_args_unicorn,
                                       min_size_data=min_size_data)

        if output_dsts:
            print("Test passed.")
        else:
            print("Test failed (emulation).")
            failed_tests.append((fct_start, binary_file))

    if failed_tests:
        print("Overall failed tests for automatic execution of candidates.")
        for failed_test in failed_tests:
            print("%08x - %s" % (failed_test[0], failed_test[1]))
        return False
    return True
