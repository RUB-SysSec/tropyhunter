#!/usr/bin/env python

import os
import sys
import subprocess

import colorama


def styled(style):
    def styler(msg):
        return style + str(msg) + colorama.Style.RESET_ALL
    
    return styler


colorama.init()
good = styled(colorama.Fore.GREEN)
meh = styled(colorama.Fore.YELLOW)
bad = styled(colorama.Fore.RED + colorama.Style.BRIGHT)
blue = styled(colorama.Fore.CYAN)


IDAT_PATH = 'C:/Program Files/IDA 7.0/idat64.exe'
LOG_PATH = './log'

SCRIPT_BASE_PATH = os.path.dirname(os.path.realpath(__file__)) + os.path.sep
WRAPPER_PATH = SCRIPT_BASE_PATH + 'autom8_wrapper.py'

test_cases = [
    ('botan', 'libbotan', 'botan/test_cases/libbotan/libbotan-2.so.8', 6729, [
        (0x003377a0, False, 'Botan::RDRAND_RNG::rdrand_status'),
        (0x00337870, False, 'Botan::RDRAND_RNG::randomize'),
        (0x00336540, False, 'Botan::ChaCha_RNG::randomize_with_input'),
        (0x00336e00, False, 'Botan::HMAC_DRBG::randomize_with_input'),
    ]),
    ('crypto++', 'libcryptopp', 'crypto++/test_cases/libcryptopp/libcryptopp.so.7.0.0', 6809, [
        (0x003283c0, False, 'CryptoPP::RDRAND::GenerateBlock'),
        (0x003320b0, False, 'CryptoPP::LC_RNG::GenerateBlock'),
        (0x001ff460, False, 'CryptoPP::KDF2_RNG::GenerateBlock'),
        (0x002040a0, False, 'CryptoPP::Weak1::ARC4_Base::GenerateBlock'),
    ]),
    ('libgcrypt', 'libgcrypt', 'libgcrypt/test_cases/libgcrypt.so.20.2.4', 1368, [
        (0x000c81a0, True, 'mix_pool'),
        (0x000ccbd3, True, 'jent_read_entropy'),
        (0x000cc91a, True, 'jent_measure_jitter'),
        (0x000ccabb, True, 'jent_gen_entropy'),
        (0x000cc67c, True, 'jent_lfsr_time'),
    ]),
    ('libsodium', 'libsodium', 'libsodium/test_cases/libsodium/libsodium.so.23.1.0', 954, [
        (0x0002c4c0, True, 'randombytes_sysrandom_buf'),
        (0x00020da0, True, 'stream_ietf_ref'),
    ]),
    ('libtomcrypt', 'libtomcrypt', 'libtomcrypt/test_cases/libtomcrypt/libtomcrypt.so.1.0.1', 732, [
        (0x000975d0, True, 'chacha20_prng_read'),
        (0x00098fe0, True, 'fortuna_read'),
        (0x00099740, True, 'rc4_read'),
        (0x0009a650, True, 'sober128_read'),
        (0x0009b7a0, False, 'yarrow_read'),
    ]),
    ('nettle', 'libnettle', 'nettle/test_cases/libnettle/libnettle.so.6.4', 421, [
        (0x00025eb0, True, 'nettle_yarrow256_random'),
    ]),
    ('openssl', 'libcrypto', 'openssl/test_cases/libcrypto/libcrypto.so.1.1', 6128, [
        (0x00190440, True, 'OPENSSL_ia32_rdrand_bytes'),
        (0x001bd610, False, 'drbg_hash_generate'),
        (0x001bde10, False, 'drbg_hmac_generate'),
        (0x001bb370, False, 'drbg_ctr_generate'),
    ]),
    ('wolfssl', 'libwolfssl', 'wolfssl/test_cases/libwolfssl.so.19.1.0', 874, [
        (0x0000c9c0, True, 'Hash_DRBG_Generate'),
    ]),
    ('php7', 'php', 'php7/test_case/php', 9301, [
        (0x0069dda0, True, 'php_combined_lcg'),
        (0x006a9670, True, 'php_mt_rand'),
        (0x005084f0, True, 'unixRandomness'),
        (0x00523410, False, 'sqlite3_randomness'),
        (0x006e3810, True, 'php_random_bytes'),
    ]),
    ('ruby', 'ruby', 'ruby/test_cases/ruby', 5573, [
        (0x000f5620, True, 'genrand_int32'),
        (0x000f7340, True, 'ruby_fill_random_bytes'),
    ]),
    
    # this should be last because it takes ages to process it
    ('mongodb-3.2.4+vtv', 'mongod', 'mongodb-3.2.4+vtv/mongod', 43566, [
        (0x0212ddd0, True, '__wt_random'),
    ]),
]


def read_found_funcs(output_name):
    """
    Parses a preselection output file.
    """
    found_funcs = []
    with open(output_name, 'r') as f:
        for line in f:
            line = line.strip()
            
            if line == '':
                continue
            
            func = int(line, 16)
            found_funcs.append(func)
        
    return found_funcs


def run_test_cases(test_cases, script_path):
    """
    Runs the given script on the given test cases.
    """
    print('Running {} on all test cases:'.format(os.path.basename(script_path)))
    for i, (lib_name, test_case_name, idb_path, func_count, functions_must_find) in enumerate(test_cases):
        print('  - {}/{}: {}'.format(i + 1, len(test_cases), lib_name))
        output_name = '{}_{}'.format(lib_name, test_case_name).lower().replace(' ', '_')
        success = run_script('tests/' + idb_path, script_path, output_name)
        
        if success:
            output_funcs_file = os.path.basename(idb_path) + '_funcs.txt'
            found_funcs = read_found_funcs(output_funcs_file)
            found_funcs_count = len(found_funcs)
            found_funcs_percentage = '{:.0f}%'.format(100 * found_funcs_count / float(func_count))
            print('    - Found {}/{} ({})'.format(blue(found_funcs_count), func_count, blue(found_funcs_percentage)))
            for func_addr, required, func_name in functions_must_find:
                if func_addr in found_funcs:
                    status = good('Found     ')
                elif required:
                    status = bad('NOT Found!')
                else:
                    status = meh('NOT Found!')
                print('    - 0x{:08x}: {} ({})'.format(func_addr, status, func_name))


def run_script(idb_path, script_path, args=''):
    """
    Runs the given script on the given IDA database.
    """
    log_file = make_path_os_specific(get_log_file_path(idb_path))
    wrapper_path_specific = make_path_os_specific(WRAPPER_PATH)
    script_path_specific = make_path_os_specific(script_path)
    wrapper_cmd = '"{}" "{}"'.format(wrapper_path_specific, script_path_specific)
    cmd = [
        make_path_os_specific(IDAT_PATH),    # the path of the idat executable
        '-A',                                # run in autonomous mode
        '-L{}'.format(log_file),             # log to this file
        '-S{} {}'.format(wrapper_cmd, args), # use this script
        make_path_os_specific(idb_path),     # on this IDA db
    ]
    ret = subprocess.call(cmd)
    if ret != 0:
        print(bad('    Returned {}'.format(ret)))
        return False
    
    return True


def get_log_file_path(idb_path):
    """
    Returns the log file path for an IDA database path.
    """
    dirname = os.path.dirname(idb_path) if LOG_PATH is None else LOG_PATH
    idb_name = os.path.basename(idb_path)
    log_name = os.path.splitext(idb_name)[0] + '_log.txt'
    log_file = dirname + os.path.sep + log_name
    return log_file


def make_path_os_specific(path):
    """
    Converts path separators to the OS-specific ones.
    """
    return path.replace('/', os.path.sep)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        run_test_cases(test_cases, sys.argv[1])
    else:
        gather_script = SCRIPT_BASE_PATH + 'source/ida_export/preselect/metrics/gather_metrics.py'
        run_test_cases(test_cases, gather_script)
