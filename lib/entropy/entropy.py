from ..emulation.core import FunctionOutput, FunctionOutputType
from ..arch.x64 import RegistersX64
import subprocess


class EntropyCheck(object):

    def __init__(self, target_file: str):
        self.dieharder_location = "/usr/bin/dieharder"
        self.target_file = target_file

        # Dieharder tests used for the randomness check.
        self.dieharder_tests = [0, 4, 8, 10, 11, 12, 14]
        self.dieharder_tests_results = {"PASSED": [], "WEAK": [], "FAILED": []}

    def check(self) -> bool:
        """
        Checks if the given file has enough entropy.

        :return: True if it passes more than half the tests.
        """
        passed_ctr = 0
        weak_ctr = 0
        failed_ctr = 0

        ctr = 1
        for test_number in self.dieharder_tests:
            print("Starting dieharder test: %d (%d/%d)" % (test_number, ctr, len(self.dieharder_tests)))
            cmd = [self.dieharder_location, "-g", "201", "-f", self.target_file, "-d", str(test_number)]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.wait()
            output, err = p.communicate()
            temp = output.decode("utf-8").split("\n")
            for line in temp:
                line_split = line.replace(" ", "").split("|")
                if len(line_split) != 6:
                    continue
                if line_split[0] == "test_name":
                    continue
                if line_split[5] == "PASSED":
                    passed_ctr += 1
                    self.dieharder_tests_results["PASSED"].append(test_number)
                elif line_split[5] == "WEAK":
                    weak_ctr += 1
                    self.dieharder_tests_results["WEAK"].append(test_number)
                elif line_split[5] == "FAILED":
                    failed_ctr += 1
                    self.dieharder_tests_results["FAILED"].append(test_number)
                else:
                    raise ValueError("Test result '%s' not known for dieharder." % line_split[5])
            ctr += 1

        print("Result: %d passed; %d weak; %d failed" % (passed_ctr, weak_ctr, failed_ctr))
        if (passed_ctr+weak_ctr) > 0:
            return True
        return False


def check_entropy(fct_output: FunctionOutput) -> bool:
    """
    Checks the entropy of the FunctionOutput object and if we consider it a PRNG.
    :param fct_output: FunctionOutput object to check.
    :return: True if we consider output a PRNG.
    """
    type_str = "Register: %s, Type: %s" % (RegistersX64.from_unicorn_to_str(fct_output.register),
                                           FunctionOutputType.to_str(fct_output.output_type))
    print("Checking entropy for function %08x (%s)" % (fct_output.fct_addr, type_str))

    # Store function output before processing it.
    if fct_output.is_data_cached():
        fct_output.store_to_file()

    check_obj = EntropyCheck(fct_output.data_file)
    result = check_obj.check()

    msg = "Test results:"
    for k, v in check_obj.dieharder_tests_results.items():
        fct_output.dieharder_results[k].extend(v)
        msg += " %s: %s;" % (k, str(v))
    print(msg)

    if result:
        print("Function %08x (%s) is probably a PRNG." % (fct_output.fct_addr, type_str))
    else:
        print("Function %08x (%s) does not create enough entropy to be a PRNG." % (fct_output.fct_addr, type_str))
    return result
