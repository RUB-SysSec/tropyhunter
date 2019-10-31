#!/usr/bin/python3

from lib.tests.test_input_args import test_regression_input_args
from lib.tests.test_fuzzing import test_regression_fuzzing
from lib.tests.test_emulation import test_regression_candidate_emulation
from lib.tests.test_entropy import test_regression_entropy
from lib.tests.test_execution import test_regression_execution
from lib.tests.test_dynamic_size import test_regression_dyn_size

'''
Tests for different functionalities.
'''

def main():
    test_cases = list()

    #'''
    test_cases.append({
        "fct": test_regression_input_args,
        "name": "Regression input argument extraction",
        "pass": True,
    })
    #'''

    #'''
    test_cases.append({
        "fct": test_regression_fuzzing,
        "name": "Regression fuzzing",
        "pass": True,
    })
    #'''

    #'''
    test_cases.append({
        "fct": test_regression_candidate_emulation,
        "name": "Regression candidate emulation",
        "pass": True,
    })
    #'''

    #'''
    test_cases.append({
        "fct": test_regression_dyn_size,
        "name": "Regression dynamic size evaluation of candidates",
        "pass": True,
    })
    #'''

    #'''
    # NOTE: This test takes hours, only run if necessary.
    test_cases.append({
        "fct": test_regression_entropy,
        "name": "Regression entropy checking",
        "pass": True,
    })
    #'''

    #'''
    # NOTE: This test takes hours, only run if necessary.
    test_cases.append({
        "fct": test_regression_execution,
        "name": "Regression automatic execution of candidates",
        "pass": True,
    })
    #'''

    # Execute tests.
    for test_case in test_cases:
        test_case["pass"] = test_case["fct"]()

    # Summarize tests.
    print("\nSummary")
    for test_case in test_cases:
        if test_case["pass"]:
            print(("Test '%s':" % test_case["name"]).ljust(60) + "passed" )
        else:
            print(("Test '%s':" % test_case["name"]).ljust(60) + "failed")


if __name__ == '__main__':
    main()