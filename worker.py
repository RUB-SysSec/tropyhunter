from lib.executer import execute_function
from lib.emulation.core import FunctionEnds
import sys
import json
import os

def main():
    input_data = json.loads(sys.argv[1])
    min_size_data = input_data["min_size_data"]
    binary_file = input_data["binary_file"]
    fct_addr = input_data["function_addr"]
    fct_ends_dict = input_data["function_ends"]
    fct_ends = FunctionEnds.from_dict(fct_ends_dict)
    input_args_raw = input_data["input_args"]
    parent_fd = input_data["fd"]

    # Since the keys in json loaded dicts are always strings, we
    # have to convert them to integers.
    input_args = dict()
    for unicorn_op_str, input_type in input_args_raw.items():
        input_args[int(unicorn_op_str)] = int(input_type)

    output_dsts = execute_function(binary_file,
                                   fct_addr,
                                   fct_ends,
                                   input_args,
                                   min_size_data)

    # Write results back to parent.
    result = list()
    for output_dst in output_dsts:
        result.append(output_dst.to_dict())
    os.write(parent_fd, json.dumps(result).encode("utf-8"))
    os.close(parent_fd)


if __name__ == '__main__':

    if len(sys.argv) == 2:
        main()
    else:
        print("Usage: %s <data_to_process>" % sys.argv[0])
