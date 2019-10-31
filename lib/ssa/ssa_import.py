import os
from typing import Dict, List
from . import ssa_export_pb2
from . import ssa_block
from . import ssa_function
from ..arch import x64


# Imports all SSA data for a given file.
def import_ssa(file_base: str, fct_addrs: List[int] = None) -> Dict[int, ssa_function.FunctionSSA]:

    file_base = file_base + "_ssa.pb2_part"

    # TODO architecture specific
    cconv = x64.CallingConventionX64()

    functions = dict()

    # Load all protobuf data.
    file_ctr = 0
    curr_file = file_base + str(file_ctr)
    while os.path.isfile(curr_file):
        print("Importing file: %s" % os.path.basename(curr_file))
        fp = open(curr_file, 'rb')
        curr_functions_ssa = ssa_export_pb2.Functions()
        curr_functions_ssa.ParseFromString(fp.read())
        fp.close()

        # Transform protobuf sturcture into internal structure.
        for function_ssa in curr_functions_ssa.functions:
            if fct_addrs is None or not fct_addrs or function_ssa.address in fct_addrs:
                function = ssa_function.FunctionSSA(function_ssa.address, cconv)
                for block_ssa in function_ssa.basic_blocks:
                    function.add_basic_block(ssa_block.BlockSSA(block_ssa))
                function.finalize()
                functions[function.address] = function

        file_ctr += 1
        curr_file = file_base + str(file_ctr)

    return functions

