from lib import import_ssa
from lib.emulation.core import FunctionOutput, FunctionOutputType
from lib.input_args_extraction import get_input_regs, convert_input_args_ssa_to_unicorn
from lib.function_end_extraction import get_function_ends
from lib.postprocessing.return_data_flow import check_return_register_usage, import_xrefs
from lib.postprocessing.dynamic_size_output import set_dynamic_size_output
from lib.postprocessing.function_class_heuristic import set_class
from typing import Dict, Set
import json
import subprocess
import os
import time
import sys

# CONFIGURATION SETTINGS
python_interpreter = "/home/sqall/work/2018-binary-prngs/virtualenv_unicorn_git/bin/python3"
worker_file = "/home/sqall/work/2018-binary-prngs/source/worker.py"
num_processes = 4

binary_file = sys.argv[1]
function_candidates = list()
with open(binary_file + "_funcs.txt", 'r') as fp:
    for line in fp:
        function_candidates.append(int(line.strip(), 16))

class Worker(object):
    def __init__(self, id, null_fp):
        self.id = id
        self.process = None
        self.addr = None
        self.function_ssa = None
        self.functions_ssa = None
        self.binary_file = None
        self.null_fp = null_fp
        self.read_fd = None
        self.write_fd = None
        self.start_time = 0

    def start(self):
        function_addr = self.addr
        binary_file = self.binary_file

        print("\n%d: Starting worker process for function %08x." % (self.id, function_addr))
        function_ssa = self.function_ssa

        # Get the last address of the function end address.
        try:
            function_ends = get_function_ends(self.functions_ssa, function_ssa)
        except Exception as e:
            print("%d Not able to extract function ends for function %08x." % (self.id, function_addr))
            self.clear()
            return

        # Get input arguments for the current function.
        input_args_ssa = get_input_regs(binary_file, function_ssa)
        input_args_unicorn = convert_input_args_ssa_to_unicorn(input_args_ssa)

        # Create argument for subprocess.
        argument = dict()
        argument["min_size_data"] = 200000
        argument["binary_file"] = binary_file
        argument["function_addr"] = function_addr
        argument["function_ends"] = function_ends.to_dict()
        argument["input_args"] = input_args_unicorn
        argument["fd"] = self.write_fd
        argument_str = json.dumps(argument)

        self.start_time = int(time.time())

        # Start suprocess.
        self.process = subprocess.Popen([python_interpreter, worker_file, argument_str],
                                        stdout=self.null_fp,
                                        stderr=self.null_fp,
                                        pass_fds=(self.write_fd,))

    def clear(self):
        self.process = None
        self.addr = None
        self.function_ssa = None
        self.binary_file = None
        os.close(self.read_fd)
        os.close(self.write_fd)
        self.read_fd = None
        self.write_fd = None
        self.start_time = 0


def main():

    start_time = int(time.time())

    # Import SSA data.
    functions_ssa = import_ssa(binary_file)

    # Import xrefs data.
    functions_xrefs = import_xrefs(binary_file)

    # Create workers list.
    null_fp = open("/dev/null", 'w')
    workers = list()
    for i in range(num_processes):
        workers.append(Worker(i, null_fp))

    prng_candidates = dict()  # type: Dict[int, Set[FunctionOutput]]
    while function_candidates:

        # Process all worker slots.
        no_change = True
        for worker in workers:

            # If no process is running at the moment, start one.
            if worker.process is None:
                no_change = False

                if not function_candidates:
                    continue

                # Get function to process.
                function_addr = function_candidates[0]
                function_candidates.pop(0)

                worker.addr = function_addr
                worker.function_ssa = functions_ssa[function_addr]
                worker.functions_ssa = functions_ssa
                worker.binary_file = binary_file

                # Create file descriptors for subprocess to write back.
                read_fd, write_fd = os.pipe()
                os.set_blocking(read_fd, False)
                worker.read_fd = read_fd
                worker.write_fd = write_fd
                worker.start()

            # If process is running, check if we already have results we can process.
            else:

                # Check if the process is already exited.
                status = worker.process.poll()
                if status is None:
                    continue

                no_change = False
                if status != 0:
                    print("%d: Worker process for function %08x crashed." % (worker.id, worker.addr))
                else:
                    print("%d: Worker process for function %08x finished." % (worker.id, worker.addr))
                    result_str = b""
                    while True:
                        try:
                            result_str += os.read(worker.read_fd, 1000)
                        except BlockingIOError:
                            break
                    output_dsts_raw = json.loads(result_str.decode("utf-8"))
                    output_dsts = list()
                    for output_dst_dict in output_dsts_raw:
                        output_dst = FunctionOutput.from_dict(output_dst_dict)
                        output_dsts.append(output_dst)
                    if output_dsts:
                        print("%d: Worker process for function %08x found %d candidate." % (worker.id, worker.addr, len(output_dsts)))
                        prng_candidates[worker.addr] = output_dsts

                print("%d: Worker needed %d seconds." % (worker.id, (int(time.time()) - worker.start_time)))

                # Clear worker process.
                worker.clear()

        # If we processed each worker slot without having any change, sleep before processing them again.
        if no_change:
            time.sleep(1)

    # Collect the last results of the worker processes.
    for worker in workers:
        if worker.process:
            worker.process.wait()
            status = worker.process.poll()
            if status != 0:
                print("%d: Worker process for function %08x crashed." % (worker.id, worker.addr))
            else:
                print("%d: Worker process for function %08x finished." % (worker.id, worker.addr))
                result_str = b""
                while True:
                    try:
                        result_str += os.read(worker.read_fd, 1000)
                    except BlockingIOError:
                        break
                output_dsts_raw = json.loads(result_str.decode("utf-8"))
                output_dsts = list()
                for output_dst_dict in output_dsts_raw:
                    output_dst = FunctionOutput.from_dict(output_dst_dict)
                    output_dsts.append(output_dst)
                if output_dsts:
                    print("%d: Worker process for function %08x found %d candidate." % (worker.id, worker.addr, len(output_dsts)))
                    prng_candidates[worker.addr] = output_dsts

            print("%d: Worker needed %d seconds." % (worker.id, (int(time.time()) - worker.start_time)))

            # Clear worker process.
            worker.clear()

    # Post-processing of output destinations.
    for func_addr, output_dsts in prng_candidates.items():
        # Post-processing of output destinations.
        for output_dst in list(output_dsts):

            if output_dst.output_type == FunctionOutputType.Register:

                # Check return register usage.
                if not check_return_register_usage(func_addr,
                                                   output_dst,
                                                   functions_ssa,
                                                   functions_xrefs):

                    print("Removing %s for function %08x (Return register post processing)."
                          % (str(output_dst), func_addr))

                    output_dsts.remove(output_dst)

            elif output_dst.output_type == FunctionOutputType.Pointer:

                function_ssa = functions_ssa[func_addr]
                function_ends = get_function_ends(functions_ssa, function_ssa)

                # Check for a dynamic size via a size argument and add it as feature.
                set_dynamic_size_output(binary_file,
                                        func_addr,
                                        function_ends,
                                        output_dst.used_input_regs,
                                        output_dst)

            # Set class type based on heuristic.
            set_class(output_dst)

    # Remove candidates that do not have any output destination left.
    to_remove = set()
    for func_addr, output_dsts in prng_candidates.items():
        if not output_dsts:
            to_remove.add(func_addr)
    for func_addr in to_remove:
        del prng_candidates[func_addr]

    end_time = int(time.time())

    sys.stdout.flush()
    sys.stderr.flush()
    print("Results:")

    for addr, output_dsts in prng_candidates.items():
        print("Function %08x is possible PRNG" % addr)
        for output_dst in output_dsts:
            print(output_dst)
        print("")

    print("Time needed: %s seconds" % (end_time - start_time))


if __name__ == '__main__':
    main()
