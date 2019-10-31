import idc
import idautils
import idaapi

import __builtin__
import time
import pickle
import os

from lib.shovel.cfg import Function
import lib.shovel.arch.meta
from lib.shovel.arch import RegistersTricore, RegistersX64
from export.ssa_export import export_ssa_functions
from preselect import Preselector


# Set used architecture.
#__builtin__.REGISTERS = RegistersTricore()
__builtin__.REGISTERS = RegistersX64()


# Removes the renaming of all registers.
def remove_regvars(func_addr):
    func = idaapi.get_func(func_addr)

    # Store register renaming.
    addr = func.startEA
    regvars = set()
    while addr <= func.endEA:
        for reg_str in __builtin__.REGISTERS._to_idx.keys():
            regvar = idaapi.find_regvar(func, addr, reg_str)
            if regvar is not None:

                regvars.add((reg_str,
                             regvar.user,
                             regvar.cmt,
                             regvar.startEA,
                             regvar.endEA))
        addr += 1

    # Since IDA places two not connected CFGs sometimes in the same
    # functions (multiple entry basic blocks), we have to go
    # through all basic blocks also.
    ida_blocks = list(idaapi.FlowChart(func))
    for b in ida_blocks:

        addr = b.startEA
        block_end = b.endEA
        while addr != BADADDR and addr < block_end:

            for reg_str in __builtin__.REGISTERS._to_idx.keys():

                regvar = idaapi.find_regvar(func, addr, reg_str)

                if regvar is not None:

                    regvars.add((reg_str,
                                 regvar.user,
                                 regvar.cmt,
                                 regvar.startEA,
                                 regvar.endEA))
            addr = NextHead(addr)


    # Remove register renaming.
    for regvar in regvars:
        idaapi.del_regvar(func,
                          regvar[3], # startEA
                          regvar[4], # endEA
                          regvar[0]) # register string

    return regvars


# Restores all removed register renamings.
def restore_regvars(func_addr, regvars):
    func = idaapi.get_func(func_addr)
    for regvar in regvars:
        idaapi.add_regvar(func,
                          regvar[3], # startEA
                          regvar[4], # endEA
                          regvar[0], # register string
                          regvar[1], # user register string
                          regvar[2]) # comment


# Yield code references (and follow .plt references).
def get_real_code_refs_to(func_addr):
    for code_ref in idautils.CodeRefsTo(func_addr, True):
        if plt_start <= code_ref <= plt_end:
            for transient_code_ref in idautils.CodeRefsTo(code_ref, True):
                yield transient_code_ref
        if plt_got_start <= code_ref <= plt_got_end:
            for transient_code_ref in idautils.CodeRefsTo(code_ref, True):
                yield transient_code_ref
        else:
            yield code_ref


# Checks if the .plt entry points to the code.
# Returns None if we cannot check it, True if the .plt entry points into
# the code and False if it does not.
def plt_entry_points_to_code(func_addr):
    # .plt.got or .plt entries look like this "jmp <GOT ADDRESS>".
    # Extract the .GOT address and check if it points into
    # the .text section. We are only interested in functions
    # that do not point into the text section.
    if GetMnem(func_addr) != "jmp":
        return None
    got_addr = GetOperandValue(func_addr, 0)
    is_code = False
    for data_ref in idautils.DataRefsFrom(got_addr):
        if text_seg and text_start <= data_ref <= text_end:
            is_code = True
    return is_code


# Triple recursion limit.
sys.setrecursionlimit(3*sys.getrecursionlimit())

plt_seg = None
plt_start = 0
plt_end = 0
plt_got_seg = None
plt_got_start = 0
plt_got_end = 0
text_seg = None
text_start = 0
text_end = 0
segments = list(idautils.Segments())
exec_segments = list()
for segment in segments:
    if idc.SegName(segment) == ".plt":
        plt_seg = segment
        plt_start = idc.SegStart(plt_seg)
        plt_end = idc.SegEnd(plt_seg)

    if idc.SegName(segment) == ".plt.got":
        plt_got_seg = segment
        plt_got_start = idc.SegStart(plt_got_seg)
        plt_got_end = idc.SegEnd(plt_got_seg)

    if idc.SegName(segment) == ".text":
        text_seg = segment
        text_start = idc.SegStart(text_seg)
        text_end = idc.SegEnd(text_seg)

    permissions = idaapi.getseg(segment).perm
    if permissions & idaapi.SEGPERM_EXEC:
        exec_segments.append(segment)

start_time = time.time()

# Import existing ssa file if exists in order to be able to process idb
# in multiple steps.
export_ssa_file = idc.GetInputFile() + "_ssa.pb2"
export_ssa_dict = dict()

file_counter = 0

function_code_refs = dict()

# Remove all regvars before starting the analysis.
for i, func_addr in enumerate(idautils.Functions()):
    print("Removing regvars for 0x%x" % func_addr)
    regvars = remove_regvars(func_addr)
    #print("Restoring regvars for 0x%x" % func_addr)
    #restore_regvars(func_addr, regvars)

for segment in exec_segments:

    if idc.SegStart(segment) == plt_start:
        continue

    start_ea = idc.SegStart(segment)
    end_ea = idc.SegEnd(segment)

    print('\nProcessing segment %s.' % idc.SegName(segment))

    for i, func_addr in enumerate(idautils.Functions(start_ea, end_ea)):

        print("Building CFG for 0x%x" % func_addr)
        func = Function(func_addr)

        print("Building SSA for 0x%x" % func_addr)
        func.transform()

        # DEBUG
        func.comment()
        print("")

        export_ssa_dict[func_addr] = func

        # Export every 150 functions in order to compensate memory problems.
        if len(export_ssa_dict) % 150 == 0:
            current_file = export_ssa_file + "_part%d" % file_counter
            print("Exporting to %s" % current_file)
            export_ssa_functions(__builtin__.REGISTERS,
                                 export_ssa_dict,
                                 current_file)
            file_counter += 1

            # Empty dictionary because of memory problems in IDA 32 bit python.
            export_ssa_dict = dict()

        # Getting function code refs.
        function_code_refs[func_addr] = list(get_real_code_refs_to(func_addr))

# Final export of ssa.
if export_ssa_dict:
    current_file = export_ssa_file + "_part%d" % file_counter
    print("Exporting to %s" % current_file)
    export_ssa_functions(__builtin__.REGISTERS,
                         export_ssa_dict,
                         current_file)


# This will hold the candidates we are about to find
preselection_candidates = set()

# This boi is in charge of selecting candidates
preselector = Preselector()

# Iterate over all segments
function_counter = 0
for segment in exec_segments:
    # Skip the PLT since it has no real code
    if idc.SegStart(segment) == plt_start:
        continue

    # Get the segment boundaries
    segment_start_ea = idc.SegStart(segment)
    segment_end_ea = idc.SegEnd(segment)

    print('Processing segment {}'.format(idc.SegName(segment)))

    # Iterate over all function in this segment
    for i, func_addr in enumerate(idautils.Functions(segment_start_ea, segment_end_ea)):
        print('  Checking {}'.format(GetFunctionName(func_addr)))
        function_counter += 1

        is_candidate, filter_name = preselector.decide(func_addr)
        if is_candidate:
            preselection_candidates.add(func_addr)

            # Add more functions based on the one we found
            for additional_func in preselector.post_process(func_addr, filter_name):
                preselection_candidates.add(additional_func)

# Print stats
print('Found {} candidates in {} functions'.format(len(preselection_candidates), function_counter))

# Export candidates to file
candidates_file = '{}_funcs.txt'.format(GetInputFile())
print('Exporting candidates to {}...'.format(candidates_file))
with open(candidates_file, 'w') as f:
    sorted = list(preselection_candidates)
    sorted.sort()

    for candidate in sorted:
        f.write('{:x}'.format(candidate))
        f.write('\n')

# Export function code refs.
candidates_file = '{}_xrefs.txt'.format(GetInputFile())
with open(candidates_file, 'w') as f:
    for func_addr, code_xrefs in function_code_refs.items():
        f.write("%x" % func_addr)
        for code_xref in code_xrefs:
            f.write(" %x" % code_xref)
        f.write("\n")

# Export .plt entries.
counter = 0
with open(GetInputFile() + '_plt.txt', 'w') as f:
    if plt_seg is not None:
        for i, func_addr in enumerate(Functions(plt_start, plt_end)):

            # Ignore functions that do not have a name.
            func_name = GetFunctionName(func_addr)
            if not func_name:
                continue

            # Only export entries that do not point into the code itself.
            if plt_entry_points_to_code(func_addr):
                continue

            # Names of .plt function start with an ".". Remove it.
            f.write("%x %s\n" % (func_addr, func_name[1:]))
            counter += 1

    if plt_got_seg is not None:
        for i, func_addr in enumerate(Functions(plt_got_start, plt_got_end)):

            # Ignore functions that do not have a name.
            func_name = GetFunctionName(func_addr)
            if not func_name:
                continue

            # Only export entries that do not point into the code itself.
            if plt_entry_points_to_code(func_addr):
                continue

            f.write("%x %s\n" % (func_addr, func_name))
            counter += 1

print('\nExported %d .plt entries.' % counter)

print("Finished in %.2f seconds." % (time.time() - start_time))