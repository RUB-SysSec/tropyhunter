import idautils
import idaapi
import idc


def instructions(start_ea, end_ea):
    """
    Returns the list of instruction addresses in the given address range (including).
    """
    return list(idautils.Heads(start_ea, end_ea))


def basic_blocks(func_addr):
    """
    Generator that yields tuples of start and end addresses of all basic blocks in the given function.
    """
    f = idaapi.get_func(func_addr)
    flow = idaapi.FlowChart(f)

    for block in flow:
        yield block.startEA, block.endEA


def func_instructions(func_addr):
    """
    Generator that yields the instruction addresses of all instructions in the given function.
    """
    for bb_start, bb_end in basic_blocks(func_addr):
        for instr_addr in instructions(bb_start, bb_end):
            yield instr_addr


def func_last_instr(func_addr):
    """
    Returns the address of the last instruction of the given function.
    """
    return list(func_instructions(func_addr))[-1]


def func_mnemonics(func_addr):
    """
    Generator that yields the mnemonics of all instructions in the given functions.
    """
    for bb_start, bb_end in basic_blocks(func_addr):
        for mnemonic in mnemonics(bb_start, bb_end):
            yield mnemonic


def mnemonics(start_ea, end_ea):
    """
    Generator that yields all mnemonics in the given address range (including).
    """
    for instr_addr in instructions(start_ea, end_ea):
        yield idc.GetMnem(instr_addr)


def count_mnemonics(start_ea, end_ea, needle_mnemonics):
    """
    Counts how many times the mnemonics in needle_mnemonics occur in the given address range (including).
    """
    count = 0
    for mnemonic in mnemonics(start_ea, end_ea):
        if mnemonic in needle_mnemonics:
            count += 1
    return count
