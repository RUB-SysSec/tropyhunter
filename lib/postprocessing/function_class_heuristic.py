from ..emulation.core import FunctionOutput, FunctionOutputType, RegisterInputType


def set_class(output_dst: FunctionOutput):

    num_value = 0
    num_mem = 0
    unknown_args = list()
    for _, inferred_arg in output_dst.used_input_regs.items():
        if inferred_arg.input_type == RegisterInputType.Value:
            num_value += 1
        elif inferred_arg.input_type == RegisterInputType.Memory:
            num_mem += 1

    for _, inferred_arg in output_dst.inferred_input_regs.items():
        if inferred_arg.input_type == RegisterInputType.Unknown:
            unknown_args.append(inferred_arg)

    if unknown_args:
        output_dst.args_conclusive = False
    else:
        output_dst.args_conclusive = True

    if output_dst.output_type == FunctionOutputType.Register:
        return

    # Usually a PRNG has 1 or 2 memory arguments (state ptr and output ptr) and at least 1 value argument (size).
    if 3 > num_mem >= 1 and num_value >= 1 and output_dst.dyn_size:
        output_dst.maybe_prng = True

    # Usually, a Hash function has 1 or 2 memory arguments (state ptr and output ptr).
    elif num_mem >= 1 and num_value == 0 and not output_dst.dyn_size:
        output_dst.maybe_hash = True

    # Usually, an encryption function has 3 memory arguments (state ptr, input ptr, output ptr)
    # and 1 value argument (size).
    elif num_mem == 3 and num_value >= 1 and output_dst.dyn_size:
        output_dst.maybe_enc = True
