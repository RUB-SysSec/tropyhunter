from .ssa import ssa_function, ssa_operand, ssa_instruction
import networkx as nx

# Writes the path as .dot to the given file.
def write_graph(graph: nx.Graph, path: str):
    font = 'Ubuntu Mono'
    dot = nx.drawing.nx_pydot.to_pydot(graph)

    for n in dot.get_node_list():
        n.set_fontname(font)
        n.set_shape('rect')

    for e in dot.get_edge_list():
        e.set_fontname(font)
        if e.get('control'):
            e.set_style('dotted')

    dot.write(path)

# Traces back the data flow from the starting from the given instruction and operand.
def augment_use(function_ssa: ssa_function.FunctionSSA, instr, op_ssa: ssa_operand.OperandSSA):

    graph = nx.DiGraph()
    graph.add_node(instr)

    work_list = list()
    operands_seen = set()

    work_list.append(op_ssa)
    while work_list:
        use_op_ssa = work_list.pop(0)
        if use_op_ssa in operands_seen:
            continue
        operands_seen.add(use_op_ssa)

        def_instrs = set(function_ssa.definitions_map[use_op_ssa])

        # Set of operand uses we want to track.
        use_ops_ssa = set()
        use_ops_ssa.add(use_op_ssa)

        # Follow also the memory base register definition.
        # We kind of "overtaint" here.
        # Track both "rax" and "[rax-8]" in case of "mov [rax-8], rdi".
        if use_op_ssa.is_memory:
            if type(use_op_ssa) == ssa_operand.MemoryX64SSA:
                base_op_ssa = use_op_ssa.base

                def_instrs.update(function_ssa.definitions_map[base_op_ssa])

                # Consider base of memory also as "use" (this is important
                # for example if we start our backtrace analysis from
                # a "definition" via memory object like mov [rax-8], rdi
                # where [rax-8] is our starting operand).
                use_ops_ssa.add(base_op_ssa)
            else:
                raise NotImplementedError("Architecture not implemented.")

        for track_op_ssa in use_ops_ssa:
            for use_instr in function_ssa.uses_map[track_op_ssa]:
                for def_instr in def_instrs:

                    # Only draw an edge with the operand if the definition
                    # instruction actually defines the operand. For example,
                    # mov rbx_69, [rbp_11-f0] -> mov rsi_88, [rbx_69+0]
                    # would otherwise draw an edge with "rbx_69" and
                    # "[rbx_69+0]". We only want the edge with "rbx_69".
                    if track_op_ssa not in def_instr.definitions:
                        continue

                    # Ignore cases in which the def and use node are the same.
                    # This can happen because in cases of "[rbp_11-f0]"
                    # we track also "rbp_11" back and therefore
                    # instructions like mov "[rbp_11-f0], rcx_72"
                    # have also a edge to itself with "rbp_11".
                    if use_instr == def_instr:
                        continue

                    graph.add_node(use_instr)
                    graph.add_node(def_instr)
                    graph.add_edge(def_instr, use_instr, label=str(track_op_ssa), op=track_op_ssa)

                    # Add definitions to operand uses to track next.
                    for next_op_ssa in def_instr.uses:
                        work_list.append(next_op_ssa)

                        # Follow also the memory base register definition.
                        # We kind of "overtaint" here.
                        # Track both "rax" and "[rax-8]"
                        # in case of "mov [rax-8], rdi".
                        if next_op_ssa.is_memory:
                            if type(next_op_ssa) == ssa_operand.MemoryX64SSA:
                                base_op_ssa = next_op_ssa.base
                                work_list.append(base_op_ssa)
                            else:
                                raise NotImplementedError("Architecture not implemented.")

    return graph

# Prunes graph in such a way that the start instruction is the only leaf node and only
# the searched data flow is considered
def prune_graph(graph: nx.DiGraph, function_ssa, start_instr, initial_use):

    # Remove all incoming edges to the initial instruction that do not contain
    # the operand we are tracking currently and remove all outgoing edges
    # of the initial instruction.
    to_remove = set()
    for edge in graph.in_edges(start_instr):

        # Check both ways, if incoming edge contains the initial operand
        # or if the initial operand contains the incoming edge
        # (the latter can happen when we have "call [r15_6]#98" and an
        # incoming edge with r15_6).
        edge_op = graph.edges[edge]["op"]
        if not edge_op.contains_coarse(initial_use) and not initial_use.contains_coarse(edge_op):
            to_remove.add(edge)

    # Remove all outgoing edges from the start instruction (because the start instruction
    # should be the leaf instruction of the graph)
    for edge in graph.out_edges(start_instr):
        to_remove.add(edge)

    # Remove edges
    for edge in to_remove:
        graph.remove_edge(edge[0], edge[1])

    to_remove = set()
    for node in graph:

        # Ignore the initial instruction since we want to
        # trace its data backwards.
        if node == start_instr:
            continue

        # "call" instructions are the artificial boundary which end the
        # data flow backtracing. Remove all incoming edges of a "call"
        # instruction.
        if type(node) == ssa_instruction.InstructionSSA and node.is_call:
            for edge in graph.in_edges(node):
                to_remove.add(edge)

        # Remove edges in which the "definition" operand of the source node
        # and the "definition" operand of the destination node are different
        # memory objects, but connected via the same register operand in
        # the edge. For example, if the source is "mov [rbp_1-0x70], rax_59"
        # and the destination is "mov [rbp_1-0x60], rdi_5" and both nodes
        # are connected via "rbp_1". This happens because of our
        # "overtainting" in the augment_use() function.
        if not node.definitions:
            continue
        src_op = node.definitions[0]
        # Only consider nodes where the "definition"
        # operand is a memory object.
        if not src_op.is_memory:
            continue
        for edge in graph.out_edges(node):
            edge_op = graph.edges[edge]["op"]
            # Only consider edges where the operand is a register.
            if not edge_op.is_register:
                continue
            # Only continue if the edge belongs to the memory
            # "definition" operand
            if not src_op.contains(edge_op):
                continue
            dst_node = edge[1]
            if not dst_node.definitions:
                continue
            # Only consider nodes where the "definition" operand is
            # a memory object.
            dst_op = dst_node.definitions[0]
            if not dst_op.is_memory:
                continue
            # We are only interested in different memory operands.
            if src_op == dst_op:
                continue
            # Only continue if the edge belongs to the memory
            # "definition" operand
            if not dst_op.contains(edge_op):
                continue
            # Ignore if the destination node has the operand as a
            # "use" operand.
            skip = False
            for use_op in dst_node.uses:
                if use_op.contains(edge_op):
                    skip = True
                    break
            if skip:
                continue
            to_remove.add(edge)

    # Remove edges
    for edge in to_remove:
        graph.remove_edge(edge[0], edge[1])

    # Remove all leaf nodes that are not the source from which we started.
    changed = True
    while changed:
        changed = False
        to_remove = set()
        for node in graph:
            # Ignore the initial instruction.
            if node == start_instr:
                continue

            # Mark node for removal that does not have outgoing edges.
            if not graph.out_edges(node):
                to_remove.add(node)
                changed = True

        # Remove all nodes and their incoming edges.
        for node in to_remove:
            graph.remove_node(node)

    # Check if each node has a path to the initial node.
    # If it does not have one then we have a component in the graph that
    # is not connected to the main component we are searching for. Remove
    # these nodes.
    to_remove = set()
    for node in graph:
        if node == start_instr:
            continue
        if not nx.has_path(graph, node, start_instr):
            to_remove.add(node)
    for node in to_remove:
        graph.remove_node(node)

    # Check if the nodes have a control-flow path to the start instruction
    # and remove them if not. This can happen because we do not have memory SSA.
    # For example we can have the start instruction "mov rax_1 [rdi_0]#9c0" which
    # is the first instruction of the function, but have a data flow from 
    # "mov [rdi_0]#9c0 rdx_1" to it because we do have memory SSA.
    to_remove = set()
    cfg = function_ssa.cfg
    dst_bb = function_ssa.get_containing_basicblock(start_instr.address)
    for node in graph:
        if node == start_instr:
            continue
        src_bb = function_ssa.get_containing_basicblock(node.address)
        if not nx.has_path(cfg, src_bb, dst_bb):
            to_remove.add(node)
    for node in to_remove:
        graph.remove_node(node)