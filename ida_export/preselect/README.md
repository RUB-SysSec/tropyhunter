# Preselection
This package handles the preselection of functions that are possible candidates of random number generators (RNGs).

## Idea
To select function candidates, filters can be implemented to determine whether a function *could* be an RNG.
Each filter should use one specific method to determine that.
These filters should be fast and can have false positives, as there are precise but computational intense checks being done on the candidates that come out of the preselection.
A filter should favor false positives over false negatives, as the former can be sorted out later, but the latter would be missed entirely (which is bad).

## Structure
```
.
├── filters/
│   ├── filter.py               Defines the filter interface
│   ├── __init__.py             Placeholder to indicate a python package
│   └── *_filter.py             Actual filter implementations (see below)
├── metrics/
│   ├── autom8.py               Run an IDA script on multiple databases
│   ├── autom8_wrapper.py       IDA script that wraps another script
│   └── gather_metrics.py       IDA script that gathers code metrics
├── post_processors/
│   ├── post_processor.py       Defines the post processor interface
│   ├── __init__.py             Placeholder to indicate a python package
│   └── *_post_processor.py     Actual post processor implementations (see below)
├── __init__.py                 Placeholder to indicate a python package
├── preselect.py                Groups the filter functionality into high level functions
└── README.md                   This doc your are reading right now :)
```

## Filters

### Syscall
See [syscall_filter.py](filters/syscall_filter.py).

Looks for interesting syscalls (or libc `_syscall()`).

### Instruction
See [instruction_filter.py](filters/instruction_filter.py).

Looks for randomness-related instructions such as `rdrand` on x86_64.

### Read `/dev/urandom`
See [read_random_filter.py](filters/read_random_filter.py).

Checks if a function gathers randomness via `read("/dev/urandom")`.

### Arithmetic
See [arithmetic_filter.py](filters/arithmetic_filter.py).

Checks for heavy usage of arithmetic instructions which might be an indicator for cryptographic operations.

## Adding a new Filter
1. Create `myheuristic_filter.py` in `filters/`
1. Create the class `MyHeuristicFilter` that inherits from `FunctionFilter` and implements `decide()`
1. Document and test it!
1. Add it as an import to `filters/__init__.py`

## Post Processors


### Call Graph
See [call_graph_post_processor.py](post_processors/call_graph_post_processor.py).

Uses the call graph to determine the correct functions that should be emulated.
