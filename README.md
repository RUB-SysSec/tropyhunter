# Tropyhunter

Tool to search pseudo-random number generators and cryptographic hash functions in binary executables. The usage is split into two steps: export necessary data via IDA python and executing the analysis. The analysis can use multiple processes (supervised by `arbiter.py`) and thus can be heavily parallelized (the actual analyzes is done in the `worker.py` script).


# Installation

Short installation description tested on Ubuntu 16.04 and 18.04.

- Needs `dieharder` installed
```
apt install dieharder
```

- Needs unicorn 1.0.2
```
git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn
./make.sh
sudo ./make.sh install
cd bindings/python/
python3 setup.py install
```

- Needs networkx
```
pip3 install networkx
```

- Needs capstone
```
pip3 install capstone
```

- Needs protobuf
```
pip3 install protobuf
```

- Needs pyelftools
```
pip3 install pyelftools
```

- Configure `arbiter.py` by setting in the beginning of the file the number of processes started, the python interpreter that should be used, and the location of the `worker.py` file.


# Usage

## IDA Export

First load the binary into IDA (preferable IDA on Linux). Then execute the `ida_export.py` script available in the `ida_export` directory. This script will transform the binary executable into SSA form, export necessary information, and do a pre-selection of PRNG/CHF functions. The SSA generation is taken from the [SSA for IDA project](https://github.com/dwuid/phida).

## Analysis

Just execute the following command:

```
python3 ./arbiter.py /path/to/target/binary_executable
```

Please note that the files the IDA export script creates have to be placed in the same directory as the target binary executable.