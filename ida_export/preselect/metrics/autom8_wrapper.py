import os
import sys
import imp
import traceback

import idc
import idaapi


def run_script(script_path):
    """
    Runs the given (IDA) python script in the current context.
    """
    try:
        # remove wrapper from argv
        idc.ARGV = idc.ARGV[1:]

        # add the script's path to the import paths so relative imports will work
        script_dir = os.path.dirname(os.path.realpath(script_path))
        sys.path.insert(0, script_dir)

        # run the script by loading it
        imp.load_source('__main__', script_path)
    except KeyboardInterrupt:
        # likely ctrl+c, so exit cleanly
        idaapi.qexit(0)
    except Exception as e:
        # there went something wrong, print error and exit cleanly with error code
        print('Error running script:')
        traceback.print_exc(e)
        idaapi.qexit(2)


def main():
    # check for correct usage
    if len(idc.ARGV) < 2:
        print('No script provided')
        idaapi.qexit(3)
    
    run_script(idc.ARGV[1])

    # all went fine, exit cleanly
    idaapi.qexit(0)


if __name__ == "__main__":
    main()



