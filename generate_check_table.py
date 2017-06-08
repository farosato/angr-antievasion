import sys
from subprocess import check_output
import json


if __name__ == '__main__':
    # create dict symbols -> addr
    bin_name = sys.argv[1]
    check_file_name = sys.argv[2]

    symbols = {}
    nm_output = check_output("nm --demangle {}".format(bin_name), shell=True).split('\n')
    for line in nm_output:
        line = line.split()
        try:
            addr, symtype, sym = line
            if symtype == 'T':
                symbols[sym] = int(addr, 16)
        except ValueError:
            pass  # bad line

    with open(check_file_name, 'r') as cf:
        checks = [line.strip() for line in cf]

    check_table = []
    for c in checks:
        check_table.append((c, symbols[c]))

    # dump to json file
    with open(bin_name + '_checks.json', 'w') as jdump:
        jdump.write(json.dumps(check_table, indent=4))
