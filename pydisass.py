#!/usr/bin/env python
import sys
from elfconstants import E_TYPES, E_MACHINES
from readelf import read_header, read_sections



if __name__ == "__main__":
    with open(sys.argv[1]) as fp:
        executable = fp.read()

    parsed_header = read_header(executable)
    read_sections(parsed_header, executable)

