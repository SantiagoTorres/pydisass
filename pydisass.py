#!/usr/bin/env python
import sys
from readelf import read_executable



if __name__ == "__main__":
    with open(sys.argv[1]) as fp:
        data = fp.read()

    read_executable(data)
