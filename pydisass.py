#!/usr/bin/env python
import sys
import struct
from elfconstants import E_TYPES, E_MACHINES


def read_elf_header(executable):
   
    HEADER_STRINGS = [
       "EI_MAGIC",        # Magic string, identifying the ELF header
       "EI_CLASS",        # Wordsize
       "EI_DATA",         # Endianness
       "EI_VERSION",      # File version
       "EI_OSABI",        # Operating system/ABI identification
       "EI_ABIVERSION",   # ABI version
       "E_TYPE",          # Type of executable
       "E_MACHINE",       # Type of machine
       "E_VERSION",       # Version, should be 1
       "E_ENTRY",         # The program's entry point
       "E_PHOFF",         # Offset until the start of the header table
       "E_SHOFF",         # Offset to the start of the section header table
       "E_FLAGS",         # This is architecture specific
       "E_EHSIZE",        # Header size (should be 52 or 64)
       "E_PHENTSIZE",     # Size of the program header table entry
       "E_PHNUM",         # Number of entries in such table
       "E_SHENTSIZE",     # Size of the section header table entry
       "E_SHUM",          # Number of entries in the section header 
       "E_SHSTRNDX",      # Index of the section header entries (section names)
    ]

    parsed_header = {}
    unpackerstr = "<bbbbbbbbb"
    
    header_data = struct.unpack(unpackerstr, bytes(executable[0:9]))
    parsed_header[HEADER_STRINGS.pop(0)] = header_data[0:4]

    for i in range(4, 9):
        parsed_header[HEADER_STRINGS.pop(0)] = header_data[i]

    strmagic = "Magic (ELF Header):"
    for byte in parsed_header["EI_MAGIC"]:
        strmagic += " {}".format(hex(byte))
    print(strmagic)

    if parsed_header["EI_CLASS"] == 0x01:
        print("CLASS             : ELF32")
        unpackerstr= "HHIIIIIHHHHHH"
        headersize = 52

    elif parsed_header["EI_CLASS"] == 0x02:
        print("CLASS             : ELF64")
        EI_CLASS = 0x2
        unpackerstr = "HHIQQQIHHHHHH"
        headersize = 64
        
    else:
        raise Exception("Wrong EI_CLASS value! ({})".format(
            hex(parsed_header["EI_CLASS"])))

    if parsed_header["EI_DATA"] == 0x01:
        print("EI_DATA           : ELFDATA2LSB")
        byteorder = '<'
    elif parsed_header["EI_DATA"] == 0x02:
        print("EI_DATA           : ELFDATA2MSB")
        byteorder = '>'
    else:
        raise Exception("Endianness is not defined!")

    header_data = struct.unpack(byteorder + unpackerstr,
            bytes(executable[16 : headersize]))

    for field in header_data:
        parsed_header[HEADER_STRINGS.pop(0)] = field
    
    print("EI_VERSION        : {}".format(hex(parsed_header["EI_VERSION"])))
    print("EI_OSABI          : {}".format(hex(parsed_header["EI_OSABI"])))
    print("EI_ABIVERSION     : {}".format(hex(parsed_header["EI_ABIVERSION"])))

    if parsed_header["E_TYPE"] not in E_TYPES:
        raise Exception("Not a valid Executable format!")

    print("E_TYPE            : {}".format(E_TYPES[parsed_header["E_TYPE"]]))

    if parsed_header["E_MACHINE"] not in E_MACHINES:
        raise Exception("Not a valid machine number! ({})".format(
            E_MACHINE))

    print("E_MACHINE         : {}".format(E_MACHINES[parsed_header["E_MACHINE"]]))

    if parsed_header["E_VERSION"] == 0x1:
        print("E_VERSION         : 0x1 (VALID)")
    else:
        raise Exception("E_VERSION INVALID ({})".format(
            parsed_header["E_VERSION"]))

    print("Entry Point       : {}".format(hex(parsed_header["E_ENTRY"])))
    print("Header table off. : {}".format(hex(parsed_header["E_PHOFF"])))
    print("Section header off: {}".format(hex(parsed_header["E_SHOFF"])))
    print("E_FLAGS           : {}".format(hex(parsed_header["E_FLAGS"])))

    return parsed_header


HEADER_TYPES = {
        '\x7fELF': read_elf_header
        }

def read_sections(executable):

    print("{}".format(executable))

    return

def read_header(executable):

    magic = executable[:4]

    if magic not in HEADER_TYPES: 
        raise Exception("Magic number not recognized!! {}".format(magic))
    else:
        HEADER_TYPES[magic](executable)

    return

if __name__ == "__main__":
    with open(sys.argv[1]) as fp:
        executable = fp.read()

    read_header(executable)
    #read_sections(executable)

