#!/usr/bin/env python
import struct
from elfconstants import E_TYPES, E_MACHINES, SECTION_HEADER_TYPES, \
    SHT_LOOS, SHT_HIOS, SHT_LOPROC, SHT_HIPROC, SHT_LOUSER, SHT_HIUSER


"""
    Class section_header

    Includes information regarding a section header for an elf binary.

    <Attributes>
        _name: a string repesenting the name
        _nameind: the index of the string representing its name in the string
                  section
        _type: the constant representing its type
        _flags: flags for this section (read, write, etc.)
        _addr: The location of this header
        _offset: The offset from this header to its contents
        _size: the size of the section
        _link: I have no idea what this does
        _align: The address it should be loaded into
        _entsize: The size of this entry

    <Methods>
       init:        initializes from the values provided
       fetch_name:  given a string table section, find our name and set the
                    property
       toString:    pretty print the available information
"""
class section_header:
    
    _name    = None  # string name
    _nameind = None  # name index
    _type    = None  # type of section
    _flags   = None  # Flags for the section
    _addr    = None  # Address location
    _offset  = None  # Offset into the file
    _size    = None  # Size of the section
    _link    = None  # Link?
    _align   = None  # Address to be loaded into
    _entsize = None  # size of this entry


    """
        init method

        this is a simple kwargs-copying constructor, nothing fancy.

    """
    def __init__(self, kwargs):
    
        
        if "sh_name" in kwargs:
            self._nameind = kwargs['sh_name']

        if "sh_type" in kwargs:
            self._type = kwargs['sh_type']

        if "sh_flags" in kwargs: 
            self._flags = kwargs['sh_type']

        if "sh_addr" in kwargs:
            self._addr = kwargs['sh_addr']

        if "sh_offset" in kwargs:
            self._offset = kwargs['sh_offset']

        if "sh_size" in kwargs:
            self._size = kwargs['sh_size']

        if "sh_link" in kwargs:
            self._link = kwargs['sh_size']

        if "sh_info" in kwargs:
            self._info = kwargs['sh_info']

        if "sh_addralign" in kwargs:
            self._align = kwargs['sh_addralign']

        if "sh_entsize" in kwargs:
            self._entsize = kwargs['sh_entsize']

        return None

    """
        fetch_name method:

        When provided the contents to a string table, seek four the name of
        this section and set it in this instance.

        <parameters>
            strtable: a byte-string containing the contents of the section to 
                      seek

        <returns>
            the name of this section

        <Side Effects>
            The name of this instance's section is set

    """
    def fetch_name(self, strtable):
    
        if self._type == 0:
            self._name = "TYPE_NULL"

        else:

            strtable = strtable[self._nameind:]
            end = strtable.find('\x00')
            self._name = strtable[:end ]

        return self._name

    """
        toString method:

        Pretty prints (read formats) the contents of this object for
        printing.

        <Parameters>
            None

        <Returns>
            A string representation for this object for printing.
    """
    def toString(self):

        returnstr = ""
        
        if self._name is not None:
            returnstr += 'Name: {:20}  '.format(self._name)

        else:
            returnstr += 'Name: {:20}  '.format(self._nameind)
 
        if self._type in SECTION_HEADER_TYPES:
            returnstr += 'Type: {:10}'.format(SECTION_HEADER_TYPES[self._type])
        elif self._type >= SHT_LOOS and self._type <= SHT_HIOS:
            returnstr += 'Type: OS    '
        elif self._type >= SHT_LOPROC and self._type <= SHT_HIPROC:
            returnstr += 'Type: PROC  '
        elif self._type >= SHT_LOUSER and self._type <= SHT_HIUSER:
            returnstr += 'Type: USER  '
        else:
            returnstr +=  'Type: Unknown({:3})'.format(hex(self._type))

        return returnstr


"""
    Class elf_executable

    Holds the information of an executable, contains methods for parsing and
    reading section headers and binary blobs of data.

    <Attributes>
        Header:         Contains information about the header, wordsize, 
                        target platform, all that stuff

        section_headers: Contains a list of section header objects

        executable:      The binary blob of data for the loaded executable

    <Methods>
        __init__:        Given a stream of data, try to load it as an ELF.
        read_elf_header: Read the header from an executable

    <Notes>
        TODO: The methods below should be part of the object in later stages
    """
class elf_executable:

    header = None
    section_headers = None
    executable = None

    def __init__(self, executable):

        self.header = self.read_elf_header(executable)
        self.section_headers = parse_elf_sections(executable, self.header)
        self.executable = executable

    def read_elf_header(self, executable):
       
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
           "E_SHNUM",         # Number of entries in the section header 
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
        print("E_EHSIZE          : {}".format(hex(parsed_header["E_EHSIZE"])))
        print("E_PHENTSIZE       : {}".format(hex(parsed_header["E_PHENTSIZE"])))
        print("E_PHNUM           : {}".format(hex(parsed_header["E_PHNUM"])))
        print("E_SHENTSIZE       : {}".format(hex(parsed_header["E_SHENTSIZE"])))
        print("E_SHNUM           : {}".format(hex(parsed_header["E_SHNUM"])))
        print("E_SHSTRNDX        : {}".format(hex(parsed_header["E_SHSTRNDX"])))

        return parsed_header

def build_elf_section(executable, offset, wordsize, size):

    readstr = "<IIQQQQIIQQ"
    HEADER_SECTIONS = [
        "sh_name",
        "sh_type",
        "sh_flags",
        "sh_addr",
        "sh_offset",
        "sh_size",
        "sh_link",
        "sh_info",
        "sh_addralign",
        "sh_entsize",
    ]
        
    parsed_section = {}
    names = []

    data = struct.unpack(readstr, executable[offset:offset+size])

    for i in data:
        parsed_section[HEADER_SECTIONS.pop(0)] = i

    new_section_header = section_header(parsed_section)
    return new_section_header

def build_string_table(executable, string_sections):

    string = ''
    for section in string_sections:
        location = section._offset
        length = section._size 
        strings_table = executable[location:location + length]
        if strings_table[1] == '.':
            string += strings_table

    return string

def parse_elf_sections(executable, parsed_headers):
    no_of_entries = parsed_headers["E_SHNUM"]
    wordsize      = parsed_headers["EI_CLASS"]
    start_address = parsed_headers["E_SHOFF"]
    size          = parsed_headers["E_SHENTSIZE"]


    section_headers = [] 
    string_sections = []
    for i in range(0, no_of_entries):
        section_header = build_elf_section(executable, start_address + i*size,
                wordsize, size)
        section_headers.append(section_header)
        if section_header._type == 3:
            string_sections.append(section_header)

    strtable = build_string_table(executable, string_sections)

    for section in section_headers:
        section.fetch_name(strtable)
        print(section.toString())
    


    return

def read_executable(executable):

    magic = executable[:4]

    if magic != '\x7fELF': 
        raise Exception("Magic number not recognized!! {}".format(magic))
    else:
        parsed_executable = elf_executable(executable)

    return parsed_executable 

