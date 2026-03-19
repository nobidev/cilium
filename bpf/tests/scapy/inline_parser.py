#!/usr/bin/env python3

from scapy.all import *
from pkt_defs_common import *

# these paths are rooted to ./bpf/tests directory where eBPF unit test runner
# is ran.
SCAPY_BLOCK_ID_SIZE = 8
BPF_TESTS_PATH = "."
PACKET_BIN_PATH = BPF_TESTS_PATH + "/output"
PACKET_SIZE_HDR_PATH = "./output/pkt_sizes.h"
PACKET_SIZE_MACRO = "#define {var}_size {size}\n"

# The InlineScapyParser searches a set of C files for block comments in the form
# of /* SCAPY ... SCAPY */, within these blocks are SCAPY packet definitions.
#
# The parser extracts the python code within the block and executes it, storing
# any defined variables in a new namespace. This namespace mirrors the global
# one, so all imported module data is available to the executing code, i.e.
# pkt_defs_common module.
#
# If each variable is a scapy Packet, it is converted to binary and written to
# a .bin file representing the packet, at PACKET_BIN_PATH/{var}.bin. These
# binary files are to be included as binary during C assembly.
#
# Lastly, a header defining all packet sizes is written to PACKET_SIZE_HDR_PATH.
# This provides compile-time sizing of packet buffers to C programs which
# include this header.
class InlineScapyParser():
    def __init__(self, paths):
        # list of file paths to parse inline scapy buffers.
        self.paths = paths
        # a namespace to execute scapy python blocks into
        self.namespace = globals().copy()
        # a list of macro strings containing packet sizes written to
        # PACKET_SIZES_HDR_PATH
        self.packet_size_macros = []

    # writes all packet size macros to PACKET_SIZES_HDR_PATH that can be
    # included in test files.
    def write_header(self):
        preamble = '''#pragma once

/**
* This is an auto-generated header containing byte arrays of the scapy
* buffer definitions.
*/


'''
        with open(PACKET_SIZE_HDR_PATH, "w") as f:
            f.write(preamble)
            for macro in self.packet_size_macros:
                f.write(macro)
            print(f"Wrote packet size macros to {PACKET_SIZE_HDR_PATH}")

    # executes parsed SCAPY code blocks, converts SCAPY packets to binary, and
    # writes them to binary files in our tests directory.
    def parse_packets_to_bin(self, packet_variables):
        for var in packet_variables:
            pkt = self.namespace[var]
            if not isinstance(pkt, Packet):
                raise ValueError(f"Variable {var} is not a scapy Packet")

            # write packet as binary file
            with open(f"{PACKET_BIN_PATH}/{var}.bin", "wb") as bf:
                bf.write(bytes(pkt))

            self.packet_size_macros.append(PACKET_SIZE_MACRO.format(var=var, size=len(pkt)))

    # parses the SCAPY comment block containing inline scapy packet definition.
    def parse_block(self, path):
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()

            start = code.find('/* SCAPY')

            if start == -1:
                return

            end = code.find('SCAPY */', start)

            block = code[start + SCAPY_BLOCK_ID_SIZE:end]

            before = set(self.namespace.keys())
            try:
                exec(block, self.namespace)
            except Exception as e:
                print(f"Error executing code block in file {path}: {e}")
                print(block)
                raise
            added = (self.namespace.keys() - before)

            print(f"Parsed SCAPY block in {path}, found packets: {added}")

            self.parse_packets_to_bin(added)

    def parse(self):
        for path in self.paths:
            self.parse_block(path)
        self.write_header()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory_to_scan>")
        sys.exit(1)

    dir = sys.argv[1]
    if not os.path.isdir(dir):
        print(f"[ERROR] Invalid directory: {dir}")
        sys.exit(1)

    paths = []
    with os.scandir(dir) as it:
        for entry in it:
            if entry.is_dir(follow_symlinks=False):
                # Implement recursion if tests are in subdirs
                continue

            if not entry.name.endswith(('.h', '.c')) or entry.name == "scapy.h":
                continue

            paths.append(entry.path)

    parser = InlineScapyParser(paths)

    parser.parse()
