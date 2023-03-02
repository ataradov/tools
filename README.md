# A collection of random tools

## genmif
A simple utility to generate Altera MIF (Memory Initialization File) files from the binary files

## bin2uf2
A simple utility to generate UF2 files from raw binaries for RP2040

## svd2h
Convert CMSIS SVD files to C header files. Supports generation of bitfields
and defines for register access. This converter also supports some heuristics
to fix common issues in SVD files that prevent generation of usable header files.

This tool would be updated as I use it, since SVD files are incredibly inconsistent
between the vendors, so it is hard to predict all possible cases.

