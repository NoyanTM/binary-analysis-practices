#!/bin/bash

# compile binary file
gcc -o ./build/example.o ./src/example.c

# check properties of binary file by readelf and objdump
readelf -h ./build/example.o > ./build/example_readelf.txt
objdump -x ./build/example.o > ./build/example_objdump.txt

# change entrypoint and execute binary
objcopy --change-start=0x401000 ./build/example.o
./build/example.o
