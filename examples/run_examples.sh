#!/bin/sh

cd ../

# x86
./ghidralligator -m replay -c examples/x86/config.json -I -i examples/x86/input/input_double_free.bin > examples/x86/input/input_double_free.bin.log 2>&1
./ghidralligator -m replay -c examples/x86/config.json -I -i examples/x86/input/input_read_before_write.bin > examples/x86/input/input_read_before_write.bin.log 2>&1
./ghidralligator -m replay -c examples/x86/config.json -I -i examples/x86/input/input_read_overflow.bin > examples/x86/input/input_read_overflow.bin.log 2>&1
./ghidralligator -m replay -c examples/x86/config.json -I -i examples/x86/input/input_use_after_free.bin > examples/x86/input/input_use_after_free.bin.log 2>&1
./ghidralligator -m replay -c examples/x86/config.json -I -i examples/x86/input/normal_use_case.bin > examples/x86/input/normal_use_case.bin.log 2>&1
./ghidralligator -m replay -c examples/x86/config.json -I -i examples/x86/input/input_write_overflow.bin > examples/x86/input/input_write_overflow.bin.log 2>&1

# ARM
./ghidralligator -m replay -c examples/ARM/config.json -I -i examples/ARM/input/input_double_free.bin > examples/ARM/input/input_double_free.bin.log 2>&1
./ghidralligator -m replay -c examples/ARM/config.json -I -i examples/ARM/input/input_read_before_write.bin > examples/ARM/input/input_read_before_write.bin.log 2>&1
./ghidralligator -m replay -c examples/ARM/config.json -I -i examples/ARM/input/input_read_overflow.bin > examples/ARM/input/input_read_overflow.bin.log 2>&1
./ghidralligator -m replay -c examples/ARM/config.json -I -i examples/ARM/input/input_use_after_free.bin > examples/ARM/input/input_use_after_free.bin.log 2>&1
./ghidralligator -m replay -c examples/ARM/config.json -I -i examples/ARM/input/normal_use_case.bin > examples/ARM/input/normal_use_case.bin.log 2>&1
./ghidralligator -m replay -c examples/ARM/config.json -I -i examples/ARM/input/input_write_overflow.bin > examples/ARM/input/input_write_overflow.bin.log 2>&1

# MIPS
./ghidralligator -m replay -c examples/MIPS/config.json -I -i examples/MIPS/input/input_double_free.bin > examples/MIPS/input/input_double_free.bin.log 2>&1
./ghidralligator -m replay -c examples/MIPS/config.json -I -i examples/MIPS/input/input_read_overflow.bin > examples/MIPS/input/input_read_overflow.bin.log 2>&1
./ghidralligator -m replay -c examples/MIPS/config.json -I -i examples/MIPS/input/input_use_after_free.bin > examples/MIPS/input/input_use_after_free.bin.log 2>&1
./ghidralligator -m replay -c examples/MIPS/config.json -I -i examples/MIPS/input/normal_use_case.bin > examples/MIPS/input/normal_use_case.bin.log 2>&1
./ghidralligator -m replay -c examples/MIPS/config.json -I -i examples/MIPS/input/input_write_overflow.bin > examples/MIPS/input/input_write_overflow.bin.log 2>&1


# PPC
./ghidralligator -m replay -c examples/PPC/config.json -I -i examples/PPC/input/input_double_free.bin > examples/PPC/input/input_double_free.bin.log 2>&1
./ghidralligator -m replay -c examples/PPC/config.json -I -i examples/PPC/input/input_read_before_write.bin > examples/PPC/input/input_read_before_write.bin.log 2>&1
./ghidralligator -m replay -c examples/PPC/config.json -I -i examples/PPC/input/input_read_overflow.bin > examples/PPC/input/input_read_overflow.bin.log 2>&1
./ghidralligator -m replay -c examples/PPC/config.json -I -i examples/PPC/input/input_use_after_free.bin > examples/PPC/input/input_use_after_free.bin.log 2>&1
./ghidralligator -m replay -c examples/PPC/config.json -I -i examples/PPC/input/normal_use_case.bin > examples/PPC/input/normal_use_case.bin.log 2>&1
./ghidralligator -m replay -c examples/PPC/config.json -I -i examples/PPC/input/input_write_overflow.bin > examples/PPC/input/input_write_overflow.bin.log 2>&1


# AARCH64
./ghidralligator -m replay -c examples/AARCH64/config.json -I -i examples/AARCH64/input/input_double_free.bin > examples/AARCH64/input/input_double_free.bin.log 2>&1
./ghidralligator -m replay -c examples/AARCH64/config.json -I -i examples/AARCH64/input/input_read_before_write.bin > examples/AARCH64/input/input_read_before_write.bin.log 2>&1
./ghidralligator -m replay -c examples/AARCH64/config.json -I -i examples/AARCH64/input/input_read_overflow.bin > examples/AARCH64/input/input_read_overflow.bin.log 2>&1
./ghidralligator -m replay -c examples/AARCH64/config.json -I -i examples/AARCH64/input/input_use_after_free.bin > examples/AARCH64/input/input_use_after_free.bin.log 2>&1
./ghidralligator -m replay -c examples/AARCH64/config.json -I -i examples/AARCH64/input/normal_use_case.bin > examples/AARCH64/input/normal_use_case.bin.log 2>&1
./ghidralligator -m replay -c examples/AARCH64/config.json -I -i examples/AARCH64/input/input_write_overflow.bin > examples/AARCH64/input/input_write_overflow.bin.log 2>&1
