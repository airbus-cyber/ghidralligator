# Ghidralligator - Configuration File

Usually, when using Ghidralligator, configuration file writing is the first step.

This requires you to understand the target binary, and more precisely its initial state from which the emulation should start along with its memory layout.


Configuration file examples can be found under the ```./examples``` directory of the repository.

The Ghidralligator configuration file follows the JSON format. Each entry in the configuration is formed from a "key:value" pair.

Let's walk through the configuration, and explain the meaning of each field:

* ```sla_file```: Path to the corresponding sla file. A set of sla files are available under the ```./specfiles``` directory.

* ```target```: Name of the registered user-hook. See tutorials for a proper understanding of this value. For now, it just has to be a unique string across the configurations.

## Emulator

* ```start_address``` : Address where the emulator should start its job.

* ```stop_addresses``` : List of addresses where to stop the emulation.

## Configurations

* ```track_exec_operations``` : As Ghidralligator is able to detect memory corruptions through the tracking of 'exec' operations, we can choose to disable it for a particular use-case.


## Registers

* ```registers``` : Top-level container that aggregates the initial state of registers.

* ```registers``` - ```name``` : Name that describes a register. This name should follow the same syntax as in the provided .sla file.

* ```registers``` - ```value``` : The initial value stored in those registers when the emulation starts.

## Memory Sections

* ```sections``` : Top-level container that aggregates the memory layout of the emulator.

* ```sections``` - ```name``` : Describes the memory area being instantiated. Can be any string, only for debugger purposes.

* ```sections``` - ```path``` : Path to the file on the disk that contains the data to insert in memory. If an option path is not present, the buffer is created and treated as a **new empty buffer**.

* ```sections``` - ```offset``` : Describes the offset from the provided on-disk file where to start copying data.

* ```sections``` - ```address``` : Describes the virtual address where this memory area should start.


* ```sections``` - ```size``` : Describes the number of bytes that should be copied from file "path" starting at offset "offset" into the emulator memory space.

* ```sections``` - ```perms``` : A combination of permissions to apply on the new memory area.



## emu_heap

emu_heap section is used to store a new allocation with ASAN checks. 

/!\  alloc and free function hooks must be defined. See [Ghidralligator Hooks](./user_hook.md) for more information.

* ```emu_heap```             : Top-level container that aggregates the layout of the heap memory.

* ```emu_heap``` - ```address``` : Start address of the heap area.

* ```emu_heap``` - ```size``` : Size of the heap.



