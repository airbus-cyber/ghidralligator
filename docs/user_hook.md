# Ghidralligator - User Hook File

## Introduction
Ghidralligator supports the insertion of user-defined hooks that are triggered during the emulation. The goal of such hooks can vary from modifying a specific function return value during emulation to the re-implementation of external library functions or hardware access.

It can also become interesting when dealing with syscalls or interruptions that the emulator have no idea about.

Even if the emulation is available without the need to write a user hook file (only in replay mode and under specific conditions), it is nearly impossible to fuzz a piece of code without a proper user hook file, as this is the place where the test-case insertion should be defined.

Allocation functions must be hooked in order to detect memory corruption (ASAN).


Each of the listed functions below is mandatory in a user hook file. In the case where one (or several) of them is not required in a specific context, the function should be left blank.

### Template

For the majority of the Ghidralligator usage, the following template can be used as a starting point:
```Cpp
#include <cstdio>
#include "globals.h"
#include "fuzzers.h"
#include "memory.h"

// Register this particular fuzzer backend to the emulator for multiple hooks files cohabitation
namespace change_me {
  

  // Define where to trigger the insertion routine callback (can be different than the start address of the emulation)
  unsigned long int get_insert_point() {
    return G_LOCAL_CONFIG.start_address;
  }


  // This function is used to describe how to write the test_case into the target program.
  void insert_test_case(Emulate* emulate, uint8_t* test_case, uint64_t test_case_len, bool* ret_mode) {

    // Add code here

    *ret_mode = false;
    return;
  };


  // This function is used to insert user defined hooks and interuptions routines in the emulator
  std::map<uint64_t, BreakCallBack*> register_user_hooks() {
    
    std::map<uint64_t, BreakCallBack*> hook_map;
   
    // Add code here

    debug_print("[Loader]  %ld user-defined hooks applied\n", hook_map.size());
    return hook_map;
  };


  // This function is used to defined "user defined" opcodes hooks
  std::map<string, BreakCallBack*> register_opcodes_hooks() {
    std::map<string, BreakCallBack*> opcode_hooks;

    // This is the place where to add opcodes handler
    ForceCrashCallback* force_crash_callback = new ForceCrashCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"sysenter", force_crash_callback));

    log_info("[Loader]  %ld callback(s) for opcodes applied\n", opcode_hooks.size());
    return opcode_hooks;
  };


 // Register the user-defined callback with a unique identifier
 fuzz_target Fuzz_Target("change_me", get_insert_point, insert_test_case, register_user_hooks, register_opcodes_hooks);
};
```

### Register a target
In the previous tutorial, when writing a configuration file, the ```target``` field was ignored and set to a unique value. This value is used to identify the corresponding hook file when several of them are available at the same time.

To register a hook file and make it points to a specific configuration file (or vice versa), the ```change_me``` strings in the template should be updated. For instance, if the configuration file has the entry:
```json
[...]
    "target"       : "my_first_hook",    
[...]
```

The template becomes:
```Cpp
#include <cstdio>
#include "globals.h"
#include "fuzzers.h"
#include "memory.h"

namespace my_first_hook {
  [...]
 fuzz_target Fuzz_Target("my_first_hook", get_insert_point, insert_test_case, register_user_hooks, register_opcodes_hooks);
};
```

### Insertion routine
This part may be the most important of the user hook file, as it is related to test-case insertion during fuzzing (and also in replay mode when an input is given as an argument).

This function should be carefully written and avoid unnecessary code, as it will be executed at each emulation loop during fuzzing, which can degrade the fuzzer's performances if not optimized.

The ```insert_test_case``` function and the ```get_insert_point``` function are the ones we want to focus on.

The second one ```get_insert_point``` should return to the address where the test-case insertion is happening. It gives flexibility to the user hook file author.

For instance, if the insertion should be triggered at the address ```0x11223344```, the corresponding function becomes:
```Cpp
  uint64_t get_insert_point() {
    return 0x11223344;
  }
```

By default, the template provides a way to register the insertion point at the first address of the emulation, without having to write it down:
```Cpp
  uint64_t get_insert_point() {
    return G_LOCAL_CONFIG.start_address;
  }
```

The ```insert_test_case``` function takes the current test-case and its size as a parameter. It should perform the memory manipulation needed to write it in memory at the correct location.

For instance, if we want to write the test-case in a buffer located at ```0xF00DBABE```,  and to write the address and size of the buffer in the registers ```eax``` and ```ebx``` the insertion routine becomes:
```Cpp
void insert_test_case(Emulate* emulate, uint8_t* test_case, uint64_t test_case_len, bool* ret_mode) {

    MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();

    mem_write(0xF00DBABE, test_case, test_case_len, mem); 
    
    mem->setValue("eax", 0x20000000);
    mem->setValue("ebx", test_case_len);
 
    *ret_mode = false;
    return;
```


### Adding some custom callback

If the target binary is calling some external library functions or hardware access, and we want to hook them, we can use the ```register_user_hooks``` function.

It works by populating a map with a set of addresses and callback functions.

If we want to hook the putchar function. We locate the first putchar instruction (address 0x8051d80 in our case):
```Cpp
std::map<uuint64_t, BreakCallBack*> register_user_hooks() {
    std::map<uint64_t, BreakCallBack*> hook_map;
   
    PutcharCallback* putchar_callback = new PutcharCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x8051d80, putchar_callback));

    debug_print("[Loader]  %ld user-defined hooks applied\n", hook_map.size());
    return hook_map;
  };
```

And once again, this ```PutcharCallback``` should be defined in the user hook file:
```Cpp
class PutcharCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool PutcharCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t save_eip = 0;
  uint32_t esp = mem->getValue("ESP");
  uint32_t char2print = 0;

  if (!mem_read_uint32_le(mem, esp+0, &save_eip)) {
      log_error("[HOOK] putchar: Failed to get save_eip\n");
      exit(-1);
  }

  if (!mem_read_uint32_le(mem, esp+4, &char2print)) {
      log_error("[HOOK] putchar: Failed to get arg\n");
      exit(-1);
  }


  log_info("[HOOK] putchar 0x%x : %c\n", char2print, char2print);
  emulate->setExecuteAddress(Address(ram, save_eip));
  return true;
};

```

As seen in this ```PutcharCallback```, it is up to the callback code to redirect the execution flow. This can be done by specifying a hardcoded return address value, or by dynamically retrieving it (from a special register, or by reading the stack).

A set of multiple examples can be found under the ```./user_hooks/``` folder. 

Final point, the user_hook file must have a name that ends with ```_hooks.cc``` in order to be compiled.


### ASAN hooks

In order to activate heap memory corruption, special hooks have to be done.

Be sure to define "emu_heap" section in the configuration file. All new allocations will be stored in it.

Locate the allocator function and add a hook on the first instruction:
 * Allocator functions must be replaced by ```heap_allocate```.
 * Free functions must be replaced by ```heap_free```.

 Here is an example of an x86 program with malloc and free functions starting respectively at 0x805dbd0 and 0x805e180:

```Cpp

  std::map<uint64_t, BreakCallBack*> register_user_hooks() {
    std::map<uint64_t, BreakCallBack*> hook_map;
    
    // This is the place where to add new callbacks

    // ASAN callbacks
    MallocCallback* malloc_callback = new MallocCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x805dbd0, malloc_callback));

    FreeCallback* free_callback = new FreeCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x805e180, free_callback));


```

The ```MallocCallback``` and  ```FreeCallback``` should be defined in the user hook file:

```Cpp

// hook malloc for ASAN feature
class MallocCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool MallocCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t size = 0;
  uint32_t save_eip = 0;
  uint32_t esp = mem->getValue("ESP");
  uint32_t addr_buf = 0;


  if (!mem_read_uint32_le(mem, esp+4, &size)) {
      log_error("[HOOK] malloc: Failed to get size\n");
      exit(-1);
  }
  if (!mem_read_uint32_le(mem, esp+0, &save_eip)) {
      log_error("[HOOK] malloc: Failed to get save_eip\n");
      exit(-1);
  }

  log_info("[HOOK] malloc: size: 0x%X\n", size);

  addr_buf = (uint32_t)heap_allocate(size, false, ram, mem);
  mem->setValue("EAX", addr_buf);

  emulate->setExecuteAddress(Address(ram, save_eip));
  return true;
};



// hook free for ASAN feature
class FreeCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool FreeCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t addr_buf = 0;
  uint32_t save_eip = 0;
  uint32_t esp = mem->getValue("ESP");

  if (!mem_read_uint32_le(mem, esp+4, &addr_buf)) {
      log_error("[HOOK] free: Failed to get buffer address\n");
      exit(-1);
  }
  if (!mem_read_uint32_le(mem, esp+0, &save_eip)) {
      log_error("[HOOK] free: Failed to get save_eip\n");
      exit(-1);
  }

  log_info("[HOOK] free: 0x%X\n", addr_buf);

  if (heap_free(addr_buf)) {
      // chunk successfully freed in emu_heap section
      emulate->setExecuteAddress(Address(ram, save_eip));
      return true;
  }

  // Buffer not allocated with heap_allocate
  // let the program free it...
  return false;
};


```




