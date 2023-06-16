/*
 * Ghidralligator
 *
 * Copyright 2023 by Airbus - Guillaume Orlando, Flavian Dola
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include "globals.h"
#include "fuzzers.h"
#include "memory.h"
#include "utils.h"

//////////////// Callbacks ///////////////////



// hook malloc for ASAN feature
class aarch64_test_MallocCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool aarch64_test_MallocCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t size = mem->getValue("x0");
  uint64_t lr = mem->getValue("x30");
  uint64_t addr_buf = 0;


  log_info("[HOOK] malloc: size: 0x%X\n", size);

  addr_buf = heap_allocate(size, true, ram, mem);
  mem->setValue("x0", addr_buf);

  emulate->setExecuteAddress(Address(ram, lr));
  return true;
};



// hook free for ASAN feature
class aarch64_test_FreeCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool aarch64_test_FreeCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint64_t addr_buf = mem->getValue("x0");
  uint64_t lr = mem->getValue("x30");

  log_info("[HOOK] free: 0x%lx\n", addr_buf);

  if (heap_free(addr_buf)) {
      // chunk successfully freed in emu_heap section
      emulate->setExecuteAddress(Address(ram, lr));
      return true;
  }

  // Buffer not allocated with heap_allocate
  // let the program free it...
  return false;
};




// hook printf
class aarch64_test_PrintfCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool aarch64_test_PrintfCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint64_t lr = mem->getValue("x30");
  uint64_t address_char = mem->getValue("x0");
  char* pChar = NULL;


  if (mem_get_string(mem, address_char, &pChar)) {
      log_info("[HOOK] printf: %s\n", pChar);
      free(pChar);
      pChar = NULL;
  } else {
      log_info("[HOOK] printf: Failed to get string\n");
  }

  emulate->setExecuteAddress(Address(ram, lr));
  return true;
};



// hook putchar
class aarch64_test_PutcharCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool aarch64_test_PutcharCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint64_t lr =  mem->getValue("x30");
  uint64_t char2print = mem->getValue("x0");


  log_info("[HOOK] putchar 0x%x : %c\n", char2print, char2print);
  emulate->setExecuteAddress(Address(ram, lr));
  return true;
};



// hook puts
class aarch64_test_PutsCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool aarch64_test_PutsCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint64_t lr = mem->getValue("x30");
  uint64_t address_char = mem->getValue("x0");
  char* pChar = NULL;

  if (mem_get_string(mem, address_char, &pChar)) {
      log_info("[HOOK] puts: %s\n", pChar);
      free(pChar);
      pChar = NULL;
  } else {
      log_info("[HOOK] puts: Failed to get string\n");
  }

  emulate->setExecuteAddress(Address(ram, lr));
  return true;
};



//////////////////////////////////////////////


// Register this particular fuzzer backend to the emulator for multiple hooks files cohabitation
namespace aarch64_test {
  

  // Define where to trigger the insertion routine callback (can be different than the start address of the emulation)
  uint64_t get_insert_point() {
    return G_LOCAL_CONFIG.start_address;
  }


  // This function is used to describe how to write the test_case into the target program.
  void insert_test_case(Emulate* emulate, uint8_t* pTest_case, uint64_t test_case_len, bool* ret_mode) {

      MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
      AddrSpace *spc = mem->getTranslate()->getSpaceByName("ram");

      uint64_t addr_test_case = 0;
      uint64_t x29 = mem->getValue("x29");


      if (test_case_len > 0x100) {
        emulate->setHalt(true);
        return;
      }

      // pReq => x29-0x18
      // szReq => x29-0x1c

      addr_test_case = heap_allocate(test_case_len, true, spc, mem);
      if (addr_test_case == 0) {
          log_error("insert_test_case: Failed to allocate virtual memory for test_case - sz: 0x%lx\n", test_case_len);
          exit(-1);
      }

      mem_write(addr_test_case, pTest_case, test_case_len, mem);

      log_debug("insert: addr_test_case (x29-0x18): 0x%lx\n", x29-0x18);
      mem->setValue(spc, x29-0x18, 8, addr_test_case);
      log_debug("insert: test_case_len (x29-0x1c): 0x%lx\n", x29-0x1c);
      mem->setValue(spc, x29-0x1c, 4, test_case_len);

      *ret_mode = false;
      return;
    };




  // This function is used to insert user defined hooks and interuptions routines in the emulator
  std::map<uint64_t, BreakCallBack*> register_user_hooks() {
    std::map<uint64_t, BreakCallBack*> hook_map;
    
    // This is the place where to add new callbacks

    // ASAN callbacks
    aarch64_test_MallocCallback* malloc_callback = new aarch64_test_MallocCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x100003ef0, malloc_callback));

    aarch64_test_FreeCallback* free_callback = new aarch64_test_FreeCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x100003ee4, free_callback));




    // printf callbacks
    aarch64_test_PrintfCallback* printf_callback = new aarch64_test_PrintfCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x100003efc, printf_callback));



    log_info("[Loader]  %ld user-defined hooks applied\n", hook_map.size());
    return hook_map;
  };



  // This function is used to defined "user defined" opcodes hooks
  std::map<string, BreakCallBack*> register_opcodes_hooks() {
    std::map<string, BreakCallBack*> opcode_hooks;

    // This is the place where to add opcodes handler

    log_info("[Loader]  %ld callback(s) for opcodes applied\n", opcode_hooks.size());
    return opcode_hooks;
  };


 // Register the user-defined callback with a unique identifier
 fuzz_target Fuzz_Target("aarch64_test", get_insert_point, insert_test_case, register_user_hooks, register_opcodes_hooks);
};


