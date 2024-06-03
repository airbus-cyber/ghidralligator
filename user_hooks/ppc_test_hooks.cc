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
#include <iostream>
#include "globals.h"
#include "fuzzers.h"
#include "memory.h"
#include "utils.h"

//////////////// Callbacks ///////////////////






// hook malloc for ASAN feature
class ppc_test_MallocCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool ppc_test_MallocCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t size = mem->getValue("r3");
  uint32_t lr = mem->getValue("LR");
  uint32_t addr_buf = 0;
  //uint32_t addr_end = 0;
  //uint32_t o = 0;

  log_info("[HOOK] malloc: size: 0x%x\n", size);

  addr_buf = (uint32_t)heap_allocate(size, true, ram, mem);

  /*
  // force align on 4 bytes
  // otherwise valid memset, memcpy call will failed with ASAN check...
  // remove check of read before write (ghidra implementation of swl instruction read buffer before writing it...)
  o = (addr_buf+size) % 4;
  if (o != 0) {
    addr_end = addr_buf + size + (4 - o);
  } else {
    addr_end = addr_buf + size;
  }
  log_debug("MallocCallback: begin: 0x%x end: 0x%x\n", addr_buf, addr_end);
  if(!set_emulated_memory_perms(PERM_READ|PERM_WRITE, addr_buf, addr_end-addr_buf)) {
      log_error("MallocCallback: Failed assign permissions\n");
      exit(-1);
  }
  */

  mem->setValue("r3", addr_buf);

  emulate->setExecuteAddress(Address(ram, lr));
  return true;
};



// hook free for ASAN feature
class ppc_test_FreeCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool ppc_test_FreeCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t addr_buf = mem->getValue("r3");
  uint32_t lr = mem->getValue("LR");

  log_info("[HOOK] free: 0x%x\n", addr_buf);

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
class ppc_test_PrintfCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool ppc_test_PrintfCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t lr = mem->getValue("LR");
  uint32_t address_char = mem->getValue("r3");;
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
class ppc_test_PutcharCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool ppc_test_PutcharCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t lr = mem->getValue("LR");
  uint32_t char2print = mem->getValue("r3");

  log_info("[HOOK] putchar 0x%x : %c\n", char2print, char2print);
  emulate->setExecuteAddress(Address(ram, lr));
  return true;
};



// hook puts
class ppc_test_PutsCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool ppc_test_PutsCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t lr = mem->getValue("LR");
  uint32_t address_char = mem->getValue("r3");
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



// hook strtol
// partial implementation
class ppc_test_StrtolCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool ppc_test_StrtolCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t lr = mem->getValue("LR");
  uint32_t addr_nptr = mem->getValue("r3");
  //uint32_t addr_endptr = mem->getValue("r4");
  uint32_t base = mem->getValue("r5");
  uint32_t res = 0;
  char* nptr = 0;

  if(!mem_get_string(mem, addr_nptr, &nptr)) {
    log_error("StrtolCallback: Error get nptr\n");
    exit(-1);
  }

  res = (uint32_t)strtol(nptr, 0, base);
  mem->setValue("r3", res);
  log_info("[HOOK] strtol: 0x%x\n", res);

  if (nptr != 0) {
      free(nptr);
  }

  emulate->setExecuteAddress(Address(ram, lr));
  return true;
};

//////////////////////////////////////////////


// Register this particular fuzzer backend to the emulator for multiple hooks files cohabitation
namespace ppc_test {


  // Define where to trigger the insertion routine callback (can be different than the start address of the emulation)
  uint64_t get_insert_point() {
    return G_LOCAL_CONFIG.start_address;
  }


  // This function is used to describe how to write the test_case into the target program.
  void insert_test_case(Emulate* emulate, uint8_t* pTest_case, uint64_t test_case_len, bool* ret_mode) {

    MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
    AddrSpace *spc = mem->getTranslate()->getSpaceByName("ram");
    uint32_t addr_argv = 0;
    uint32_t addr_test_case = 0;
    uint8_t* pMy_test_case = 0;
    uint64_t my_test_case_len = 0;

    uint32_t be_tmp = 0;
    uint32_t o = 0;

    if (test_case_len > 0x100) {
      emulate->setHalt(true);
      return;
    }

    addr_argv = heap_allocate(8, true, spc, mem);

    // add null byte
    my_test_case_len = test_case_len+1;

    // align on 8 bytes (if not strlen failed because of ASAN)
    o = my_test_case_len % 8;
    if (o != 0) {
        my_test_case_len = my_test_case_len + (8 - o);
    }

    pMy_test_case = (uint8_t*)malloc(my_test_case_len);
    if (pMy_test_case == NULL) {
        log_error("insert_test_case: Error alloc sz: 0x%x\n", my_test_case_len);
        exit(-1);
    }
    memset(pMy_test_case, 0, my_test_case_len);
    memcpy(pMy_test_case, pTest_case, test_case_len);



    addr_test_case = heap_allocate(my_test_case_len, true, spc, mem);
    if (addr_test_case == 0) {
        log_error("insert_test_case: Failed to allocate virtual memory for test_case - sz: 0x%lx\n", my_test_case_len);
        exit(-1);
    }
    mem_write(addr_test_case, pMy_test_case, my_test_case_len, mem);

    free(pMy_test_case);
    pMy_test_case = 0;

    // write addr_test_case to argv[1]
    be_tmp = uint32_reverse_endianness(addr_test_case);
    mem_write(addr_argv+4, (uint8_t*)&be_tmp, 4, mem);

    //argc = 2
    mem->setValue("r3", 2);

    // argv
    mem->setValue("r4", addr_argv);

    *ret_mode = false;
    return;
  };




  // This function is used to insert user defined hooks and interuptions routines in the emulator
  std::map<uint64_t, BreakCallBack*> register_user_hooks() {
    std::map<uint64_t, BreakCallBack*> hook_map;

    // This is the place where to add new callbacks

    // ASAN callbacks

    ppc_test_MallocCallback* malloc_callback = new ppc_test_MallocCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x10019b80, malloc_callback));

    ppc_test_FreeCallback* free_callback = new ppc_test_FreeCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x1001a3f0, free_callback));



    // printf callbacks
    ppc_test_PrintfCallback* printf_callback = new ppc_test_PrintfCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x10008d80, printf_callback));

    ppc_test_PutcharCallback* putchar_callback = new ppc_test_PutcharCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x10009ed0, putchar_callback));

    ppc_test_PutsCallback* puts_callback = new ppc_test_PutsCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x10009c00, puts_callback));


    // strtol
    ppc_test_StrtolCallback* strtol_callback = new ppc_test_StrtolCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x10007e30, strtol_callback));


    log_info("[Loader]  %ld user-defined hooks applied\n", hook_map.size());
    return hook_map;
  };



  // This function is used to defined opcodes hooks
  std::map<string, BreakCallBack*> register_opcodes_hooks() {
    std::map<string, BreakCallBack*> opcode_hooks;

    // This is the place where to add opcodes handler

    log_info("[Loader]  %ld callback(s) for opcodes applied\n", opcode_hooks.size());
    return opcode_hooks;
  };
 // Register the user-defined callback with a unique identifier
 fuzz_target Fuzz_Target("ppc_test", get_insert_point, insert_test_case, register_user_hooks, register_opcodes_hooks);
};


