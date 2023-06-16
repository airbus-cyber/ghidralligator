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


// Default hooks
// Do not modify this file!!!

//////////////// Callbacks ///////////////////





//////////////////////////////////////////////


// Register this particular fuzzer backend to the emulator for multiple hooks files cohabitation
namespace my_default {
  

  // Define where to trigger the insertion routine callback (can be different than the start address of the emulation)
  uint64_t get_insert_point() {
      //  return 0;
      return G_LOCAL_CONFIG.start_address;
  }


  // This function is used to describe how to write the test_case into the target program.
  //     ret_mode:
  //         true: do not execute current instruction
  //         false: execute current instruction
  //         (see: EmulatePcodeCache::executeInstruction source code)
  void insert_test_case(Emulate* emulate, uint8_t* test_case, uintb test_case_len, bool* ret_mode) {

    *ret_mode = false;
    return;
  };


  // This function is used to insert user defined hooks and interuptions routines in the emulator
  std::map<uint64_t, BreakCallBack*> register_user_hooks() {
    std::map<uint64_t, BreakCallBack*> hook_map;

    log_info("[Loader]  %ld user-defined hooks applied\n", hook_map.size());
    return hook_map;
  };


  // This function is used to defined "user defined" opcodes hooks
  std::map<string, BreakCallBack*> register_opcodes_hooks() {
    std::map<string, BreakCallBack*> opcode_hooks;

    // This is the place where to add opcodes handler
    //ForceCrashCallback* force_crash_callback = new ForceCrashCallback();
    //opcode_hooks.insert(pair<string, BreakCallBack*>((string)"sysenter", force_crash_callback));

    log_info("[Loader]  %ld callback(s) for opcodes applied\n", opcode_hooks.size());
    return opcode_hooks;
  };
  

 // Register the user-defined callback with a unique identifier
 fuzz_target Fuzz_Target("default", get_insert_point, insert_test_case, register_user_hooks, register_opcodes_hooks);
};


