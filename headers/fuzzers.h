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

#ifndef FUZZERS_H
#define FUZZERS_H

#include "globals.h"

// Multiple fuzzer targets inspired by https://github.com/0vercl0k/wtf/blob/e7469eed9205117c874b61b5990c05f2c9045e13/src/wtf/targets.cc
struct fuzz_target {
  using get_insert_point_t 		    = uint64_t (*)();
  using insert_test_case_t		    = void (*)(Emulate*, uint8_t*, uint64_t, bool*);
  using register_user_hooks_t       = std::map<uint64_t, BreakCallBack*> (*)();
  //using register_opcodes_hooks_t    = std::vector<string> (*)();
  using register_opcodes_hooks_t    = std::map<string, BreakCallBack*> (*)();
  
  explicit fuzz_target(
      const string &target_name, 
      const get_insert_point_t _get_insert_point,
      const insert_test_case_t _insert_test_case,
      const register_user_hooks_t _register_user_hooks,
      const register_opcodes_hooks_t _register_opcodes_hooks
  );

  std::string target_name;
  get_insert_point_t  get_insert_point = NULL;
  insert_test_case_t insert_test_case = NULL;
  register_user_hooks_t register_user_hooks = NULL;
  register_opcodes_hooks_t register_opcodes_hooks = NULL;
};


struct fuzz_target_struct {
  std::vector<fuzz_target> fuzz_target_vec;

  fuzz_target *GetTarget(const string &target_name);
  
  void ShowTargets();
  void RegisterTarget(const fuzz_target &Target);
  
  static fuzz_target_struct &Instance() {
    static fuzz_target_struct fuzz_target_vec;
    return fuzz_target_vec;
  }
};

#endif

