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


fuzz_target::fuzz_target(
    const string &target_name,
    const get_insert_point_t _get_insert_point,
    const insert_test_case_t _insert_test_case,
    const register_user_hooks_t _register_user_hooks,
    const register_opcodes_hooks_t _register_unsuported_opcodes_hooks
) :
    target_name(target_name),
    get_insert_point(_get_insert_point),
    insert_test_case(_insert_test_case),
    register_user_hooks(_register_user_hooks),
    register_opcodes_hooks(_register_unsuported_opcodes_hooks) {
        fuzz_target_struct::Instance().RegisterTarget(*this);
    }


void fuzz_target_struct::RegisterTarget(const fuzz_target &Target) {
  fuzz_target_vec.emplace_back(Target);
}


fuzz_target *fuzz_target_struct::GetTarget(const string &target_name) {
  for (auto &elem : fuzz_target_vec) {
    if (target_name == elem.target_name) {
      return &elem;
    }
  }
  return NULL;
}


void fuzz_target_struct::ShowTargets() {
  log_info("Available user-hooks callback(s):\n");

  for (const auto &elem : fuzz_target_vec) {
    log_info(" * %s\n", elem.target_name.c_str());
  }

}
