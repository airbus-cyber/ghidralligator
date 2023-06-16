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

#ifndef AFL_H
#define AFL_H

#include "globals.h"

void afl_end_testcase(int32_t status);
void afl_start_forkserver();
uint32_t afl_next_testcase(uint8_t *buf, uint32_t max_len);
void afl_reset_trace();
void afl_init_shm();
void afl_update_bitmap(uint64_t cur_loc);
void afl_update_int_bitmap(uint64_t cur_loc);

#endif
