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

#ifndef MEMORY_H
#define MEMORY_H

#include "globals.h"

void memory_free_tmp_permissions();
bool is_in_emu_heap(uint64_t address);
uint64_t heap_allocate(size_t buff_size, bool bAligned, AddrSpace* spc, MemoryState* mem);
bool set_emulated_memory_perms(uint8_t new_perms, uint64_t start_address, size_t length);
void mem_write(uint64_t address, uint8_t* pData, size_t szData, MemoryState* mem);
bool heap_free(uint64_t address);
void debug_show_buffer(uint64_t address, AddrSpace *ram, MemoryState *mem);
MemoryState reset_precise_dirty(MemoryState memstate, MemoryState originalstate);
MemoryState restore_original_memory(MemoryState memstate, MemoryState originalstate);
void check_address_perms_exec(uint64_t address);
void check_address_perms_read(uint64_t address, uint64_t pc, size_t size);
void check_address_perms_write(uint64_t address, uint64_t pc, size_t size);

#endif
