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

#ifndef STRUCTS_H
#define STRUCTS_H

#include <ctime>
#include "globals.h"

using namespace ghidra;

// set_variable_default config struct
typedef struct {
   string name;
   uint64_t value;
} variablesDefault;



// Section / Segment config struct
typedef struct {
   uint64_t virtual_address;
   uint64_t offset;
   size_t size;
   string perm_id;
   string name;
   string src_path;
   unsigned char* data = NULL;
} sectionConfig;


// Single register definition (we don't want to hardcode any register name oustide of the configuration file)
typedef struct {
   string name;
   uint64_t value;
} registersConfig;



// Act as the main MMU
// Each section
// Store the information related to a memory section
typedef struct {
  bool bFreeAfterEmu = false; // Delete after each emulation loop (Ex: true for test_case mem perm)
  size_t size = 0;
  bool is_dirty = false;
  uint64_t virtual_address = 0;
  uint8_t* permissions = NULL;
  vector< pair <long, uint32_t> > dirty_list;
} sectionInfo;


// Store all of the permissions of the various memory segments
typedef struct {
  vector<sectionInfo> sections;
  vector<ulong> whitelist;
} memoryInfo;


// Store all of the permissions of the various memory segments
typedef struct {
  unsigned long previous_location = 0;
  unsigned char* afl_area_ptr = NULL;
  unsigned int* afl_shared = NULL;
  unsigned int* afl_fake = NULL;
  const int afl_forksrv_fd_read = 198;
  const int afl_forksrv_fd_write = 199;
  int afl_map_size = 65536;
  bool crash;
} configAFL;


// Loader configuration file structure
typedef struct {
  string sla_path;
  vector<variablesDefault> variables_default;
  string target;
  string trace_file;
  uint64_t start_address;
  vector<ulong> stop_addresses;
  size_t stop_address_number;
  bool fuzz_mode;
  bool replay_mode;
  size_t section_number;
  int32_t persist_nb;
  uint8_t* test_case;
  uint32_t test_case_len;
  ofstream trace_file_out;
  configAFL* AFL;
  vector<registersConfig> registers;
  vector<sectionConfig> sections;
  uint64_t emu_heap_begin;
  uint64_t emu_heap_end;
} localConfig;



// Hold data related to a single emulator memory section
typedef struct {
  uint64_t baseaddr;
  int32_t length;
  unsigned char *data;
  string name;
} loader_section;



#endif
