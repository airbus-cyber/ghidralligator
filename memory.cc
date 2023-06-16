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

#include <algorithm>
#include <cstdio>
#include "globals.h"
#include "memory.h"

#define G_HEAP_GUARD_SIZE 10

uint64_t G_CURRENT_ALLOC_ADDR = 0;





sectionInfo get_memory_section_from_address(uint64_t address, bool* inRange, size_t size, uint32_t* seg_idx);
bool _mem_get_string(MemoryState *mem, uint64_t addr, char* pOstr, size_t* pLenOstr);






// Manualy set the permissions for a chunk of memory (allocated by the ghidra emulator or by VirtualMemoryCreateBlock() / HeapCreateBlock())
// THIS FUNCTION DOES NOT CHECK IF THE GIVEN TARGET ADDRESS IS VALID, USE AT YOUR OWN RISK
bool set_emulated_memory_perms(uint8_t new_perms, uint64_t start_address, size_t length) {
  uint32_t i = 0;
  bool is_in_range = false;
  sectionInfo section = get_memory_section_from_address(start_address, &is_in_range, length, &i);
  if (!is_in_range) {
      return false;
  }
  uint64_t perm_offset = start_address - section.virtual_address;
  
  // Set the new permissions for the given chunk
  for (int i = 0; i < length; i++) {
     section.permissions[perm_offset + i] = new_perms;
  }
  
  return true;
};





// free memory permission buffer marked after eached emulation loop
void memory_free_tmp_permissions() {
    uint32_t idx2free = -1;
    bool bTmpPermFound = false;
    uint32_t idx = 0;

    while (1) {
        idx = 0;
        idx2free = 0;
        for (auto& sec : G_MEMORY_INFO.sections) {
            if (sec.bFreeAfterEmu == true) {
                bTmpPermFound = true;
                idx2free = idx;
                if (sec.permissions != NULL) {
                    free(sec.permissions);
                }
                break;
            }
            idx++;
        }

        if (bTmpPermFound) {
            G_MEMORY_INFO.sections.erase(G_MEMORY_INFO.sections.begin() + idx2free);
            bTmpPermFound = false;
        } else {
            // no more sectionPerm to free
            break;
        }
    }
    return;
}





// Create a new dynamic buffer on demand and allocate it in the emulated memory space
bool virtual_memory_allocate(size_t buff_size, uint64_t buff_va, uint8_t buff_perms, bool delete_after_emu) {
  bool res = false;

  sectionInfo NewSection;

  NewSection.size = buff_size;
  NewSection.virtual_address = buff_va;
  NewSection.permissions = (uint8_t*)malloc(NewSection.size);
  if (NewSection.permissions == NULL) {
      log_error("ERROR: virtual_memory_allocate: malloc failed!");
      return res;
  }

  NewSection.bFreeAfterEmu = delete_after_emu;
  memset(NewSection.permissions, buff_perms, NewSection.size);
  G_MEMORY_INFO.sections.push_back(NewSection);
  log_debug("virtual_memory_allocate: New buffer allocated at 0x%lx size: 0x%lx\n", NewSection.virtual_address, NewSection.size);
  res = true;
  return res;
}


bool is_in_emu_heap(uint64_t address) {
    bool res = false;

    if ((address >= G_LOCAL_CONFIG.emu_heap_begin) && (address < G_LOCAL_CONFIG.emu_heap_end)) {
        res = true;
    }

    return res;
}



// Create a new memory buffer on demand (heap)
// 10 bytes reserved before the chunk and 10 bytes after to act as a guard memory region to detect overflows
// Read-After-Write permissions forced on the newly created chunk
// if bAligned == true:
//    Aligned allocated buffer (start address) on 4 bytes

uint64_t heap_allocate(size_t buff_size, bool bAligned, AddrSpace* spc, MemoryState* mem) {
  bool res = false;
  uint64_t address_buf = 0;
  size_t chunksize = 0;
  uint64_t address_chunk = 0;
  uint32_t prefix_heap_guard_size = G_HEAP_GUARD_SIZE;
  uint8_t o = 0;

  if (bAligned) {
      o = (G_CURRENT_ALLOC_ADDR+prefix_heap_guard_size) % 4;
      if ( o % 4 != 0 ) {
          prefix_heap_guard_size = prefix_heap_guard_size + (4 - o);
      }
  }
  chunksize = prefix_heap_guard_size + buff_size + G_HEAP_GUARD_SIZE;
  address_chunk = G_CURRENT_ALLOC_ADDR;


  if (G_CURRENT_ALLOC_ADDR == 0) {
      log_error("heap_allocate: Allocation segment for emaulation is not defined in conf (emu_heap)\n");
      exit(-1);
  }

  res = virtual_memory_allocate(chunksize, address_chunk, PERM_NO_PERM, true);
  if (!res) {
      log_info("heap_allocate: Out of memory\n");
      return 0;
  }
  log_debug("heap_allocate: chunk allocated at 0x%lx\n", address_chunk);

  address_buf = address_chunk + prefix_heap_guard_size;


  // Set permission on prefix guard
  if (!set_emulated_memory_perms(PERM_H_DELIM, G_CURRENT_ALLOC_ADDR, prefix_heap_guard_size)) {
      log_error("heap_allocate: Error unable to set permission on 0x%lx sz:0x%x\n", G_CURRENT_ALLOC_ADDR, prefix_heap_guard_size);
      exit(-1);
  }
  // set permission on user allocated buffer
  if (!set_emulated_memory_perms(PERM_RAW|PERM_READ|PERM_WRITE, address_buf, buff_size)) {
      log_error("heap_allocate: Error unable to set permission on 0x%lx sz:0x%x\n", address_buf, buff_size);
      exit(-1);
  }

  // Set permission on suffix guard
  if (!set_emulated_memory_perms(PERM_H_DELIM, address_buf+buff_size, G_HEAP_GUARD_SIZE)) {
      log_error("heap_allocate: Error unable to set permission on 0x%lx sz:0x%x\n", address_buf+buff_size, G_HEAP_GUARD_SIZE);
      exit(-1);
  }

  G_CURRENT_ALLOC_ADDR = G_CURRENT_ALLOC_ADDR + chunksize;

  /*
  // create the chunk
  unsigned char* pTmpBuf;
  pTmpBuf = (unsigned char*)malloc(chunksize);
  if (pTmpBuf == NULL) {
      log_error("heap_allocate: Unable to allocate chunk size: 0x%lx\n", chunksize);
      exit(-1);
  }
  memset(pTmpBuf, 0xff, chunksize);
  mem->setChunk(pTmpBuf, spc, address_chunk, chunksize);
  free(pTmpBuf);
  */

  log_debug("heap_allocate: address_buf: 0x%llx - size: 0x%lx\n", address_buf, buff_size);

  return address_buf;
}



// Write data into memory
void mem_write(uint64_t address, uint8_t* pData, size_t szData, MemoryState* mem) {

  AddrSpace *spc = mem->getTranslate()->getSpaceByName("ram");

  if (szData == 0) {
    return;
  }
  uint32_t i = 0;
  bool is_in_range = false;
  sectionInfo section = get_memory_section_from_address(address, &is_in_range, 1, &i);

  if (is_in_range == false) {
    crash_handler("mem_write: Requested memory offset is not mapped.", address, 0x0);
    return;
  }
  
  if (section.size == 0) {
    crash_handler("mem_write: The destination buffer does not exist.", address, 0x0);
    return;
  }
  uint32_t offset = address - section.virtual_address;
  uint64_t end_address = address + szData;
  if (end_address > (section.virtual_address + section.size)) {
    crash_handler("mem_write: Requested memory offset out of range for write operation.", address, 0x0);
    return;
  };
  for (uint32_t j = offset; j < (offset + szData); j++) {
    if (!(section.permissions[j] & PERM_WRITE) || (section.permissions[j] == PERM_NO_PERM)) {
      crash_handler("mem_write: Write Access-Violation - Insufficient permissions to write.", address + j, 0x0);
      return;
    }
    if ((section.permissions[j] == PERM_H_DELIM) || (section.permissions[j] == PERM_H_CHUNK)) {
      crash_handler("mem_write: Requested memory offset overwrite a chunk delimiter.", address + j, 0x0);
      return;
    }
    if (section.permissions[j] & PERM_RAW) {
      section.permissions[j] ^= PERM_RAW;
    }
  }
  G_MEMORY_INFO.sections[i].is_dirty = true;
  G_MEMORY_INFO.sections[i].dirty_list.push_back(make_pair(address, szData));

  log_debug("mem_write: write at 0x%lx - sz: 0x%lx\n", address, szData);
  mem->setChunk(pData, spc, address, szData);

  return;
}





// Free a chunk in emu_heap
// return:
//    true: chunk succesfuly freed
//    false: chunk maybe not belonging to emu_heap
bool heap_free(uint64_t address) {
  bool res = false;
  uint32_t i = 0;
  bool is_in_range = false;

  if (!is_in_emu_heap(address)) {
      log_info("heap_free: buffer 0x%lx not in emu_heap\n", address);
      return res;
  }

  sectionInfo section = get_memory_section_from_address(address, &is_in_range, 1, &i);
  if (is_in_range == false) {
    crash_handler("heap_free: Requested memory offset is not mapped.", address, 0x0);
    return res;
  }
  if (section.size == 0) {
    crash_handler("heap_free: The destination buffer does not exist.", address, 0x0);
    return res;
  }


  // TODO: Maybe improve perf:  not free => just put restricted permissions

  log_debug("heap_free: free chunk: addr: 0x%lX - size: 0x%lX\n", G_MEMORY_INFO.sections[i].virtual_address, G_MEMORY_INFO.sections[i].size);
  if (G_MEMORY_INFO.sections[i].permissions != NULL) {
      free(G_MEMORY_INFO.sections[i].permissions);
  }
  G_MEMORY_INFO.sections.erase(G_MEMORY_INFO.sections.begin() + i);

  res = true;
  return res;
}


// Show the emulator memory state, for debug purposes
void debug_show_buffer(uint64_t address, AddrSpace *ram, MemoryState *mem) {
  uint32_t i = 0;
  bool is_in_range = false;
  sectionInfo section = get_memory_section_from_address(address, &is_in_range, 1, &i);
  log_debug("* Buffer start address: %lx\n", section.virtual_address);
  log_debug("* Buffer size: %d\n", section.size);

  uint8_t buffer[4096];
  mem->getChunk(buffer, ram, section.virtual_address, section.size);

  log_debug("* Buffer Content      : ");
  for (uint32_t i = 0; i < section.size ; i++) {
    log_debug("%02x ", buffer[i]);
  }
  log_debug("\n");

  log_debug("* Permissions Content : ");
  for (uint32_t i = 0; i < section.size ; i++) {
    log_debug("%02x ", section.permissions[i]);
  }
  log_debug("\n");
}


// Returns the emulated memory section in which a given address fits in
sectionInfo get_memory_section_from_address(uint64_t address, bool* inRange, size_t size, uint32_t* seg_idx) {
  sectionInfo section;
  for (auto& sec : G_MEMORY_INFO.sections) {
    uint64_t start_address = sec.virtual_address;
    uint64_t end_address = (start_address + sec.size);

    if ((address >= start_address) and (address < end_address) and ((address + size) >= start_address) and ((address + size) <= end_address)) {
      *inRange = true;
      section = sec;
      break;
    }
    *seg_idx = *seg_idx + 1;
  }
  return section;
}






// Reset dirty memory space, trying to be faster than reset_dirty_bytes_memory()
MemoryState reset_precise_dirty(MemoryState memstate, MemoryState originalstate) {
  AddrSpace *ram = memstate.getTranslate()->getSpaceByName("ram");
  for (int i = 0; i < G_MEMORY_INFO.sections.size(); i++) {
     
     if (G_MEMORY_INFO.sections[i].is_dirty) {

        for (auto& elem : G_MEMORY_INFO.sections[i].dirty_list) {
            uint32_t ori_value = originalstate.getValue(ram, elem.first, elem.second);
            memstate.setValue(ram, elem.first, elem.second, ori_value);
        }

       G_MEMORY_INFO.sections[i].dirty_list.clear();
       G_MEMORY_INFO.sections[i].is_dirty = false;
     }

  }
  return memstate;
}




MemoryState restore_original_memory(MemoryState memstate, MemoryState originalstate) {
  AddrSpace *ram = memstate.getTranslate()->getSpaceByName("ram");
  AddrSpace *ram_orig = memstate.getTranslate()->getSpaceByName("ram");

  uint1 *pChunk = NULL;
  for (int i = 0; i < G_MEMORY_INFO.sections.size(); i++) {

        pChunk = (uint1 *)malloc(G_MEMORY_INFO.sections[i].size);
        if (pChunk == NULL) {
            log_error("ERROR: restore_original_memory: Allocation of 0x%lx failed\n", G_MEMORY_INFO.sections[i].size);
            exit(-1);
        }

        originalstate.getChunk(pChunk, ram_orig, G_MEMORY_INFO.sections[i].virtual_address, G_MEMORY_INFO.sections[i].size);
        memstate.setChunk(pChunk, ram, G_MEMORY_INFO.sections[i].virtual_address, G_MEMORY_INFO.sections[i].size);
        G_MEMORY_INFO.sections[i].dirty_list.clear();
        G_MEMORY_INFO.sections[i].is_dirty = false;
        free(pChunk);
  }  
  return memstate;  
}


// Check if the current address is executable
void check_address_perms_exec(uint64_t address) {
  uint32_t i = 0;
  bool is_in_range = false;
  sectionInfo section = get_memory_section_from_address(address, &is_in_range, 1, &i);

  if (!is_in_range) {
    crash_handler("check_address_perms_exec: Requested memory offset not mapped.", address, address);
    return;

  } else {
      int perm_offset = address - section.virtual_address;
      // Check for exec permissions
      if (section.permissions[perm_offset] & PERM_EXEC) {
        return;
      } else {
        crash_handler("check_address_perms_exec: Not enough permissions to exec the requested memory.", address, address);
        return;
      }
  }
  return;
}


// Check the permissions for a read operation on the given virtual address
void check_address_perms_read(uint64_t address, uint64_t pc, size_t size) {
  // Find the sections in wich the memory operation occurs
  bool is_in_range = false;
  uint32_t idx = 0;
  sectionInfo mem = get_memory_section_from_address(address, &is_in_range, size, &idx);

  if (!is_in_range) {
    crash_handler("check_address_perms_read: Requested memory offset not mapped.", address, pc);
    return;

  } else {
      int perm_offset = address - mem.virtual_address;

      for (int i = 0; i < size; i++) {
        // Check for read permissions
        if (mem.permissions[perm_offset] & PERM_READ) {
            ;;
        } else {
          crash_handler("check_address_perms_read: Not enough permissions to read the requested memory.", address, pc);
          return;
        }

        if (mem.permissions[perm_offset] & PERM_RAW) {
          crash_handler("check_address_perms_read: Attempt to read an uninitialized memory address.", address, pc);
          return;
        }
      }
  }
  return;
}


// check the permissions for a write operation on the given virtual address
void check_address_perms_write(uint64_t address, uint64_t pc, size_t size) {
  uint32_t i = 0;

  log_debug("check_address_perms_write: 0x%lx\n", address);

  bool is_in_range = false;
  sectionInfo section_tmp = get_memory_section_from_address(address, &is_in_range, size, &i);

  if (!is_in_range) {
    crash_handler("check_address_perms_write: Requested memory buffer not mapped.", address, pc);
    return;

  } else {
      int perm_offset = address - G_MEMORY_INFO.sections[i].virtual_address;

      // Mark section as dirty for a faster reset tracking (faster not to check if already at true)
      G_MEMORY_INFO.sections[i].is_dirty = true;
      G_MEMORY_INFO.sections[i].dirty_list.push_back(make_pair(address, size));

      log_debug("Dirty Address: 0x%lx\n", address);


      for (int j = 0; j < size; j++) {

        int curr_perm = G_MEMORY_INFO.sections[i].permissions[perm_offset + j];

        // Check for write permissions
        if (curr_perm & PERM_WRITE) {

            // Check for heap corruptions
            if (curr_perm & PERM_NO_PERM ) {
                crash_handler("check_address_perms_write: Insufficient permissions to write.", address + i, 0x0);
                return;
            }

            if ((curr_perm & PERM_H_DELIM) || (curr_perm & PERM_H_CHUNK)) {
                crash_handler("check_address_perms_write: Requested memory offset overwrite a chunk delimiter.", address + i, 0x0);
                    return;
            }




            // Check if we are writing in an uninitialized portion of memory
            if (G_MEMORY_INFO.sections[i].permissions[perm_offset + j] & PERM_RAW) {
                // Update the read after write permissions to mark the memory as initialized now
                G_MEMORY_INFO.sections[i].permissions[perm_offset + j] ^= PERM_RAW;
                //G_MEMORY_PERMISSIONS.sections[i].permissions[perm_offset + j] |= PERM_READ;
            }

        } else {
          // Determine why we can't write here
          crash_handler("check_address_perms_write: Not enough permissions to write to the requested memory.", address, pc);
          return;
        }
      }
  }
  return;
}


