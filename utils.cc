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

#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"
#include "globals.h"


bool mem_read_uint32_le(MemoryState *mem, uint64_t addr, uint32_t* pOvalue ) {
    bool res = false;
    AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");

    if (pOvalue == NULL) {
        return res;
    }


    try {
        mem->getChunk((uint8_t*)pOvalue, ram, addr, 4);
        res = true;
    } catch (...) {
        res = false;
    }

    return res;
}



// if call with pOstr == NULL
//     => update pLenOstr with the string 's length (without null byte)
bool _mem_get_string(MemoryState *mem, uint64_t addr, char* pOstr, size_t* pLenOstr) {
    bool res = false;
    bool bGetSize = false;
    unsigned char c = 0;
    AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");

    if (pLenOstr == NULL) {
        return res;
    }

    if (pOstr == NULL) {
        bGetSize = true;
    }

    uint idx = 0;
    while (1) {
        try {
            mem->getChunk((uint8_t*)&c, ram, addr+idx, 1);
        } catch (...) {
            res = false;
            break;
        }

        if (!bGetSize) {
            if (idx >= *pLenOstr) {
                // Overflow
                break;
            }
            *(pOstr+idx) = c;
        }

        if (c == 0) {
            if (bGetSize) {
                *pLenOstr = idx;
            }
            res = true;
            break;
        }
        idx++;
    }
    return res;
}


// Get string
// *ppOStr must be freed by caller
bool mem_get_string(MemoryState *mem, uint64_t addr, char** ppOstr) {
    bool res = false;
    size_t lenChar = 0;

    if (ppOstr == NULL) {
        return res;
    }

    if (_mem_get_string(mem, addr, 0, &lenChar)) {
        // Add for NULL byte
        lenChar++;
        *ppOstr = (char*)malloc(lenChar);
        if (*ppOstr != NULL) {
            if (_mem_get_string(mem, addr, *ppOstr, &lenChar)) {
                res = true;
            }
        }
    }

    if (!res) {
        if (*ppOstr != NULL) {
            free(*ppOstr);
            *ppOstr = NULL;
        }
    }
    return res;
}


uint32_t uint32_reverse_endianness(uint64_t value) {
    uint32_t inv_value = 0;

    inv_value = (value & 0xff000000) >> 24;
    inv_value += ((value & 0xff0000) >> 16) << 8;
    inv_value += ((value & 0xff00) >> 8) << 16;
    inv_value += (value & 0xff) << 24;

    return inv_value;
}






bool is_reg_file(const char *path)
{
    struct stat statbuf;
    stat(path, &statbuf);
    // test for a regular file
    if (S_ISREG(statbuf.st_mode))
        return true;
    return false;
}


// print if -D arg provided
void log_debug(const char* format, ...) {

    va_list args;
    va_start (args, format);
    if (G_LOG_LEVEL >= LOG_LVL_DEBUG) {
        if (G_ENABLE_TRACE) {
            char buff[0x1000];
            vsnprintf(buff, sizeof(buff), format, args);
            string buffer_trace = buff;
            G_LOCAL_CONFIG.trace_file_out.write(buffer_trace.data(), buffer_trace.size());
            G_LOCAL_CONFIG.trace_file_out.flush();
        }
        else {
            vprintf(format, args);
            fflush(stdout);
        }
    }
    va_end (args);
}


// print if -I or -D args provided
void log_info(const char* format, ...) {

    va_list args;
    va_start (args, format);
    if (G_LOG_LEVEL >= LOG_LVL_INFO) {
        if (G_ENABLE_TRACE) {
            char buff[0x1000];
            vsnprintf(buff, sizeof(buff), format, args);
            string buffer_trace = buff;
            G_LOCAL_CONFIG.trace_file_out.write(buffer_trace.data(), buffer_trace.size());
            G_LOCAL_CONFIG.trace_file_out.flush();
        }
        else {
            vprintf(format, args);
            fflush(stdout);
        }
    }
    va_end (args);
}



void log_error(const char* format, ...) {
    va_list args;
    va_start (args, format);

    if (G_ENABLE_TRACE) {
        char buff[0x1000];
        vsnprintf(buff, sizeof(buff), format, args);
        string buffer_trace = buff;
        G_LOCAL_CONFIG.trace_file_out.write(buffer_trace.data(), buffer_trace.size());
        G_LOCAL_CONFIG.trace_file_out.flush();
    }
    else {
        vprintf(format, args);
        fflush(stdout);
    }
    va_end (args);
}



void emu_hexdump(uint64_t addr, size_t size, MemoryState *mem) {
    AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
    uint8_t* pBuf = 0;

    log_info("emu_hexdump 0x%lx - 0x%x\n", addr, size);

    pBuf = (uint8_t*)malloc(size);
    if (pBuf == NULL) {
        goto END_EMU_HEXDUMP;
    }
    memset(pBuf, 0xee, size);
    mem->getChunk(pBuf, ram, addr, size);
    hexdump(pBuf, size);

END_EMU_HEXDUMP:
    if (pBuf != 0) {
        free(pBuf);
    }
}



// Hexdump of the given buffer for visualization and/or debug purposes
void hexdump(const void* data, size_t size) {

    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    log_info("hexdump 0x%lx - 0x%x\n", data, size);
    for (i = 0; i < size; ++i) {
        log_info("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            log_info(" ");
            if ((i+1) % 16 == 0) {
                log_info("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    log_info(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    log_info("   ");
                }
                log_info("|  %s \n", ascii);
            }
        }
    }
}


// Display the current regiters contents
void dump_register(EmulatePcodeCache* pEmul) {

  uint32_t idx = 0;
  uint32_t nb_regs = G_LOCAL_CONFIG.registers.size();
  MemoryState *mem = pEmul->getMemoryState();
  uint64_t reg_value_1 = 0;
  uint64_t reg_value_2 = 0;

  log_info("\n");
  while (idx < (int)(nb_regs / 2)) {
    reg_value_1 = mem->getValue(G_LOCAL_CONFIG.registers[idx].name);
    reg_value_2 = mem->getValue(G_LOCAL_CONFIG.registers[(int)(nb_regs / 2) + idx].name);
    log_info("  %-3s: 0x%08lx | %-3s: 0x%08lx \n", G_LOCAL_CONFIG.registers[idx].name.c_str(), reg_value_1, G_LOCAL_CONFIG.registers[(int)(nb_regs / 2) + idx].name.c_str(), reg_value_2);
    idx++;
  }

  if ((idx*2) < nb_regs) {
    reg_value_1 = mem->getValue(G_LOCAL_CONFIG.registers[idx*2].name);
    log_info("  %-3s: 0x%08lx |\n", G_LOCAL_CONFIG.registers[idx*2].name.c_str(), reg_value_1);
  }
  log_info("\n");
}


// Reset the registers to the local configuration's value
MemoryState reset_registers(MemoryState memstate) {
  for (auto& elem : G_LOCAL_CONFIG.registers) {
    memstate.setValue(elem.name, elem.value);
  }
  return memstate;
}


// Handle crash during emulation
void crash_handler(string msg, uint64_t address, uint64_t pc) {
  // Is this a whitelisted address
  if (std::count(G_MEMORY_INFO.whitelist.begin(), G_MEMORY_INFO.whitelist.end(), pc)) {
    return;
  }

  // replay mode: crash to stdout + reason + stop execution
  if (G_LOCAL_CONFIG.replay_mode) {
    log_error("[Crash] (pc=0x%lx)(access @0x%lx) : %s\n", pc, address, msg.c_str());
    exit(-1);
  }

  G_EMULATION_ABORT_FLAG = 1;
  G_LOCAL_CONFIG.AFL->crash = true;

 }
