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

#ifndef UTILS_H
#define UTILS_H

#include "globals.h"

bool mem_read_uint32_le(MemoryState *mem, uint64_t addr, uint32_t* pOvalue );
bool mem_get_string(MemoryState *mem, uint64_t addr, char** ppOstr);
uint32_t uint32_reverse_endianness(uint64_t value);
bool is_reg_file(const char *path);
void log_debug(const char* format, ...);
void log_info(const char* format, ...);
void log_error(const char* format, ...);
void hexdump(const void* data, size_t size);
void dump_register(EmulatePcodeCache* pEmul);
MemoryState reset_registers(MemoryState memstate);
void crash_handler(string msg, uint64_t address, uint64_t pc);


class PcodeRawOut : public PcodeEmit {
public:
  bool jump;
  virtual void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize);
};


class ForceCrashCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
  virtual bool pcodeCallback(PcodeOpRaw *curop);
};


class AssemblyRaw : public AssemblyEmit {
public:
  virtual void dump(const Address &addr,const string &mnem,const string &body) {
    log_info("0x%lx: %s %s\n", addr.getOffset(), mnem.c_str(), body.c_str());
  }
};


class EmuLoadImage : public LoadImage {
  vector<loader_section> sections;
public:
  EmuLoadImage(uintb ad,uint1 *ptr,int4 sz, string nm) : LoadImage("nofile") { 
    // Populate our section vector with the first declared section details
    add_new_section(ad, ptr, sz, nm);
  }
  virtual void loadFill(uint1 *ptr, int4 size, const Address &addr);
  virtual string getArchType(void) const { return "myload"; }
  virtual void adjustVma(long adjust) { }
  virtual void add_new_section(uintb ad, uint1 *ptr, int4 sz, string nm) {
    // Populate our section vector with the newly declared section details
    loader_section newSection;
    newSection.baseaddr = ad;
    newSection.length   = sz;
    newSection.data     = ptr;
    newSection.name     = nm;
    sections.push_back(newSection);
    log_info("[Loader]  Section '%s' loaded (%x)\n", nm.c_str(), ptr[0]);
  }
};


class TerminateCallBack : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};


class blank_hook : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};


class EmuPcodeCache : public EmulatePcodeCache {
public:
    void executeStore(void);
    void executeLoad(void);
    EmuPcodeCache(Translate *t, MemoryState *s, BreakTable *b);
};

#endif
