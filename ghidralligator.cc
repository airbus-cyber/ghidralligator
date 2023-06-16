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
// Root include for parsing using SLEIGH
#include "sleigh.hh"
#include "emulate.hh"
#include "loadimage.hh"

#include <string>
#include <iostream>
#include <unistd.h>

// JSON parser for configuration file
#include "libs/json.hpp"

// Ghidralligator internals
#include "afl.h"
#include "utils.h"
#include "parser.h"
#include "memory.h"
#include "globals.h"
#include "fuzzers.h"
#include "cmdline.h"

#include <mcheck.h>
#include <stdlib.h>
#include <stdio.h>



using json = nlohmann::json;


void EmuLoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr) {
  uint64_t start = addr.getOffset();
  log_debug("[LOAD] address: 0x%lx size: 0x%x\n", start, size);
  for (auto& sec : sections) {
    uint64_t max_addr = sec.baseaddr + (sec.length - 1);
    if ( ((start >= sec.baseaddr) && (start <= max_addr)) || (((start+size) > sec.baseaddr) && ((start+size-1) <= max_addr)) ) {
        for (int i = 0; i < size; ++i) {
            uint64_t current_offset = start + i;
            if ( (current_offset >= sec.baseaddr) && (current_offset <= max_addr) ) {
                int localIndex = current_offset - sec.baseaddr;
                ptr[i] = sec.data[localIndex];
            }
        }
    }
  }
}



void PcodeRawOut::dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) {
  // Check for a basic block
  if ((opc == 4) | (opc == 5) | (opc == 6) | (opc == 7) | (opc == 8) | (opc == 9) | (opc == 10)) {
    jump = true;
  }

  /*
  if (outvar != (VarnodeData *)0) {
    print_vardata(cout,*outvar);
    cout << " = ";
  }
  cout << get_opname(opc);
  // Possibly check for a code reference or a space reference
  for(int4 i=0;i<isize;++i) {
    cout << ' ';
    print_vardata(cout,vars[i]);
  }
  cout << endl;
  */
};


bool ForceCrashCallback::addressCallback(const Address &addr) {
  log_info("[HOOK][addr]: Force crash at 0x%lx\n", emulate->getExecuteAddress().getOffset());
  G_EMULATION_ABORT_FLAG = 1;
  return true;
};


bool ForceCrashCallback::pcodeCallback(PcodeOpRaw *curop) {
  log_info("[HOOK][pcode]: Force crash at 0x%lx\n", emulate->getExecuteAddress().getOffset());
  G_EMULATION_ABORT_FLAG = 1;
  return true;
};


class InsertGenericCallback : public BreakCallBack {
public:
  const fuzz_target *target;
  virtual bool addressCallback(const Address &addr);
  virtual void setTarget(const fuzz_target *my_target);
};


bool InsertGenericCallback::addressCallback(const Address &addr) {
  bool ret_mode;
  // Call external user-defined insertion routine
  target->insert_test_case(emulate, G_LOCAL_CONFIG.test_case, G_LOCAL_CONFIG.test_case_len, &ret_mode);
  // ret_mode:
  //     true: do not execute current instruction
  //     false: execute current instruction
  //     (see: EmulatePcodeCache::executeInstruction source code)
  return ret_mode;
}


void InsertGenericCallback::setTarget(const fuzz_target *my_target) {
  target = my_target;
}


bool TerminateCallBack::addressCallback(const Address &addr) {
  emulate->setHalt(true);
  log_info("[HOOK]    End of the emulation\n");
  return true;
}





EmuPcodeCache::EmuPcodeCache(Translate *t, MemoryState *s, BreakTable *b) : EmulatePcodeCache(t, s, b) {}


void EmuPcodeCache::executeStore(void) {
    uint64_t val = memstate->getValue(currentOp->getInput(2)); // Value being stored
    uint64_t off = memstate->getValue(currentOp->getInput(1)); // Offset to store at
    AddrSpace *spc = currentOp->getInput(0)->getSpaceFromConst(); // Space to store in

    off = AddrSpace::addressToByte(off, spc->getWordSize());
    log_debug("EmuPcodeCache::executeStore: off: 0x%lx - val: 0x%lx\n", off, val);

    check_address_perms_write(off, currentOp->getAddr().getOffset(), currentOp->getInput(2)->size);

    // Call original func
    EmulatePcodeCache::executeStore();
}



void EmuPcodeCache::executeLoad(void) {

    uint64_t off = memstate->getValue(currentOp->getInput(1));
    AddrSpace *spc = currentOp->getInput(0)->getSpaceFromConst();

    off = AddrSpace::addressToByte(off,spc->getWordSize());
    log_debug("EmuPcodeCache::executeLoad: off: 0x%lx - size: 0x%x\n", off, currentOp->getOutput()->size);

    check_address_perms_read(off, currentOp->getAddr().getOffset(), currentOp->getOutput()->size);

    // Call original func
    EmulatePcodeCache::executeLoad();
}



bool blank_hook::addressCallback(const Address &addr) {
  log_debug("blank hook\n");
  return true;
};


// Initiate the emulator object and apply the configuration on it
static void wrapper_emulation(
        bool track_exec,
        Translate &trans,
        LoadImage &loader,
        const fuzz_target &target) {

    G_EMULATION_ABORT_FLAG = 0;

    // Set up memory state object
    MemoryImage loadmemory(trans.getDefaultCodeSpace(), 8, 4096, &loader);
    MemoryPageOverlay ramstate(trans.getDefaultCodeSpace(), 8, 4096, &loadmemory);
    MemoryHashOverlay registerstate(trans.getSpaceByName("register"), 8, 4096, 4096, (MemoryBank *)0);
    MemoryHashOverlay tmpstate(trans.getUniqueSpace(), 8, 4096, 4096, (MemoryBank *)0);

    MemoryState memstate(&trans);
    memstate.setMemoryBank(&ramstate);
    memstate.setMemoryBank(&registerstate);
    memstate.setMemoryBank(&tmpstate);

    // Copy for fast reset
    MemoryImage ori_loadmemory(trans.getDefaultCodeSpace(), 8, 4096, &loader);
    MemoryPageOverlay ori_ramstate(trans.getDefaultCodeSpace(), 8, 4096, &ori_loadmemory);
    MemoryHashOverlay ori_registerstate(trans.getSpaceByName("register"), 8, 4096, 4096, (MemoryBank *)0);
    MemoryHashOverlay ori_tmpstate(trans.getUniqueSpace(), 8, 4096, 4096, (MemoryBank *)0);

    MemoryState originalmemstate(&trans);
    originalmemstate.setMemoryBank(&ori_ramstate);
    originalmemstate.setMemoryBank(&ori_registerstate);
    originalmemstate.setMemoryBank(&ori_tmpstate);

    BreakTableCallBack breaktable(&trans); 

    EmuPcodeCache emulater(&trans, &memstate, &breaktable);
  

    memstate = reset_registers(memstate);
    emulater.setExecuteAddress(Address(trans.getDefaultCodeSpace(), G_LOCAL_CONFIG.start_address));

    // Register default callbacks
    TerminateCallBack terminatecallback;
    InsertGenericCallback insertcallback;
    insertcallback.setTarget(&target);

    // Needed cause ghidalligator crashes on unsuported pcode (SIGABORT), so fuzzing stop...
    ForceCrashCallback force_crash_callback;

    // Dynamic test-case insertion at arbitrary address (defined in ghidralligator_hooks.cc)
    breaktable.registerAddressCallback(Address(trans.getDefaultCodeSpace(), target.get_insert_point()), &insertcallback);

    // Dynamically register user-defined callback for the emulation (defined in ghidralligator_hooks.cc)
    std::map<uint64_t, BreakCallBack*> callback_hooks = target.register_user_hooks();
    if (!callback_hooks.empty()) {
      for (auto const& [address, callback] : callback_hooks) {
        breaktable.registerAddressCallback(Address(trans.getDefaultCodeSpace(), address), callback);
      }
    }

    // Register stop addresses from the configuration file
    for (int x = 0; x < G_LOCAL_CONFIG.stop_address_number; ++x) {
        log_debug("[Config]  emu        : stop=0x%lx\n", G_LOCAL_CONFIG.stop_addresses[x]);
        breaktable.registerAddressCallback(Address(trans.getDefaultCodeSpace(), G_LOCAL_CONFIG.stop_addresses[x]), &terminatecallback);

    }

    // Dynamically register some hooks for user-defined  opcode during emulation
    std::map<string, BreakCallBack*> opcode_hooks = target.register_opcodes_hooks();
    if (!opcode_hooks.empty()) {
      for(auto const& [opcode_string, callback] : opcode_hooks) {
        log_debug("Opcode callback: %s\n", opcode_string.c_str());
        breaktable.registerPcodeCallback(opcode_string, callback);
      }
    }

    // Init the AFL structure
    configAFL AFL;
    G_LOCAL_CONFIG.AFL = &AFL;
    G_LOCAL_CONFIG.AFL->crash = false;

    if (G_LOCAL_CONFIG.fuzz_mode) {
        // Steps to initialize the communication with AFL through a shared-memory
        afl_init_shm();
        afl_start_forkserver();
    }

    uint32_t len = 0;
    uint8_t buf[0x7fff];

    bool bIsMemRestore = true;

    //mtrace();

    // TMP: test mem cons
    //uint32_t count = 0;

    while(( (G_LOCAL_CONFIG.replay_mode) or (len = afl_next_testcase(buf, sizeof(buf))) > 0)) {
        
        G_CURRENT_ALLOC_ADDR = G_LOCAL_CONFIG.emu_heap_begin;


        if (!bIsMemRestore) {
            // Memory may not have been restored (case of crash/hangs in afl)
            restore_original_memory(memstate, originalmemstate);
            memstate = reset_registers(memstate);
            emulater.setExecuteAddress(Address(trans.getDefaultCodeSpace(), G_LOCAL_CONFIG.start_address));
            bIsMemRestore = true;
        }
        
        // Save the test case so that the callback can access it at insertion time
        if (G_LOCAL_CONFIG.fuzz_mode) {
            G_LOCAL_CONFIG.test_case_len = len;
            G_LOCAL_CONFIG.test_case = buf;
        }

        afl_reset_trace();

        if (G_LOG_LEVEL >= LOG_LVL_INFO) {
            hexdump(G_LOCAL_CONFIG.test_case, G_LOCAL_CONFIG.test_case_len);
        }

        // Emulator related objects
        emulater.setHalt(false);

        // force to update bitmap
        if (G_LOCAL_CONFIG.fuzz_mode) {
            afl_update_bitmap(G_LOCAL_CONFIG.start_address);
        }
        
        PcodeRawOut pcode;

        pcode.jump = false;
        bool record_bb = false;
        G_EMULATION_ABORT_FLAG = 0;
        while(!emulater.getHalt()) {

            // Get current address (relative to the emulator)
            Address pc = emulater.getExecuteAddress();

            // Check if we have the permissions to execute the current address
            if (track_exec) {
              check_address_perms_exec(pc.getOffset());
            }

            if (G_EMULATION_ABORT_FLAG == 1) {
                log_info("emulation aborted at address 0x%lx\n", pc.getOffset());
                if (G_LOCAL_CONFIG.fuzz_mode) {
                    G_LOCAL_CONFIG.AFL->crash = true;
                 }
                // stop emulation
                break;
            }

            if (G_LOCAL_CONFIG.fuzz_mode) {
              if (record_bb) {
                afl_update_bitmap(pc.getOffset());
                record_bb = false;
              }
            }

            if (G_LOG_LEVEL >= LOG_LVL_INFO) {
                AssemblyRaw assememit;
                trans.printAssembly(assememit, pc);
                dump_register(&emulater);
            }

            // Process P-Code and populate our 'pcode' object
            trans.oneInstruction(pcode, pc);

            // manage memory restore in case of crash/hang
            bIsMemRestore = false;

            // Emulate the next instruction
            try {
                emulater.executeInstruction();
            } catch(LowlevelError& ex) {
                printf("[Error] %s\n", ex.explain.c_str());
                G_EMULATION_ABORT_FLAG = 1;
            } catch (...) {
                G_EMULATION_ABORT_FLAG = 1;
            }

            if (pcode.jump) {
                pcode.jump = false;
                record_bb = true;
            }
        } // End while(!emulater.getHalt())
	
        if (G_LOCAL_CONFIG.fuzz_mode) {
          if (G_LOCAL_CONFIG.AFL->crash) {
            // Report the crash to AFL
            afl_end_testcase(0x1);
            G_LOCAL_CONFIG.AFL->crash = false;
          } else {
            // report the execution trace to AFL
            afl_end_testcase(0x0);
          }
        } else {

          //replay mode
          if (G_ENABLE_TRACE) {
            G_LOCAL_CONFIG.trace_file_out.close();
            printf("Execution trace available under '%s'.\n", G_LOCAL_CONFIG.trace_file.c_str());
          }
          return;
        }

        memstate = reset_precise_dirty(memstate, originalmemstate);

        // Reset the registers state back to original
        memstate = reset_registers(memstate);
        emulater.setExecuteAddress(Address(trans.getDefaultCodeSpace(), G_LOCAL_CONFIG.start_address));

        // free buffers (Ex: permission buffers for a test case) allocated for this emulation run
        memory_free_tmp_permissions();

        bIsMemRestore = true;

        /*
        // TMP: test mem cons
        if (count % 1000 == 0) {
            printf("count: %d\n", count);
            fflush(stdout);
        }
        count++;
        */

  }

  // End of the emulation cycle
  
  if (G_LOCAL_CONFIG.fuzz_mode) {
    // Close the AFL communications FD
    close(AFL.afl_forksrv_fd_read);
    close(AFL.afl_forksrv_fd_write);
  }

}


int main(int argc, char **argv) {

  G_LOG_LEVEL      = LOG_LVL_NO_LOG;
  G_ENABLE_TRACE   = false;

  bool have_test_case = false;
  bool have_config    = false;
  bool have_mode      = false;
 
  bool track_exec     = false;
 
  string str_mode;
  string str_config_path;
  string str_test_case_path;
 
  fuzz_target_struct &fuzz_targets = fuzz_target_struct::Instance();
  const fuzz_target *target;
  
  json config;

  // Parse the command line arguments and set various flags accordingly
  cmd_cmdline(
	argc, 
	argv, 
	&have_mode, 
	&have_config, 
	&have_test_case, 
	&str_mode, 
	&str_config_path, 
    &str_test_case_path);

  // Update the cnf structure to store the correct emulation mode
  cmd_set_cnf_mode(have_mode, str_mode, argv);

  // Check the provided configuation file
  cmd_check_config_file(have_config, str_config_path, argv);

  // Check the optional test-case input file
  cmd_test_case(have_test_case, str_mode, argv, str_test_case_path);

  // Check the optional replay tracer options
  cmd_replay();


  // Parse the configuration file to retreive dynamic arguments
  //try {
      std::ifstream f(str_config_path.c_str());
      config = json::parse(f);
  //}
  //catch (...) {
  //  printf("ERROR: Unable to parse config file\n");
  //  exit(-1);
  //}

  
  json sections = config["sections"];
  json regs     = config["registers"];

  try {
    json white    = config["perm_whitelist"];
    parse_whitelist(white);
  } catch(...) { };

  if (sections.size() == 0) {
    printf("CONFIG ERROR: At least one 'sections' entry is required to start the emulation\n");
    exit(-1);
  }

  // Extract some static configuration fields
  parse_static_config(&track_exec, config);
  
  // Iterate over the sections (dynamic number) and extract required fields
  parse_dynamic_sections(sections);

  // Process the registers from the provided configuration file
  parse_registers(regs);

  display_config();

  // Process the fuzzer instance by its target name
  target = fuzz_targets.GetTarget(G_LOCAL_CONFIG.target.c_str());
  if (target == NULL) {
    log_info("User hook not found\n");
    fuzz_targets.ShowTargets();
    log_info("Set to default\n");
    target = fuzz_targets.GetTarget("default");
  } 

  // Manually load the firt section in the emulator memory space
  cnv_loader_extract_section(0);
  EmuLoadImage configLoader(G_LOCAL_CONFIG.sections[0].virtual_address, G_LOCAL_CONFIG.sections[0].data, G_LOCAL_CONFIG.sections[0].size, "TEXT");
       
  // Initialize the permissions identifier map (faster parsing)
  loader_init_map();

  // Create the first section permissions struct
  loader_main_memory_section();
 
  // Process the other sections and load them
  if (G_LOCAL_CONFIG.section_number > 1) {
    for (uint32_t idx = 1; idx < G_LOCAL_CONFIG.section_number; ++idx) {

      // Extract the requested file content and the sections struct's content
      cnv_loader_extract_section(idx);
      configLoader.add_new_section( G_LOCAL_CONFIG.sections[idx].virtual_address, G_LOCAL_CONFIG.sections[idx].data, G_LOCAL_CONFIG.sections[idx].size, G_LOCAL_CONFIG.sections[idx].name );

      // Save the sections
      loader_add_new_section(idx);
    }
  }


  AttributeId::initialize();
  ElementId::initialize();

  // Set up the context object
  ContextInternal context;

  // Set up the assembler/pcode-translator
  string sleighfilename = G_LOCAL_CONFIG.sla_path;

  Sleigh trans(&configLoader,&context);

  // Read sleigh file into DOM
  DocumentStorage docstorage;
  Element *sleighroot = docstorage.openDocument(sleighfilename)->getRoot();
  docstorage.registerTag(sleighroot);
  trans.initialize(docstorage);

  // set_variable_default
  for (auto& elem : G_LOCAL_CONFIG.variables_default) {
      context.setVariableDefault(elem.name, elem.value);
  }

  wrapper_emulation(track_exec, trans, configLoader, *target);
}
