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

#include "libs/json.hpp"

#include "globals.h"
#include "cmdline.h"
#include "parser.h"


// Returns the perms associated with a string
uint8_t cnv_extract_perm_by_string(string id) {
  // Check if we do not have a corrupted permission ID
  if (G_PERM_ID_MAP.count(id.c_str())) {
    auto val = G_PERM_ID_MAP.find(id.c_str());
    return val->second;
  }
  else {
   log_error("PERMS ERROR: The permission ID '%s' does not exists. Please verify the configuration file\n", id.c_str());
   exit(-1);
  }
}


// Convert a permissions string into its actual type and value
uint8_t cnv_get_permissions_by_id(string id) {
  uint8_t perms = PERM_NO_PERM;
  string delimiter = "|";
  
  // Check if the permissions string contains a delimiter
  if (id.find(delimiter) != std::string::npos) {
  
    // We have multiple permissions to extracts and concatenate
    size_t pos;
    string token;
    while ((pos = id.find(delimiter)) != std::string::npos) {
      token = id.substr(0, pos);    

      perms |= cnv_extract_perm_by_string(token);

      id.erase(0, pos + delimiter.length());
    }
    perms |= cnv_extract_perm_by_string(id);
    return perms;

  } else {
    return cnv_extract_perm_by_string(id);
  }
  log_error("PERMS ERROR: Unable to retreive the permissions ID '%s'. Please verify the configuration file\n", id.c_str());
  exit(-1);
}


// Test if the specified configuration file is reachable
bool cnv_loader_extract_section(uint32_t idx) {
  if (strcmp(G_LOCAL_CONFIG.sections[idx].src_path.c_str(), "local") == 0) {
    if (G_LOCAL_CONFIG.sections[idx].size <= 0) {
        log_error("CONFIG ERROR: Unable to create a new memory segment of size 0x0 (%s)\n", G_LOCAL_CONFIG.sections[idx].name.c_str());
        exit(-1);
     }
     uint8_t* custom_buff = (uint8_t*)malloc(G_LOCAL_CONFIG.sections[idx].size);
     memset(custom_buff, 0, G_LOCAL_CONFIG.sections[idx].size);
     G_LOCAL_CONFIG.sections[idx].data = custom_buff;

  } else {
    FILE *fp;
    fp = fopen(G_LOCAL_CONFIG.sections[idx].src_path.c_str(), "rb");
    if (fp == NULL) {
        log_error("CONFIG ERROR: Unable to open the section file '%s'.\n", G_LOCAL_CONFIG.sections[idx].src_path.c_str());
        exit(-1);
    }

    // Grab the requested content from the file
    fseek(fp, G_LOCAL_CONFIG.sections[idx].offset, SEEK_SET);
    int nb_read = fread(G_LOCAL_CONFIG.sections[idx].data, 1, G_LOCAL_CONFIG.sections[idx].size, fp);

    if (nb_read == 0) {
        log_error("CONFIG ERROR: Unable to extract content from '%s'. Are the offset and sizes coherent ? (%d)\n", G_LOCAL_CONFIG.sections[idx].src_path.c_str(), nb_read);
        exit(-1);
    }
    
    if (nb_read != G_LOCAL_CONFIG.sections[idx].size) {
        log_error("CONFIG ERROR: Unable to grab all requested bytes from '%s'. Is the size coherent ? (%d)\n", G_LOCAL_CONFIG.sections[idx].src_path.c_str(), nb_read);
        exit(-1);
    }

    fclose(fp);
  }

  return true;
}


// Convert a hex/int string into a long
bool cnv_string_2_long(string s, uint64_t* pValue) {
  bool res = false;

  if (pValue == NULL) {
      return res;
  }

  if (s == "none") {
    return res;
  }

  char * p;
  uint64_t n = strtoul( s.c_str(), & p, 0 );
  if ( * p != 0 ) {
    return res;
  }

  *pValue = n;
  res = true;

  return res;

}


// Convert a bool string to a true bool type
bool cnv_to_bool(std::string str, bool* pValue) {
  bool res = false;

  if (pValue == NULL) {
      return res;
  }

  if (strcmp(str.c_str(), "none") == 0) {
    return res;
  }
  std::transform(str.begin(), str.end(), str.begin(), ::tolower);
  std::istringstream is(str);
  bool b;
  is >> std::boolalpha >> b;

  *pValue = b;
  res = true;
  return res;
}


// Extract the 'register' entry from the configuration file
void parse_registers(json regs) {
  // Iterate over the user defined registers names and values
  for (auto& elem : regs) {
     registersConfig reg_struct;
     reg_struct.name   = elem.value("name", "none");
     if (!cnv_string_2_long(elem.value("value", "none"), &reg_struct.value)) {
         log_error("ERROR: Unable to parse register config of %s\n", reg_struct.name.c_str());
         exit(-1);
     }
     G_LOCAL_CONFIG.registers.push_back(reg_struct);
  }
}


// Extract the 'whitelist' entry from the configuration file
void parse_whitelist(json white) {
  // Iterate over the crash / permissions whitelist
  for (auto& elem : white) {
     ulong w_address;
     if (!cnv_string_2_long(elem.value("address", "none"), &w_address)) {
         log_error("ERROR: Unable to parse whitelist\n");
         exit(-1);
     }
     G_MEMORY_INFO.whitelist.push_back(w_address);
  }
}


// Extract the multiple 'sections' entries in the configuration file
void parse_dynamic_sections(json sections) {
  G_LOCAL_CONFIG.section_number = sections.size();

  for (auto& elem : sections) {
     string section_name = elem.value("name", "none");
     string section_path = elem.value("path", "local");
     string section_perm = elem.value("perms", "none");

     if (!check_error_config_value(section_name, "name")) {
         log_error("ERROR: Failed to parse name section\n");
         exit(-1);
     }

     if (!check_error_config_value(section_perm, "perms")) {
         log_error("ERROR: Failed to parse name perms for section %s\n", section_name.c_str());
         exit(-1);
     }

     uint64_t section_va;
     if (!cnv_string_2_long(elem.value("address", "none"), &section_va)) {
        log_error("ERROR: Unable to parse address in %s\n", section_name.c_str());
        exit(-1);
     }

     uint64_t section_off=0;
     if (!cnv_string_2_long(elem.value("offset", "none"), &section_off)) {
        // no section defined => set to 0
        section_off = 0;
     }

     uint64_t section_sz;
     if (!cnv_string_2_long(elem.value("size", "none"), &section_sz)) {
        log_error("ERROR: Unable to parse size in %s\n", section_name.c_str());
        exit(-1);
     }

     int idx = &elem - &sections[0];
     G_LOCAL_CONFIG.sections.push_back(sectionConfig());
     G_LOCAL_CONFIG.sections[idx].name            = section_name;
     G_LOCAL_CONFIG.sections[idx].src_path        = section_path;
     G_LOCAL_CONFIG.sections[idx].size            = section_sz;
     G_LOCAL_CONFIG.sections[idx].offset          = section_off;
     G_LOCAL_CONFIG.sections[idx].virtual_address = section_va;
     G_LOCAL_CONFIG.sections[idx].data = (uint8_t*)malloc(G_LOCAL_CONFIG.sections[idx].size);
     memset(G_LOCAL_CONFIG.sections[idx].data, 0x0, section_sz);
     G_LOCAL_CONFIG.sections[idx].perm_id = section_perm;
  }
}


// Extract 'first-level' entries from the configuration file
void parse_static_config(bool* pTrackExec, json config) {

  G_LOCAL_CONFIG.sla_path       = config.value("sla_file", "none");

  json set_variable_default;
  json j_null;

  set_variable_default = config.value("set_variable_default", j_null);
  if (set_variable_default != j_null) {
      for (auto& elem : set_variable_default) {
         variablesDefault var_struct;
         var_struct.name   = elem.value("name", "none");
         if (!cnv_string_2_long(elem.value("value", "none"), &var_struct.value)) {
             log_error("ERROR: Unable to parse set_variable_default config of %s\n", var_struct.name.c_str());
             exit(-1);
         }
         G_LOCAL_CONFIG.variables_default.push_back(var_struct);
      }
  }

  G_LOCAL_CONFIG.target = config.value("target", "none");
  if (!cnv_string_2_long(config.value("start_address", "none"), &G_LOCAL_CONFIG.start_address)) {
      log_error("ERROR: Unable to parse start_address\n");
      exit(-1);
  }

  json stop_addresses =  config["stop_addresses"];
  G_LOCAL_CONFIG.stop_address_number = stop_addresses.size();
  for (auto& elem : stop_addresses) {
      ulong stop_address;
      if (!cnv_string_2_long(elem, &stop_address)){
          log_error("ERROR: Failed to parse stop addresses\n");
          exit(-1);
      }
      G_LOCAL_CONFIG.stop_addresses.push_back(stop_address);
  }

  if (!cnv_to_bool(config.value("track_exec_operations", "none"), pTrackExec)) {
      log_error("ERROR: Failed to parse track_exec_operations\n");
      exit(-1);
  }

  G_LOCAL_CONFIG.emu_heap_begin = 0;
  G_LOCAL_CONFIG.emu_heap_end = 0;
  json emu_heap = config.value("emu_heap", j_null);
  if (emu_heap != j_null) {
      if (!cnv_string_2_long(emu_heap.value("address", "none"), &G_LOCAL_CONFIG.emu_heap_begin)) {
             log_error("ERROR: Unable to parse emu_heap address\n");
             exit(-1);
      }
      ulong size = 0;
      if (!cnv_string_2_long(emu_heap.value("size", "none"), &size)) {
             log_error("ERROR: Unable to parse emu_heap size\n");
             exit(-1);
      }
      G_LOCAL_CONFIG.emu_heap_end = G_LOCAL_CONFIG.emu_heap_begin + size;
  }
}


// Load the set of permissions (string version and actual values) in the global permission lookup map
void loader_init_map() {
  G_PERM_ID_MAP.insert(pair<string, uint8_t>("NO_PERM", PERM_NO_PERM));
  G_PERM_ID_MAP.insert(pair<string, uint8_t>("READ", PERM_READ));
  G_PERM_ID_MAP.insert(pair<string, uint8_t>("WRITE", PERM_WRITE));
  G_PERM_ID_MAP.insert(pair<string, uint8_t>("EXEC", PERM_EXEC));
  G_PERM_ID_MAP.insert(pair<string, uint8_t>("RAW", PERM_RAW));
  G_PERM_ID_MAP.insert(pair<string, uint8_t>("HEADER", PERM_H_CHUNK));
  G_PERM_ID_MAP.insert(pair<string, uint8_t>("FREE", PERM_H_FREE));
  G_PERM_ID_MAP.insert(pair<string, uint8_t>("DELIMITER", PERM_H_DELIM));
  G_PERM_ID_MAP.insert(pair<string, uint8_t>("DIRTY", PERM_DIRTY));
}


// Initiate the first (main) memory block in the emulator
void loader_main_memory_section() {
  sectionInfo mainSection;
  mainSection.size = G_LOCAL_CONFIG.sections[0].size;
  mainSection.virtual_address = G_LOCAL_CONFIG.sections[0].virtual_address;
  mainSection.permissions = (uint8_t*)malloc(sizeof(char) * mainSection.size);

  // Convert the permission ID (string) to its corresponding byte value and init the permissions buffer with it
  uint8_t perms_value = cnv_get_permissions_by_id(G_LOCAL_CONFIG.sections[0].perm_id);
  for (uint32_t i = 0; i < mainSection.size; i++) {
    mainSection.permissions[i] = perms_value;
  }

  // Store the main permissions object
  G_MEMORY_INFO.sections.push_back(mainSection);

  log_debug("[Loader]  Permissions set to '%s' for section %s\n", G_LOCAL_CONFIG.sections[0].perm_id.c_str(), G_LOCAL_CONFIG.sections[0].name.c_str());
}


// Initiate and register additional memory block (sections) in the emulator.
void loader_add_new_section(uint32_t idx) {
  // Compute the section permissions, init them and store for a latter usage
  sectionInfo section;
  section.size = G_LOCAL_CONFIG.sections[idx].size;
  section.virtual_address = G_LOCAL_CONFIG.sections[idx].virtual_address;
  section.permissions = (uint8_t*)malloc(sizeof(char) * section.size);
  uint8_t perms_value = cnv_get_permissions_by_id(G_LOCAL_CONFIG.sections[idx].perm_id);

  for (uint32_t i = 0; i < section.size; i++) {
    section.permissions[i] = perms_value;
  }

  G_MEMORY_INFO.sections.push_back(section);
  log_debug("[Loader]  Permissions set to '%s' for section %s\n", G_LOCAL_CONFIG.sections[idx].perm_id.c_str(), G_LOCAL_CONFIG.sections[idx].name.c_str());
}



