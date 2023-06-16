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

#include "globals.h"
#include <getopt.h>
#include <sys/stat.h>

#include "cmdline.h"







bool file_exist(const char *fileName);
bool test_dir(string fname);










// Pretty print of the loaded emulator configuration
void display_config() {
  log_debug("[Config]  sla_file   : %s\n", G_LOCAL_CONFIG.sla_path.c_str());
  log_debug("[Config]  action     : replay=%d fuzz=%d\n",
     G_LOCAL_CONFIG.replay_mode,
     G_LOCAL_CONFIG.fuzz_mode
  );
  log_debug("[Config]  emu        : start=0x%lx\n", G_LOCAL_CONFIG.start_address);

  for (uint32_t x = 0; x < G_LOCAL_CONFIG.stop_address_number; ++x) {
      log_debug("[Config]  emu        : stop=0x%lx\n", G_LOCAL_CONFIG.stop_addresses[x]);
  }


  log_debug("[Config]  loglvl     : %d\n", G_LOG_LEVEL);
  log_debug("[Config]  registers  : declared=%ld\n", G_LOCAL_CONFIG.registers.size());

  for (uint32_t x = 0; x < G_LOCAL_CONFIG.section_number; ++x) {
    log_debug("[Config]  section %d  : name='%s' va=0x%lx offset=0x%lx size=0x%lx file='%s' perms='%s' \n",
	x, 
	G_LOCAL_CONFIG.sections[x].name.c_str(), 
	G_LOCAL_CONFIG.sections[x].virtual_address,
	G_LOCAL_CONFIG.sections[x].offset,
	G_LOCAL_CONFIG.sections[x].size,
	G_LOCAL_CONFIG.sections[x].src_path.c_str(),
	G_LOCAL_CONFIG.sections[x].perm_id.c_str()
    );
  }
}


// Display the help message
void usage(FILE* fp, const char* prog) {
  fprintf (fp, "usage: %s [OPTION]\n\n", prog);
  fprintf (fp, "  -h \t\t\t"
                 "Print this help and exit.\n\n");
  fprintf (fp, "  -m [replay|fuzz]\t"
                 "Specify an emulation strategy. [REQUIRED]\n"
                 "\t\t\t\tIn 'replay' mode, the emulator will only launch the program once, exiting after a single loop.\n"
                 "\t\t\t\tIn 'fuzz' mode, this program must be launched through AFL.\n\n");
  fprintf (fp, "  -c [FILENAME]\t\t"
                 "Specify the emulator json configuration file to load. [REQUIRED]\n\n");
  fprintf (fp, "  -i [FILENAME]\t\t"
                 "Specify a test-case file to insert during a replay session. [OPTIONAL]\n\n");
  fprintf (fp, "  -I \t\t\t"
                 "Display info log (/!\\ Slow down the emulation). [OPTIONAL]\n");
  fprintf (fp, "  -D \t\t\t"
                 "Display debug and info log (/!\\ Slow down the emulation). [OPTIONAL]\n\n");
  fprintf (fp, "  -t \t\t\t"
                 "Store log in ./ghidraligator.log file. [OPTIONAL]\n\n");
}


// Abort execution when an invalid value was found in the configuration file
bool check_error_config_value(string value, string elem) {

  if (strcmp(value.c_str(), "none") == 0) {
    log_error("CONFIG ERROR: An incorrect value was found for the field '%s'. Please verify the configuration file\n", elem.c_str());
    return false;
  }
  return true;
}



// Process the command-line arguments, detect errors and save the user-defined options (passed by references)
void cmd_cmdline(
        int argc, 
        char** cmdline, 
        bool* have_mode, 
        bool* have_config, 
        bool* have_test_case, 
        string* str_mode, 
        string* str_config_path, 
        string* str_test_case_path) {
        
    int opt;
    
    while((opt = getopt(argc, cmdline, ":h:m:c:i:IDt")) != -1) {
        switch(opt) {

          case 'h':
            usage(stdout, cmdline[0]);
            exit(0);

          case 'm':
            str_mode->assign(optarg, strlen(optarg));
            *have_mode = true;
            break;

          case 'c':
            str_config_path->assign(optarg, strlen(optarg));
            *have_config = true;
            break;

          case 'i':
            str_test_case_path->assign(optarg, strlen(optarg));
            *have_test_case = true;
            break;

          case 'I':
            if (G_LOG_LEVEL < LOG_LVL_INFO) {
                G_LOG_LEVEL = LOG_LVL_INFO;
            }
            break;

          case 'D':
            if (G_LOG_LEVEL < LOG_LVL_DEBUG) {
                G_LOG_LEVEL = LOG_LVL_DEBUG;
            }
            break;

          case 't':
            G_ENABLE_TRACE = true;
            break;

          case ':':
            printf("ERROR: Missing argument value\n");
            usage(stderr, cmdline[0]);
            exit(-1);

          case '?':
            printf("ERROR: Unknwon option added\n");
            usage(stderr, cmdline[0]);
            exit(-1);

          default:
            break;
        }

    }

}



// Populate the local config structure with the optional provided input test-case
void cmd_test_case(bool have_test_case, string str_mode, char** cmdline, string str_test_case_path) {
  if (have_test_case) {

    if (str_mode.compare("fuzz") == 0) {
      printf("ERROR: No need to provide a test-case when fuzzing mode is activated\n");
      usage(stderr, cmdline[0]);
      exit(-1);
    }

    if (!file_exist(str_test_case_path.c_str())) {
      printf("ERROR: The provided 'test-case' file does not exist\n");
      usage(stderr, cmdline[0]);
      exit(-1);
    }
    
    if (str_mode.compare("replay") == 0) {
        if (!is_reg_file(str_test_case_path.c_str())) {
           printf("ERROR: test-case is not a file\n");
           usage(stderr, cmdline[0]);
           exit(-1);
        }
    }
    
    // Read test case content
    FILE* tf = fopen(str_test_case_path.c_str(), "rb");
    if (tf == NULL) {
       printf("ERROR: Unable to open test-case\n");
       usage(stderr, cmdline[0]);
       exit(-1);
    }
    
    fseek(tf, 0L, SEEK_END);
    size_t length_tf = ftell(tf);
    fseek(tf, 0L, SEEK_SET);

    uint8_t* ptr = (uint8_t*)malloc(length_tf);
    fread(ptr, length_tf, 1, tf);
    fclose(tf);

    G_LOCAL_CONFIG.test_case = ptr;
    G_LOCAL_CONFIG.test_case_len = length_tf;
  }

}


// Set the optional replay tracer options
void cmd_replay() {
  if (G_ENABLE_TRACE) {
    G_LOCAL_CONFIG.trace_file = "ghidralligator.log";
    // Empty the trace file if it already exists
    G_LOCAL_CONFIG.trace_file_out.open(G_LOCAL_CONFIG.trace_file, std::ios::in | std::ios::trunc);
    G_LOCAL_CONFIG.trace_file_out.close();
    G_LOCAL_CONFIG.trace_file_out.open(G_LOCAL_CONFIG.trace_file, std::ios_base::app);
  }
}



// Check if the provided configuration file exists
void cmd_check_config_file(bool have_config, string str_config_path, char** cmdline) {
  if (have_config) {

    if (!file_exist(str_config_path.c_str())) {
      log_error("ERROR: The provided 'config' file does not exist\n");
      usage(stderr, cmdline[0]);
      exit(-1);
    }
    
    if (!is_reg_file(str_config_path.c_str())) {
       log_error("ERROR: The provided 'config' is not a file\n");
       usage(stderr, cmdline[0]);
       exit(-1);
    }

  } else {
    log_error("ERROR: The 'config' argument is mendatory\n");
    usage(stderr, cmdline[0]);
    exit(-1);
  }
}


// Process and check extracted arguments validity or coherences
void cmd_set_cnf_mode(bool have_mode, string str_mode, char** cmdline) {
  if (have_mode) {
    if (str_mode.compare("fuzz") == 0) {
      G_LOCAL_CONFIG.fuzz_mode = true;
      G_LOCAL_CONFIG.replay_mode = false;

    } else if (str_mode.compare("replay") == 0) {
      G_LOCAL_CONFIG.fuzz_mode = false;
      G_LOCAL_CONFIG.replay_mode = true;

    } else {
      log_error("ERROR: Unknown 'mode' provided. Autorized values are: [replay|fuzz]\n");
      usage(stderr, cmdline[0]);
      exit(-1);
    }

  } else {
    log_error("ERROR: 'mode' parameter expects an value: [replay|fuzz]\n");
    usage(stderr, cmdline[0]);
    exit(-1);
  }

}


// Test if a given path is a directory
bool test_dir(string fname) {
  struct stat fstat;
  if (stat(fname.c_str(), &fstat)) {
    return false;
  }

  if (!S_ISDIR(fstat.st_mode)) {
    return false;
  }

  return true;
}


// Test if a given file exists on disk
bool file_exist(const char *fileName) {
    std::ifstream infile(fileName);
    return infile.good();
}



