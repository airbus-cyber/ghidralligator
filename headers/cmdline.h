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

#ifndef CMDLINE_H
#define CMDLINE_H

#include "globals.h"

void usage(FILE* fp, const char* prog);
bool check_error_config_value(string value, string elem);
void display_config();
void cmd_cmdline(
        int argc,
        char** cmdline,
        bool* have_mode,
        bool* have_config,
        bool* have_test_case,
        string* str_mode,
        string* str_config_path,
        string* str_test_case_path);
void cmd_set_cnf_mode(bool, string, char**);
void cmd_check_config_file(bool, string, char**);
void cmd_test_case(bool, string, char**, string);
void cmd_replay();

#endif
