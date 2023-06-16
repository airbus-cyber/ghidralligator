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

#ifndef PARSER_H
#define PARSER_H

#include "../libs/json.hpp"

using json = nlohmann::json;

bool cnv_loader_extract_section(uint32_t idx);
bool cnv_to_bool(std::string str, bool* pValue);
void parse_registers(json regs);
void parse_whitelist(json white);
void parse_dynamic_sections(json sections);
void parse_static_config(bool* pTrackExec, json config);
void loader_init_map();
void loader_main_memory_section();
void loader_add_new_section(uint32_t idx);


#endif
