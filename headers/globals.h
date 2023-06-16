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

#ifndef GLOBALS_H
#define GLOBALS_H

#include <csignal>
#include "emulate.hh"
#include "structs.h"
#include "utils.h"

// Set of permission for the memory map of the emulator
const uint8_t PERM_NO_PERM = 0b00000000;
const uint8_t PERM_READ    = 0b00000001;
const uint8_t PERM_WRITE   = 0b00000010;
const uint8_t PERM_EXEC    = 0b00000100;
const uint8_t PERM_RAW     = 0b00001000;
const uint8_t PERM_H_CHUNK = 0b00010000;
const uint8_t PERM_H_FREE  = 0b00100000;
const uint8_t PERM_H_DELIM = 0b01000000;
const uint8_t PERM_DIRTY   = 0b10000000;

// Main configuration structure for the emulator
inline memoryInfo G_MEMORY_INFO;
inline localConfig G_LOCAL_CONFIG;

// Pointer on next allocated buffer (ASAN stuff)
extern uint64_t G_CURRENT_ALLOC_ADDR;

// Allows multiple and various components to report an emulation error to the engine
inline volatile sig_atomic_t G_EMULATION_ABORT_FLAG;


#define LOG_LVL_NO_LOG  0
#define LOG_LVL_INFO    1
#define LOG_LVL_DEBUG   2


inline uint8_t G_LOG_LEVEL;

// Configuration booleans
inline bool G_ENABLE_TRACE;

// Permissions lookup table (strings -> permission bits / permissions bits -> strings)
inline std::map<string, uint8_t> G_PERM_ID_MAP;

#endif
