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
#include <sys/shm.h>
#include <unistd.h>

#include "afl.h"
#include "globals.h"

// AFL related variables and macros
#define MAX_SZ_SAMPLE 0x7fff
#define FS_OPT_SET_ERROR(x) ((x & 0x0000ffff) << 8)
#define FS_OPT_ERROR 0xf800008f
#define FS_OPT_MAPSIZE 0x40000000
#define FS_OPT_MAX_MAPSIZE ((0x00fffffe >> 1) + 1)
#define FS_OPT_SET_MAPSIZE(x) (x <= 1 || x > FS_OPT_MAX_MAPSIZE ? 0 : ((x - 1) << 1))


// Notice the end of a test-case to the AFL backend
void afl_end_testcase(int32_t status) {
  int ret_write = write(G_LOCAL_CONFIG.AFL->afl_forksrv_fd_write, &status, 4);
  if (ret_write != 4) {
      exit(-1);
  }
}


// Report AFL errors to the forkserver backend
void afl_send_forkserver_error(int32_t err_code) {
  uint32_t status;
  if (!err_code || err_code > 0xffff) {
    return;
  }

  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(err_code));

  int ret_write = write(G_LOCAL_CONFIG.AFL->afl_forksrv_fd_write, (char*)&status, 4);
  if (ret_write != 4) {
    return;
  }
}


// Notify AFL that we are starting a forkserver
void afl_start_forkserver() {
  uint8_t blank[4] = {0, 0, 0, 0};
  unsigned int status = 0;

  if (G_LOCAL_CONFIG.AFL->afl_map_size <= FS_OPT_MAX_MAPSIZE) {
    status |= (FS_OPT_SET_MAPSIZE(G_LOCAL_CONFIG.AFL->afl_map_size) | FS_OPT_MAPSIZE);
  }
  if (status) status |= (0x80000001); // FS_OPT_ENABLE
  memcpy(blank, &status, 4);

  int ret_write = write(G_LOCAL_CONFIG.AFL->afl_forksrv_fd_write, blank, 4);
  if (ret_write != 4) {
    log_error("afl_start_forkserver: Failed to communicate\n");
    exit(-1);
  }
}


// Notify AFL that we are dealing with the next test-case
uint32_t afl_next_testcase(uint8_t *buf, uint32_t max_len) {
  int32_t status, res = 0xffffff;
  int32_t ret = 0;

  // Unload the AFL queue
  ret = read(G_LOCAL_CONFIG.AFL->afl_forksrv_fd_read, &status, 4);
  if (ret == 4) {
  } else {
    log_error("afl_next_testcase: Error Read: %d\n", ret);
    return 0;
  }

  memset(buf, 0, max_len);
  status = read(0, buf, max_len);

  ret = write(G_LOCAL_CONFIG.AFL->afl_forksrv_fd_write, &res, 4);
  if (ret != 4) {
      log_error("afl_next_testcase: Failed to communicate\n");
      return 0;
  }

  return status;
}


// Reset the previous AFL trace
void afl_reset_trace() {
  G_LOCAL_CONFIG.AFL->previous_location = 0;
}


// Update the AFL "shadow" bitmap
void afl_update_int_bitmap(uint64_t cur_loc) {
  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  uint64_t afl_idx = cur_loc ^ G_LOCAL_CONFIG.AFL->previous_location;
  afl_idx &= G_LOCAL_CONFIG.AFL->afl_map_size - 1;
  G_LOCAL_CONFIG.AFL->afl_shared[afl_idx]++;
  G_LOCAL_CONFIG.AFL->previous_location = cur_loc >> 1;
}


// Update the local AFL bitmap
void afl_update_bitmap(uint64_t cur_loc) {
  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  uint64_t afl_idx = cur_loc ^ G_LOCAL_CONFIG.AFL->previous_location;
  afl_idx &= G_LOCAL_CONFIG.AFL->afl_map_size - 1;
  G_LOCAL_CONFIG.AFL->afl_area_ptr[afl_idx]++;
  G_LOCAL_CONFIG.AFL->previous_location = cur_loc >> 1;
}


// Grab the shared memory address from the SHM_ID env variable
void afl_init_shm() {
  string afl_var = "__AFL_SHM_ID";
  char *id_str = getenv(afl_var.c_str());
  if (id_str == NULL) {
    log_error("ERROR AFL: Are you running this program under AFL ?\n");
    afl_send_forkserver_error(4); // FS_ERROR_SHM_OPEN
    exit(-1); 
  }
 
  uint32_t shm_id = atoi(id_str);
  G_LOCAL_CONFIG.AFL->afl_area_ptr = (uint8_t*)shmat(shm_id, NULL, 0);
  if (G_LOCAL_CONFIG.AFL->afl_area_ptr == (void *)-1) {
    log_error("ERROR AFL: Something went wrong when accessing the AFL share memory\n");
    afl_send_forkserver_error(4); // FS_ERROR_SHM_OPEN
    exit(-1);
  } 

  G_LOCAL_CONFIG.AFL->afl_area_ptr[0] = 1;

  // Update AFL bitmap size
  G_LOCAL_CONFIG.AFL->afl_map_size = (1 << 16);
}

