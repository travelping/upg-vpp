/*
 * Copyright (c) 2024-2025 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef UPF_UTILS_COMMON_H_
#define UPF_UTILS_COMMON_H_

#include <vppinfra/error.h>

#define BIT(n)             (1LLU << (n))
#define BIT_SET(mask, n)   ((void) ((mask) |= BIT (n)))
#define BIT_CLEAR(mask, n) ((void) ((mask) &= ~BIT (n)))
#define BIT_ISSET(mask, n) (!!((mask) &BIT (n)))

// Type-safe verification for invalid index (~0 or -1).
// Needed because ~0 sometimes doens't perform sign extension to long.
#define is_valid_id(index) ((index) != ((typeof (index)) (-1)))

// Used to indicate that this is hashmap key and care should be taken to pad it
// manually to avoid possibility of unitialized pad bytes and bitfields. Make
// sure to pad bitfields inside bytes as well, otherwise they may not be
// zero initialized.
#define __key_packed __clib_packed

// Hint method which should be called only in main thread
#define ASSERT_THREAD_MAIN() ASSERT (vlib_get_thread_index () == 0)

// Hint method which should be called only on specific thread, or during
// globalbarrier in main thread
#define ASSERT_THREAD_INDEX_OR_BARRIER(thread_index)                          \
  ((vlib_get_thread_index () == (thread_index)) ||                            \
   ((vlib_get_thread_index () == 0) && vlib_worker_thread_barrier_held ()))

#define STATIC_ASSERT_ALIGNOF(d, s)                                           \
  STATIC_ASSERT (__alignof__(d) == s, "Align of " #d " must be " #s " bytes")

#ifndef UPF_DEBUG_ENABLE
#define UPF_DEBUG_ENABLE 0
#endif

#define upf_debug(args...)                                                    \
  do                                                                          \
    {                                                                         \
      if (UPF_DEBUG_ENABLE)                                                   \
        clib_warning (args);                                                  \
    }                                                                         \
  while (0)

#endif // UPF_UTILS_COMMON_H_
