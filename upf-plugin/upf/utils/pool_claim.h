/*
 * Copyright (c) 2025 Travelping GmbH
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

#ifndef UPF_UTILS_POOL_CLAIM_H_
#define UPF_UTILS_POOL_CLAIM_H_

#include <stdbool.h>

#include <vppinfra/vec.h>
#include <vppinfra/bitmap.h>
#include <vlib/vlib.h>

#include "upf/utils/common.h"

// Simple object tracking for ASSERTs. Needed when main thread allocates huge
// pool with each elements being allocated to specific worker.

typedef struct
{
  uword *used_bitmap;
} upf_pool_claim_t;

__clib_unused static_always_inline bool
upf_pool_claim_is_free_index (upf_pool_claim_t *pc, uword id)
{
  ASSERT (is_valid_id (id));
  return !clib_bitmap_get (pc->used_bitmap, id);
}

__clib_unused static_always_inline void
upf_pool_claim_set_id (upf_pool_claim_t *pc, uword id)
{
  ASSERT (upf_pool_claim_is_free_index (pc, id));
  pc->used_bitmap = clib_bitmap_ori_notrim (pc->used_bitmap, id);
}

__clib_unused static_always_inline void
upf_pool_claim_free_id (upf_pool_claim_t *pc, uword id)
{
  ASSERT (!upf_pool_claim_is_free_index (pc, id));
  pc->used_bitmap = clib_bitmap_andnoti_notrim (pc->used_bitmap, id);
}

#endif // UPF_UTILS_POOL_CLAIM_H_
