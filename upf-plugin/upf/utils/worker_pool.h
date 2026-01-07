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

#ifndef UPF_UTILS_WORKER_POOL_H_
#define UPF_UTILS_WORKER_POOL_H_

/**
 * Cache-line-aware thread-safe pool for main-thread allocation, worker-thread
 * access.
 * Works for scenarios where main thread manages allocation, workers modify
 * data. Design:
 * - Main thread allocates/frees elements
 * - Workers should be allowed only modify elements in blocks they own
 * - Elements grouped by cache-line-sized blocks to prevent false sharing
 * - Single unified pool (no per-thread pools needed)
 * - Block ownership tracked to enable thread verification
 *
 * TODO: currently free blocks are not returned to the pool and are not reused
 * by other threads
 */

#include <stdbool.h>

#include <vppinfra/vec.h>
#include <vppinfra/bitmap.h>
#include <vlib/vlib.h>

#include "upf/utils/common.h"
#include "upf/utils/upf_mt.h"

typedef struct
{
  uword *used_bitmap;

  // Vector mapping block index => thread owner
  u16 *block_to_thread;

  // Per-thread vectors of block IDs that have at least one free element
  u32 **per_thread_available_blocks;

  u32 total_free_elements_count;
} upf_worker_pool_header_t;

always_inline upf_worker_pool_header_t *
upf_worker_pool_header (void *v)
{
  return vec_header (v);
}

static_always_inline bool
upf_worker_pool_is_free_index (void *p, u32 id)
{
  if (!p)
    return true;

  upf_worker_pool_header_t *h = upf_worker_pool_header (p);
  return !clib_bitmap_get (h->used_bitmap, id);
}

__clib_unused static_always_inline u16
upf_worker_pool_elt_thread_id (void *p, u32 id)
{
  ASSERT (p);
  upf_worker_pool_header_t *h = upf_worker_pool_header (p);
  return vec_elt (h->block_to_thread, id / CLIB_CACHE_LINE_BYTES);
}

__clib_unused static u32
upf_worker_pool_len (void *p)
{
  if (!p)
    return 0;

  upf_worker_pool_header_t *h = upf_worker_pool_header (p);
  return h->total_free_elements_count;
}

__clib_unused static bool
_upf_worker_pool_get_will_expand (void *p, u16 thread_id, u32 elt_sz)
{
  if (!p)
    return true;

  upf_worker_pool_header_t *h = upf_worker_pool_header (p);

  if (vec_len (h->per_thread_available_blocks) == 0)
    return true; // not initialized yet

  if (vec_len (h->per_thread_available_blocks[thread_id]))
    return false; // have free element in block

  // past this point new block allocation is imminent

  if (vec_resize_will_expand (h->block_to_thread, 1))
    return true;

  if (vec_resize_will_expand (h->per_thread_available_blocks[thread_id],
                              CLIB_CACHE_LINE_BYTES))
    return true;

  if (clib_bitmap_will_expand (h->used_bitmap,
                               vec_len (p) + CLIB_CACHE_LINE_BYTES))
    return true;

  return _vec_resize_will_expand (p, CLIB_CACHE_LINE_BYTES, elt_sz);
}

#define upf_worker_pool_get_will_expand(P, THREAD_ID)                         \
  _upf_worker_pool_get_will_expand (P, THREAD_ID, _vec_elt_sz (P))

__clib_unused static void *
_upf_worker_pool_get (void **pp, u16 thread_id, u32 elt_sz)
{
  ASSERT_THREAD_MAIN ();

  void *p = *pp;
  upf_worker_pool_header_t *h;

  // force pool base to be cache-line aligned
  vec_attr_t va = { .hdr_sz = sizeof (upf_worker_pool_header_t),
                    .elt_sz = elt_sz,
                    .align = CLIB_CACHE_LINE_BYTES };

  if (PREDICT_FALSE (!p))
    {
      p = _vec_alloc_internal (0, &va);
      h = upf_worker_pool_header (p);
      h->used_bitmap = NULL;
      h->block_to_thread = NULL;
      h->total_free_elements_count = 0;
      h->per_thread_available_blocks =
        vec_new (u32 *, vec_len (upf_mt_main.workers));
      *pp = p;
    }
  else
    {
      h = upf_worker_pool_header (p);
    }

  u32 block_idx;
  u32 id;

  u32 **p_thread_available_blocks =
    vec_elt_at_index (h->per_thread_available_blocks, thread_id);

  u32 thread_available_blocks_len = vec_len (*p_thread_available_blocks);

  if (thread_available_blocks_len)
    {
      block_idx = **p_thread_available_blocks;

      u32 block_start = block_idx * CLIB_CACHE_LINE_BYTES;
      u32 block_end = block_start + CLIB_CACHE_LINE_BYTES;

      u32 block_free_elements = 0;
      for (u32 check_id = block_start; check_id < block_end; check_id++)
        {
          if (clib_bitmap_get_no_check (h->used_bitmap, check_id))
            continue; // used element

          block_free_elements += 1;
          id = check_id;
        }

      ASSERT (block_free_elements);

      if (block_free_elements == 1)
        {
          // just consumed last free element, so need to remove block from list
          // of blocks with available elements
          if (thread_available_blocks_len > 1)
            **p_thread_available_blocks = vec_pop (*p_thread_available_blocks);
          else
            vec_pop (*p_thread_available_blocks); // it was last element
        }

      h->total_free_elements_count -= 1;
    }
  else
    {
      // need to allocate new block
      u32 old_len = vec_len (p);
      u32 new_len = old_len + CLIB_CACHE_LINE_BYTES;

      block_idx = old_len / CLIB_CACHE_LINE_BYTES;

      p = _vec_realloc_internal (p, new_len, &va);
      h = upf_worker_pool_header (p);
      *pp = p;

      clib_mem_poison (p + old_len * elt_sz, (new_len - old_len) * elt_sz);

      vec_add1 (h->block_to_thread, thread_id);
      vec_add1 (*p_thread_available_blocks, block_idx);
      clib_bitmap_validate (h->used_bitmap, new_len - 1);

      // first element from new block
      id = block_idx * CLIB_CACHE_LINE_BYTES;

      h->total_free_elements_count += CLIB_CACHE_LINE_BYTES - 1;
    }

  h->used_bitmap = clib_bitmap_ori_notrim (h->used_bitmap, id);

  void *r = p + id * elt_sz;

  clib_mem_unpoison (r, elt_sz);
  return r;
}

#define upf_worker_pool_get(P, THREAD_ID)                                     \
  _upf_worker_pool_get ((void **) &(P), THREAD_ID, _vec_elt_sz (P))

__clib_unused static bool
_upf_worker_pool_put_will_expand (void *p, u32 id)
{
  ASSERT_THREAD_MAIN ();

  upf_worker_pool_header_t *h = upf_worker_pool_header (p);

  u16 thread_id = vec_elt (h->block_to_thread, id / CLIB_CACHE_LINE_BYTES);

  if (vec_resize_will_expand (h->per_thread_available_blocks[thread_id], 1))
    return true;

  return false;
}

#define upf_worker_pool_put_will_expand(P, E)                                 \
  _upf_worker_pool_put_will_expand (P, (E) - (P))

__clib_unused static void
_upf_worker_pool_put (void *p, u32 id, u32 elt_sz)
{
  ASSERT_THREAD_MAIN ();
  ASSERT (p);
  ASSERT (is_valid_id (id));

  upf_worker_pool_header_t *h = upf_worker_pool_header (p);

  ASSERT (id < vec_len (p));
  ASSERT (!upf_worker_pool_is_free_index (p, id));

  u32 block_idx = id / CLIB_CACHE_LINE_BYTES;
  u16 thread_id = h->block_to_thread[block_idx];

  // check if block was fully used before freeing this element
  u32 block_start = block_idx * CLIB_CACHE_LINE_BYTES;
  u32 block_end = block_start + CLIB_CACHE_LINE_BYTES;

  bool had_free_elements = false;
  for (u32 i = block_start; i < block_end; i++)
    {
      if (!clib_bitmap_get_no_check (h->used_bitmap, i))
        {
          had_free_elements = true;
          break;
        }
    }

  h->used_bitmap = clib_bitmap_andnoti_notrim (h->used_bitmap, id);
  h->total_free_elements_count += 1;
  clib_mem_poison (p + id * elt_sz, elt_sz);

  if (!had_free_elements)
    // block was fully utilized, but now it has free elements
    vec_add1 (h->per_thread_available_blocks[thread_id], block_idx);
}

#define upf_worker_pool_put(P, E)                                             \
  _upf_worker_pool_put (P, (E) - (P), _vec_elt_sz (P))

__clib_unused static void
_upf_worker_pool_elt_at_index_check (void *p, u32 id, u32 elt_sz)
{
  if (CLIB_ASSERT_ENABLE)
    {
      ASSERT (p);
      ASSERT (is_valid_id (id));
      ASSERT (!upf_worker_pool_is_free_index (p, id));

      upf_worker_pool_header_t *h = upf_worker_pool_header (p);
      ASSERT (id < vec_len (p));

      u32 block_idx = id / CLIB_CACHE_LINE_BYTES;
      u16 thread_idx = vlib_get_thread_index ();

      // main thread (0) can access any block
      // worker threads can only access blocks they own
      if (thread_idx != 0)
        ASSERT (h->block_to_thread[block_idx] == thread_idx);
    }
}

#define upf_worker_pool_elt_at_index(P, ID)                                   \
  ({                                                                          \
    _upf_worker_pool_elt_at_index_check (P, ID, _vec_elt_sz (P));             \
    vec_elt_at_index (P, ID);                                                 \
  })

#endif // UPF_UTILS_WORKER_POOL_H_
