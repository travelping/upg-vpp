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

#ifndef UPF_UTILS_HEAP_HANDLE_H_
#define UPF_UTILS_HEAP_HANDLE_H_

#include <vppinfra/error.h>
#include <vppinfra/heap.h>

// Description:
// upf_heap_handle (or upf_hh_t) provides wrapper around vpp heaps. VPP heaps
// provide a way to allocate arrays of different sizes in single vector.
//
// Idea is to use vectors of structures during creation/removal/resize of
// arrays. When resizes are not needed anymore arrays can be converted from
// vector to heap array to be more cache friendly (mostly TLB cache) and packed
// more compactly.

#define heap_handle_foreach(v, heap, handle)                                  \
  __typeof__ (heap) _hhf_heap_##v = (heap);                                   \
  uword _hhf_handle_##v = (handle);                                           \
  uword _hhf_len_##v = heap_len (_hhf_heap_##v, _hhf_handle_##v);             \
  __typeof__ (heap) v =                                                       \
    heap_elt_with_handle (_hhf_heap_##v, _hhf_handle_##v);                    \
  for (__typeof__ (heap) _hhf_end_##v = v + _hhf_len_##v; v != _hhf_end_##v;  \
       v++)

/* for maximum savety: bits(base) should be >= bits(len) + bits(handle) */

typedef struct
{
  u32 base;        // maximum 4294 million objects total for all handles
  u32 len : 8;     // maximum 256 objects per handles
  u32 handle : 24; // maximum 16 million handle
} upf_hh_24_8_t;   // upf_heap_handle_24_8_t

typedef struct
{
  u64 base : 48;  // maximum 281 tera objects (sure) total for all handles
  u64 len : 16;   // maximum 64 kilo objects per handle
  u32 handle;     // maximum 4294 million handles
} upf_hh_32_16_t; // upf_heap_handle_32_16_t

typedef struct
{
  u64 len : 16;
  u64 base : 48;
} upf_hh_32_16_compact_t; // only reference to data

// we need two levels of macros here
#define __upf_stringify_helper(x) #x
// expands to a string literal of the current line number
#define __upf_stringify(x) __upf_stringify_helper (x)

#define upf_hh_max_len(_handle)                                               \
  ({                                                                          \
    __typeof__ (*(_handle)) _hh = { .len = ~0 };                              \
    (_hh.len);                                                                \
  })

#define upf_hh_elt_at_index(heap, _handle, index)                             \
  ({                                                                          \
    typeof (_handle) _h = (_handle);                                          \
    uword _index_ = (index);                                                  \
    uword _base_ = (_h->base); /* so visible in debugger locals */            \
    uword _len_ = (_h->len);   /* so visible in debugger locals */            \
    ASSERT (_index_ < _len_);                                                 \
    (heap_elt_at_index (heap, _base_ + _index_));                             \
  })

#define upf_hh_alloc(heap, size, _handle)                                     \
  do                                                                          \
    {                                                                         \
      __typeof__ (_handle) _h = (_handle);                                    \
      uword _size = (size);                                                   \
                                                                              \
      ASSERT (_h->len == 0);                                                  \
      if (_size)                                                              \
        {                                                                     \
          ASSERT (_size <= upf_hh_max_len (_h));                              \
                                                                              \
          uword handle;                                                       \
          uword base = heap_alloc (heap, _size, handle);                      \
          /* Handle is index to heap's internal pool of allocation tracking   \
           * structures. It will never be larger then total count of handles  \
           * due to pool internals, so it can be srinked to 24 bits if we     \
           * guarantee total handles count limit. */                          \
                                                                              \
          /* Here we check if we are out of bits to store values. */          \
          __typeof__ (*(_handle)) _test = { .handle = handle, .base = base }; \
          if (_test.handle != handle)                                         \
            clib_error ("out of upf_hh handle bits");                         \
          if (_test.base != base)                                             \
            clib_error ("out of upf_hh base bits");                           \
                                                                              \
          _h->base = base;                                                    \
          _h->handle = handle;                                                \
          _h->len = _size;                                                    \
        }                                                                     \
      else                                                                    \
        _h->len = 0;                                                          \
    }                                                                         \
  while (0)

#define upf_hh_free(heap, _handle)                                            \
  do                                                                          \
    {                                                                         \
      __typeof__ (_handle) _h = (_handle);                                    \
      if (_h->len)                                                            \
        {                                                                     \
          heap_dealloc (heap, _h->handle);                                    \
          _h->len = 0;                                                        \
        }                                                                     \
    }                                                                         \
  while (0)

#define upf_hh_resize(heap, size, _handle)                                    \
  do                                                                          \
    {                                                                         \
      typeof (_handle) *_h = (_handle);                                       \
      uword size_new = (size);                                                \
      uword base_new, handle_new;                                             \
                                                                              \
      if (size_new)                                                           \
        {                                                                     \
          base_new = heap_alloc (heap, size_new, handle_new);                 \
                                                                              \
          if (_h->len)                                                        \
            {                                                                 \
              uword size_old = _h->len;                                       \
              memcpy (heap_elt_at_index (heap, base_new),                     \
                      heap_elt_at_index (heap, _h->base),                     \
                      clib_min (size_new, size_old) * sizeof ((heap)[0]));    \
            }                                                                 \
        }                                                                     \
      else                                                                    \
        base_new = handle_new = ~0;                                           \
                                                                              \
      if (_h->len)                                                            \
        heap_dealloc (heap, _h->handle);                                      \
                                                                              \
      _h->len = size_new;                                                     \
      _h->handle = handle_new;                                                \
      _h->base = base_new;                                                    \
    }                                                                         \
  while (0)

#define upf_hh_dup(heap, _handle)                                             \
  ({                                                                          \
    typeof (_handle) _r, *_hh = (_handle);                                    \
    if (_hh->len)                                                             \
      {                                                                       \
        upf_hh_alloc ((heap), _hh->len, &_r);                                 \
        void *src = heap_elt_at_index ((heap), _hh->base);                    \
        void *dst = heap_elt_at_index ((heap), _r.base);                      \
        memcpy (dst, src, _hh->len * sizeof ((heap)[0]));                     \
      }                                                                       \
    else                                                                      \
      _r.len = 0;                                                             \
    (_r);                                                                     \
  })

#define upf_hh_foreach(v, heap, _handle)                                      \
  if ((_handle)->len)                                                         \
    for (__typeof__ (heap) v = upf_hh_elt_at_index ((heap), (_handle), 0),    \
                           _hhf_end = v + (_handle)->len;                     \
         v != _hhf_end; v++)

#define upf_hh_qsort(heap, _handle, f)                                        \
  do                                                                          \
    {                                                                         \
      if ((_handle)->len > 1)                                                 \
        {                                                                     \
          void *_base = upf_hh_elt_at_index ((heap), (_handle), 0);           \
          qsort (_base, (_handle)->len, sizeof ((heap)[0]), (void *) (f));    \
        }                                                                     \
    }                                                                         \
  while (0)

#define upf_hh_create_from_vec(heap, vector, _handle)                         \
  do                                                                          \
    {                                                                         \
      __typeof__ (_handle) _h2 = (_handle);                                   \
      __typeof__ (heap) _vec = (vector);                                      \
      uword _len = vec_len (_vec);                                            \
      upf_hh_alloc ((heap), _len, _h2);                                       \
      if (_len)                                                               \
        memcpy (heap_elt_at_index ((heap), _h2->base),                        \
                vec_elt_at_index (_vec, 0), _len * sizeof (_vec[0]));         \
    }                                                                         \
  while (0)

#define upf_vec_create_from_hh(heap, _handle)                                 \
  ({                                                                          \
    __typeof__ (heap) _vec = NULL;                                            \
    if ((_handle)->len)                                                       \
      {                                                                       \
        vec_set_len (_vec, (_handle)->len);                                   \
        memcpy (vec_elt_at_index (_vec, 0),                                   \
                heap_elt_at_index ((heap), (_handle)->base),                  \
                (_handle)->len * sizeof (_vec[0]));                           \
      }                                                                       \
    (_vec);                                                                   \
  })

#endif // UPF_UTILS_HEAP_HANDLE_H_
