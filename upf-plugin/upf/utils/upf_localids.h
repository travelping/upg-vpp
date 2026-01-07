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

#ifndef UPF_UTILS_UPF_LOCALIDS_H_
#define UPF_UTILS_UPF_LOCALIDS_H_

#include <stdbool.h>
#include <string.h>

#include <vppinfra/clib.h>
#include <vppinfra/types.h>
#include <vppinfra/format.h>

// Description:
// UPF controls lost of objects per session. To save on space and complexity we
// use LocalID which are indexes limited to single bytes and referenced
// relative to session/rules global handler. This allows for lots of
// optimizations, one of which is optimized Local ID Set (lidset), which
// represents set of elements using bitmask, allowing to do referncing and
// iteration in much more optimized way. Also removes complexity of managememnt
// of lists of ids.
//
// As huge downside it limits total amount of PDRs/QERs/etc.. to some limit
// (UPF_LID_MAX). But realistically such limit should never be reached.

// Should be pow2 and less then 256. Because 256 would not leave space
// for invalid id.
#define UPF_LID_MAX (64)

// Local Id, means index in subarray inside global array.
// Local Id converted to Global Id using vector offset specific to context,
// like session rules.
// Local Id should be considered stable (aka do not change) for the same item
// during it's lifetime, if not stated otherwise. This is needed to avoid
// update of global state like bihash during update what would require
// additional synchronisation with workers. As one example global bihashes
// can't be synced with worker event handling, since only main thread should
// update global bihash entries.
typedef u8 upf_lid_t;

// Update Id - in short xid, to avoid confusion with uid. Similar to upf_lid_t,
// but used only during update procedure. Reason for this is that during update
// keys and slots benefit from being linearized in memory for simpler and
// efficient: key search, slot allocation and iteration. Lids are mapped to
// xids before update and back to lids after update.
typedef u8 upf_xid_t;

typedef upf_lid_t upf_pdr_lid_t;
typedef upf_lid_t upf_far_lid_t;
typedef upf_lid_t upf_urr_lid_t;
typedef upf_lid_t upf_qer_lid_t;

#define UPF_LIDSET_MAX   (UPF_LID_MAX)
#define UPF_LIDSET_WORDS (UPF_LIDSET_MAX / uword_bits)

typedef struct
{
  uword bitmaps[UPF_LIDSET_WORDS];
} upf_lidset_t;

__clib_unused always_inline void
upf_lidset_set (upf_lidset_t *set, upf_lid_t lid)
{
  ASSERT (lid >= 0);
  ASSERT (lid < UPF_LIDSET_MAX);
  set->bitmaps[lid / uword_bits] |= 1 << (lid % uword_bits);
}

__clib_unused always_inline void
upf_lidset_unset (upf_lidset_t *set, upf_lid_t lid)
{
  set->bitmaps[lid / uword_bits] &= ~(1 << (lid % uword_bits));
}

__clib_unused always_inline upf_lid_t
upf_lidset_get_first_set_idx (upf_lidset_t *set)
{
  uword w;
  for (uword i = 0; i < UPF_LIDSET_WORDS; i++)
    {
      w = set->bitmaps[i];
      if (w != 0)
        return i * uword_bits + get_lowest_set_bit_index (w);
    }

  return -1;
}

__clib_unused always_inline upf_lid_t
upf_lidset_get_first_unset_idx (upf_lidset_t *set)
{
  uword w;
  for (uword i = 0; i < UPF_LIDSET_WORDS; i++)
    {
      w = set->bitmaps[i];
      if (w != -1)
        return i * uword_bits + get_lowest_set_bit_index (~w);
    }

  return -1;
}

__clib_unused __clib_warn_unused_result always_inline bool
upf_lidset_get (upf_lidset_t *set, upf_lid_t lid)
{
  return uword_bitmap_is_bit_set (set->bitmaps, lid);
}

__clib_unused __clib_warn_unused_result always_inline uword
upf_lidset_count (upf_lidset_t *set)
{
  return uword_bitmap_count_set_bits (set->bitmaps, UPF_LIDSET_WORDS);
}

// validated using: https://godbolt.org/z/7f7efPbdE
__clib_unused always_inline void
upf_lidset_set_first_n (upf_lidset_t *set, uword count)
{
  if (UPF_LIDSET_WORDS == 2)
    {
      // opzimized version
      uword word_id = (count & uword_bits) >> log2_uword_bits;
      uword bits = count & (uword_bits - 1);

      // bitmap[1] = 0 or bitmap[0] = -1
      set->bitmaps[1 ^ word_id] = 0 - word_id;
      if (bits)
        set->bitmaps[word_id] = (((uword) 1) << ((uword) bits)) - 1;
      else
        set->bitmaps[word_id] = 0;
    }
  else
    {
      u32 i = 0;
      u32 left = count;
      for (; left >= uword_bits; left -= uword_bits)
        {
          set->bitmaps[i] = -1;
          i += 1;
        }

      if (left)
        set->bitmaps[i] = (((uword) 1) << ((uword) left)) - 1;
    }
}

__clib_unused always_inline void
upf_lidset_clear (upf_lidset_t *set)
{
  memset (set->bitmaps, 0, sizeof (set->bitmaps));
}

__clib_unused always_inline void
upf_lidset_set_all (upf_lidset_t *set)
{
  memset (set->bitmaps, 0xff, sizeof (set->bitmaps));
}

__clib_unused always_inline bool
upf_lidset_is_empty (upf_lidset_t *set)
{
  for (int i = 0; i < UPF_LIDSET_WORDS; i++)
    if (set->bitmaps[i])
      return false;
  return true;
}

__clib_unused always_inline bool
upf_lidset_is_equal (upf_lidset_t *a, upf_lidset_t *b)
{
  for (int i = 0; i < UPF_LIDSET_WORDS; i++)
    if (a->bitmaps[i] != b->bitmaps[i])
      return false;

  return true;
}

__clib_unused always_inline void
upf_lidset_or (upf_lidset_t *dst, upf_lidset_t *a1, upf_lidset_t *a2)
{
  for (int i = 0; i < UPF_LIDSET_WORDS; i++)
    dst->bitmaps[i] = a1->bitmaps[i] | a2->bitmaps[i];
}

__clib_unused always_inline void
upf_lidset_and (upf_lidset_t *dst, upf_lidset_t *a1, upf_lidset_t *a2)
{
  for (int i = 0; i < UPF_LIDSET_WORDS; i++)
    dst->bitmaps[i] = a1->bitmaps[i] & a2->bitmaps[i];
}

__clib_unused always_inline void
upf_lidset_xor (upf_lidset_t *dst, upf_lidset_t *a1, upf_lidset_t *a2)
{
  for (int i = 0; i < UPF_LIDSET_WORDS; i++)
    dst->bitmaps[i] = a1->bitmaps[i] ^ a2->bitmaps[i];
}

__clib_unused always_inline void
upf_lidset_not (upf_lidset_t *dst, upf_lidset_t *a)
{
  for (int i = 0; i < UPF_LIDSET_WORDS; i++)
    dst->bitmaps[i] = ~a->bitmaps[i];
}

format_function_t format_upf_lidset;

// clang optimizes this pretty well using bsf instruction:
// https://godbolt.org/z/91rarKxo6
// FIXME: can't use u8 upf_lid_t, because of required uword operations and
// limitation of single type definition inside "for"
#define upf_lidset_foreach(i, set)                                            \
  for (uword wrdid = 0; wrdid < UPF_LIDSET_WORDS; wrdid++)                    \
    for (uword _tmp = (set)->bitmaps[wrdid],                                  \
               i = wrdid * uword_bits + get_lowest_set_bit_index (_tmp);      \
         _tmp; _tmp = clear_lowest_set_bit (_tmp),                            \
               i = wrdid * uword_bits + get_lowest_set_bit_index (_tmp))

#endif // UPF_UTILS_UPF_LOCALIDS_H_
