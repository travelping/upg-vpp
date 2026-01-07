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

#ifndef UPF_SXU_UPF_SXU_INLINES_H_
#define UPF_SXU_UPF_SXU_INLINES_H_

#include <vppinfra/types.h>
#include <vppinfra/vec.h>

#include "upf/sxu/upf_session_update.h"

typedef enum
{
  SXU_REF_GENERIC_OP__REF,   // used when restoring references from object
  SXU_REF_GENERIC_OP__UNREF, // remove and reset xid for safety
} sxu_generic_xid_op_t;

// searches lid by key or returns -1 if not exists
#define _(name, plural)                                                       \
  static __clib_warn_unused_result upf_xid_t sxu_get_##name##_xid_by_key (    \
    upf_sxu_t *sxu, sxu_##name##_key_t key)                                   \
  {                                                                           \
    sxu_slot_##name##_t *p;                                                   \
    vec_foreach (p, sxu->plural)                                              \
      if (memcmp (&p->key, &key, sizeof (key)) == 0)                          \
        return p - sxu->plural;                                               \
                                                                              \
    return ~0;                                                                \
  };
foreach_sxu_type
#undef _

// search object by key and try to allocates slot, if key do not exist
#define _(name, plural)                                                       \
  static __clib_warn_unused_result upf_xid_t sxu_ensure_##name##_by_key (     \
    upf_sxu_t *sxu, sxu_##name##_key_t key)                                   \
  {                                                                           \
    upf_xid_t xid = sxu_get_##name##_xid_by_key (sxu, key);                   \
    if (is_valid_id (xid))                                                    \
      return xid;                                                             \
                                                                              \
    sxu_slot_##name##_t slot = {                                              \
      .key = key,                                                             \
      .state = {},                                                            \
      .val = {},                                                              \
    };                                                                        \
                                                                              \
    uword idx = vec_len (sxu->plural);                                        \
    vec_validate (sxu->plural, idx);                                          \
    *vec_elt_at_index (sxu->plural, idx) = slot;                              \
    return idx;                                                               \
  }
foreach_sxu_type
#undef _

#define _(name, plural)                                                       \
  static upf_xid_t sxu_ref_##name##_by_xid (upf_sxu_t *sxu, upf_xid_t xid)    \
  {                                                                           \
    if (is_valid_id (xid))                                                    \
      vec_elt_at_index (sxu->plural, xid)->state.references += 1;             \
    return xid;                                                               \
  }
foreach_sxu_type
#undef _

#define _(name, plural)                                                       \
  static upf_xid_t __clib_unused __clib_warn_unused_result                    \
    sxu_ref_##name##_by_key (upf_sxu_t *sxu, sxu_##name##_key_t key)          \
  {                                                                           \
    upf_xid_t xid = sxu_ensure_##name##_by_key (sxu, key);                    \
    vec_elt_at_index (sxu->plural, xid)->state.references += 1;               \
    ASSERT (vec_elt_at_index (sxu->plural, xid)->state.references != 0);      \
    return xid;                                                               \
  }
foreach_sxu_type
#undef _

// sxu_unref_*_lid decreaces refcount of slot without zeroing lid
#define _(name, plural)                                                       \
  static void sxu_unref_unsafe_##name (upf_sxu_t *sxu, upf_xid_t xid)         \
  {                                                                           \
    if (!is_valid_id (xid))                                                   \
      return;                                                                 \
                                                                              \
    vec_elt_at_index (sxu->plural, xid)->state.references -= 1;               \
    ASSERT (vec_elt_at_index (sxu->plural, xid)->state.references !=          \
            (u16) -1);                                                        \
  }
foreach_sxu_type
#undef _

// sxu_unref_*_lid decreaces refcount of slot and zeroes lid
#define _(name, plural)                                                       \
  static void sxu_unref_##name (upf_sxu_t *sxu, upf_xid_t *xid)               \
  {                                                                           \
    sxu_unref_unsafe_##name (sxu, *xid);                                      \
    *xid = -1;                                                                \
  }
foreach_sxu_type
#undef _

// generic helper used for repeated lid reference operations
#define _(name, plural)                                                       \
  always_inline void sxu_op_xid_##name (upf_sxu_t *sxu, upf_xid_t *xid,       \
                                        sxu_generic_xid_op_t op)              \
  {                                                                           \
    if (!is_valid_id (*xid))                                                  \
      return;                                                                 \
                                                                              \
    if (op == SXU_REF_GENERIC_OP__REF)                                        \
      sxu_ref_##name##_by_xid (sxu, *xid);                                    \
    else if (op == SXU_REF_GENERIC_OP__UNREF)                                 \
      sxu_unref_##name (sxu, xid);                                            \
  }
foreach_sxu_type
#undef _

// generic helper useful for repeated bitmap reference operations
#define _(name, plural)                                                       \
  always_inline __clib_unused void sxu_op_lidset_##plural (                   \
    upf_sxu_t *sxu, upf_lidset_t *set, sxu_generic_xid_op_t op)               \
  {                                                                           \
    upf_lidset_foreach (_xid, set)                                            \
      {                                                                       \
        upf_xid_t xid = _xid;                                                 \
        ASSERT (xid < UPF_LIDSET_MAX);                                        \
        sxu_op_xid_##name (sxu, &xid, op);                                    \
      }                                                                       \
                                                                              \
    if (op == SXU_REF_GENERIC_OP__UNREF)                                      \
      upf_lidset_clear (set);                                                 \
  }
foreach_sxu_type
#undef _

#endif // UPF_SXU_UPF_SXU_INLINES_H_
