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

#include <vppinfra/hash.h>

#include "upf/rules/upf_acl.h"
#include "upf/upf.h"
#include "upf/utils/ip_mask.h"
#include "upf/utils/ip_helpers.h"

#define UPF_DEBUG_ENABLE 0

upf_acl_main_t upf_acl_main = {};

u32
upf_acl_cache_ref_from_rules (ipfilter_rule_t *rules)
{
  upf_acl_main_t *uam = &upf_acl_main;

  upf_acl_cache_entry_t *ace;
  uword *p_ace_id = hash_get (uam->cache_entry_by_rules, rules);
  if (p_ace_id)
    {
      ace = pool_elt_at_index (uam->cache_entries, *p_ace_id);
      ace->refcnt += 1;
      vec_free (rules);
      return *p_ace_id;
    }

  pool_get (uam->cache_entries, ace);
  *ace = (upf_acl_cache_entry_t){
    .refcnt = 1,
    .rules = rules,
  };

  u32 ace_id = ace - uam->cache_entries;
  hash_set (uam->cache_entry_by_rules, rules, ace_id);
  return ace_id;
}

void
upf_acl_cache_unref_by_id (u32 acl_cache_id)
{
  upf_main_t *um = &upf_main;
  upf_acl_main_t *uam = &upf_acl_main;

  upf_acl_cache_entry_t *ace =
    pool_elt_at_index (uam->cache_entries, acl_cache_id);
  ace->refcnt -= 1;
  if (ace->refcnt != 0)
    return;

  hash_unset (uam->cache_entry_by_rules, ace->rules);
  ASSERT (hash_get (uam->cache_entry_by_rules, ace->rules) == NULL);

  vec_free (ace->rules);
  upf_hh_free (um->heaps.acls4, &ace->acls4);
  upf_hh_free (um->heaps.acls6, &ace->acls6);
  pool_put (uam->cache_entries, ace);
}

// grouped ip46 version to simplify refactoring
static_always_inline void
_upf_acl_compile_rule_inline (ipfilter_rule_t *r, bool is_ip4,
                              rules_acl4_t **p_acls4, rules_acl6_t **p_acls6)
{
  rules_acl4_t a4 = {};
  rules_acl6_t a6 = {};

  bool do_match_proto = (r->proto != 0xff);

  if (is_ip4)
    {
      a4.do_match_ip_proto = do_match_proto ? 1 : 0;
      a4.ip_proto = r->proto;

      a4.ue_ip_is_assigned = r->is_ue_assigned;
      a4.port_min[UPF_EL_UE] = r->ports[UPF_EL_UE].min;
      a4.port_max[UPF_EL_UE] = r->ports[UPF_EL_UE].max;
      a4.port_min[UPF_EL_RMT] = r->ports[UPF_EL_RMT].min;
      a4.port_max[UPF_EL_RMT] = r->ports[UPF_EL_RMT].max;
    }
  else
    {
      a6.do_match_ip_proto = do_match_proto ? 1 : 0;
      a6.ip_proto = r->proto;

      a6.ue_ip_is_assigned = r->is_ue_assigned;
      a6.port_min[UPF_EL_UE] = r->ports[UPF_EL_UE].min;
      a6.port_max[UPF_EL_UE] = r->ports[UPF_EL_UE].max;
      a6.port_min[UPF_EL_RMT] = r->ports[UPF_EL_RMT].min;
      a6.port_max[UPF_EL_RMT] = r->ports[UPF_EL_RMT].max;
    }

  if (!r->is_ue_assigned)
    {
      if (is_ip4)
        {
          a4.ip[UPF_EL_UE] = r->address_ue.ip4;
          a4.ue_ip_mask = r->mask_ue;
          ip4_address_mask (&a4.ip[UPF_EL_UE],
                            &ip4_mask_by_prefix[r->mask_ue]);
        }
      else
        {
          a6.ip[UPF_EL_UE] = r->address_ue.ip6;
          a6.ue_ip_mask = r->mask_ue;
          ip6_address_mask (&a6.ip[UPF_EL_UE],
                            &ip6_mask_by_prefix[r->mask_ue]);
        }
    }

  if (is_ip4)
    {
      a4.ip[UPF_EL_RMT] = r->address_rmt.ip4;
      a4.rmt_ip_mask = r->mask_rmt;
      ip4_address_mask (&a4.ip[UPF_EL_RMT], &ip4_mask_by_prefix[r->mask_rmt]);
    }
  else
    {
      a6.ip[UPF_EL_RMT] = r->address_rmt.ip6;
      a6.rmt_ip_mask = r->mask_rmt;
      ip6_address_mask (&a6.ip[UPF_EL_RMT], &ip6_mask_by_prefix[r->mask_rmt]);
    }

  if (is_ip4)
    vec_add1 (*p_acls4, a4);
  else
    vec_add1 (*p_acls6, a6);
}

// grouped ip46 version to simplify refactoring
static_always_inline void
_upf_acl_cache_compile_inline (upf_acl_cache_entry_t *ace, bool is_ip4)
{
  upf_main_t *um = &upf_main;
  rules_acl4_t *acls4 = NULL;
  rules_acl6_t *acls6 = NULL;

  ipfilter_rule_t *r;
  vec_foreach (r, ace->rules)
    {
      ASSERT (!(r->is_ip4 && r->is_ip6));

      bool is_acl_ip_any = !r->is_ip4 && !r->is_ip6;
      bool is_acl_ip4 = is_acl_ip_any || r->is_ip4;
      bool is_acl_ip6 = is_acl_ip_any || r->is_ip6;

      upf_debug ("compiling %U", format_upf_ipfilter, r);

      if (is_ip4 && is_acl_ip4)
        _upf_acl_compile_rule_inline (r, 1 /* is_ip4 */, &acls4, NULL);
      if (!is_ip4 && is_acl_ip6)
        _upf_acl_compile_rule_inline (r, 0 /* is_ip4 */, NULL, &acls6);
    }

  bool barrier = false;
  if (is_ip4)
    {
      barrier = vec_resize_will_expand (um->heaps.acls4, vec_len (acls4));
      if (barrier)
        vlib_worker_thread_barrier_sync (vlib_get_main ());

      upf_hh_create_from_vec (um->heaps.acls4, acls4, &ace->acls4);
      vec_free (acls4);
    }
  else
    {
      barrier = vec_resize_will_expand (um->heaps.acls6, vec_len (acls6));
      if (barrier)
        vlib_worker_thread_barrier_sync (vlib_get_main ());

      upf_hh_create_from_vec (um->heaps.acls6, acls6, &ace->acls6);
      vec_free (acls6);
    }

  if (barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());
}

upf_hh_32_16_compact_t
upf_acl_cache_ensure4 (u32 acl_cache_id)
{
  upf_acl_main_t *uam = &upf_acl_main;
  upf_acl_cache_entry_t *ace =
    pool_elt_at_index (uam->cache_entries, acl_cache_id);

  if (!ace->did_created4)
    {
      ace->did_created4 = 1;
      _upf_acl_cache_compile_inline (ace, 1 /* is_ip4 */);
    }

  return (upf_hh_32_16_compact_t){
    .len = ace->acls4.len,
    .base = ace->acls4.base,
  };
}

upf_hh_32_16_compact_t
upf_acl_cache_ensure6 (u32 acl_cache_id)
{
  upf_acl_main_t *uam = &upf_acl_main;
  upf_acl_cache_entry_t *ace =
    pool_elt_at_index (uam->cache_entries, acl_cache_id);

  if (!ace->did_created6)
    {
      ace->did_created6 = 1;
      _upf_acl_cache_compile_inline (ace, 0 /* is_ip4 */);
    }

  return (upf_hh_32_16_compact_t){
    .len = ace->acls6.len,
    .base = ace->acls6.base,
  };
  ;
}
