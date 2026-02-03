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

#ifndef UPF_RULES_UPF_ACL_H_
#define UPF_RULES_UPF_ACL_H_

#include "upf/core/upf_types.h"
#include "upf/utils/heap_handle.h"
#include "upf/rules/upf_ipfilter.h"

typedef struct
{
  u16 do_match_ip_proto : 1;
  u16 ue_ip_is_assigned : 1; // then ue fields are invalid
  u16 ue_ip_mask : 6;        // up to /32
  u16 rmt_ip_mask : 6;       // up to /32

  u8 ip_proto;

  u16 port_min[UPF_N_EL];
  u16 port_max[UPF_N_EL];
  ip4_address_t ip[UPF_N_EL];
} rules_acl4_t;

STATIC_ASSERT_SIZEOF (rules_acl4_t, 20);

typedef struct
{
  u8 do_match_ip_proto : 1;
  u8 ue_ip_is_assigned : 1;  // then src fields are invalid
  u8 rmt_ip_is_assigned : 1; // then dst fields are invalid

  u8 ue_ip_mask;  // up to /128
  u8 rmt_ip_mask; // up to /128
  u8 ip_proto;

  u16 port_min[UPF_N_EL];
  u16 port_max[UPF_N_EL];

  CLIB_ALIGN_MARK (_align0, sizeof (ip6_address_t));
  ip6_address_t ip[UPF_N_EL];
} rules_acl6_t;

STATIC_ASSERT_SIZEOF (rules_acl6_t, 48);

typedef struct
{
  ipfilter_rule_t *rules;
  upf_hh_32_16_t acls4;
  upf_hh_32_16_t acls6;
  u32 refcnt;
  u8 did_created4 : 1;
  u8 did_created6 : 1;
} upf_acl_cache_entry_t;

typedef struct
{
  upf_acl_cache_entry_t *cache_entries; // pool
  uword *cache_entry_by_rules;
} upf_acl_main_t;

extern upf_acl_main_t upf_acl_main;

u32 upf_acl_cache_ref_from_rules (ipfilter_rule_t *rules);
void upf_acl_cache_unref_by_id (u32 acl_cache_id);
upf_hh_32_16_compact_t upf_acl_cache_ensure4 (u32 acl_cache_id);
upf_hh_32_16_compact_t upf_acl_cache_ensure6 (u32 acl_cache_id);

#endif // UPF_RULES_UPF_ACL_H_
