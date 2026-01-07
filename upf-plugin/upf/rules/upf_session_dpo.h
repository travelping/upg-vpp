/*
 * Copyright (c) 2019-2025 Travelping GmbH
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

#ifndef UPF_RULES_UPF_SESSION_DPO_H_
#define UPF_RULES_UPF_SESSION_DPO_H_

#include <vlib/vlib.h>
#include <vnet/fib/fib.h>

#include "upf/utils/upf_localids.h"

typedef union __clib_aligned (sizeof (u64))
{
  struct
  {
    // other threads may have old cached values, but thread with session will
    // do cache flush on creation/removal event, so it will use updated values
    u64 session_id : 24;
    u64 session_generation : 16;
    u64 thread_id : 12;
    u64 _pad : 3;
    u64 is_active : 1;
    u64 is_src_ue : 1;
    u64 ue_ip_lid : 7;
  };
  u64 as_u64;
}
upf_dpo_result_dp_t;

// should fit in atomic
STATIC_ASSERT_SIZEOF (upf_dpo_result_dp_t, 8);

typedef struct
{
  u32 session_id;
  u32 dpo_locks;
} upf_dpo_result_cp_t;

typedef struct
{
  // same index as in cp results (accessed by workers)
  // atomic load and store required
  upf_dpo_result_dp_t *dp_dpos_results; // vec
  // accessed by main thread
  upf_dpo_result_cp_t *cp_dpos_results; // pool

  u32 fq_dpo4_handoff_index;
  u32 fq_dpo6_handoff_index;
} upf_dpo_main_t;

extern upf_dpo_main_t upf_dpo_main;

int upf_tdf_ul_enable_disable (fib_protocol_t fproto, u32 sw_if_index,
                               int is_en);
vnet_api_error_t upf_tdf_ul_table_add_del (u32 vrf, fib_protocol_t fproto,
                                           u32 table_id, u8 add);

index_t upf_dpo_result_create (u16 thread_id, u32 session_id,
                               u16 session_generation, upf_lid_t ep_lid,
                               bool is_src_ue);
void upf_dpo_result_activate (index_t id);
void upf_dpo_result_delete (index_t id);

dpo_type_t upf_session_dpo_get_type (void);

int upf_session_match4_dpo_add_del (u32 fib_id, ip4_address_t addr,
                                    index_t result_id, bool is_source_matching,
                                    bool is_add);
int upf_session_match6_dpo_add_del (u32 fib_id, ip6_address_t addr,
                                    index_t result_id, bool is_source_matching,
                                    bool is_add);

index_t upf_session_match4_dpo_lookup (u32 fib_id, ip4_address_t addr,
                                       bool is_source_matching);
index_t upf_session_match6_dpo_lookup (u32 fib_id, ip6_address_t addr,
                                       bool is_source_matching);

extern vlib_node_registration_t upf_ip4_session_dpo_node;
extern vlib_node_registration_t upf_ip6_session_dpo_node;

#endif // UPF_RULES_UPF_SESSION_DPO_H_
