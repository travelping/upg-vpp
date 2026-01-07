/*
 * Copyright (c) 2017-2025 Travelping GmbH
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

#ifndef UPF_UPF_H_
#define UPF_UPF_H_

#include <vlib/vlib.h>
#include <vlib/log.h>

#include <vppinfra/mhash.h>
#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_24_8.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/policer/policer.h>
#include <vnet/session/session_types.h>

#include "upf/utils/common.h" // include for every file
#include "upf/utils/ratelimit_atomic.h"
#include "upf/rules/upf_rules.h"
#include "upf/pfcp/upf_nwi.h"
#include "upf/pfcp/pfcp_proto.h"
#include "upf/pfcp/upf_pfcp_server.h"
#include "upf/pfcp/upf_pfcp_assoc.h"
#include "upf/pfcp/upf_session.h"
#include "upf/adf/adf.h"
#include "upf/rules/upf_forwarding_policy.h"
#include "upf/rules/upf_acl.h"
#include "upf/upf_wk.h"

/* bihash buckets are cheap, only 8 bytes per bucket */
#define UPF_MAPPING_BUCKETS (64 * 1024)

/* 128 MB per hash max memory,
 *    ~ max. 64k per bucket
 *    ~ 1024 pages with 4 values each
 * 8 million entries total.
 *
 * A older setting with max 1M entries run out of memory with 200k entries
 * Pages are grown to contain log2 entries, the memory fragmentation caused
 * by smaller pages that are keept arround eats significant amount of memory
 * from bihash.
 */
#define UPF_MAPPING_MEMORY_SIZE (2 << 27)

typedef struct
{
  mhash_t pfcp_endpoint_index;

  upf_main_wk_t *workers; // vec

  upf_nwi_t *nwis;                 // pool
  upf_interface_t *nwi_interfaces; // pool
  uword *nwi_index_by_name;

  upf_forwarding_policy_t *forwarding_policies; // pool
  uword *forwarding_policy_by_id;

  upf_session_t *sessions;       // pool
  upf_dp_session_t *dp_sessions; // pool
  upf_rules_t *rules;            // pool

  struct
  {
    /* heap allocations are always aligned on cache line (HEAP_DATA_ALIGN)  */

    rules_pdr_t *pdrs;               /* heap of PDRs */
    rules_far_t *fars;               /* heap of FARs */
    rules_urr_t *urrs;               /* heap of URRs */
    rules_qer_t *qers;               /* heap of QERs */
    rules_tep_t *teps;               /* heap of UE Traffic Endpoints*/
    rules_ep_ip_t *ep_ips4;          /* heap of UE ip4 addresses */
    rules_ep_ip_t *ep_ips6;          /* heap of UE ip6 addresses */
    rules_f_teid_t *f_teids;         /* heap of f_teids */
    rules_ep_gtpu_t *ep_gtpus;       /* heap of GTPU endpoints */
    rules_acl4_t *acls4;             /* heap of ip4 acls */
    rules_acl6_t *acls6;             /* heap of ip6 acls */
    rules_netcap_set_t *netcap_sets; /* heap of netcap stream sets*/
  } heaps;

  upf_session_procedure_t *session_procedures;

  /* lookup session by up seid */
  uword *session_by_up_seid; /* keyed session id */

  /* lookup session by ingress VRF and UE (src) IP */
  //  clib_bihash_8_8_t *session_by_tdf_ue_ip;
  u32 *tdf_ul_table[FIB_PROTOCOL_IP_MAX];

  /* pool of associated PFCP nodes */
  upf_assoc_t *assocs;
  /* lookup PFCP nodes */
  mhash_t assoc_index_by_ip;
  uword *assoc_index_by_fqdn;

  /* pool of SMF sets */
  upf_smf_set_t *smf_sets;
  /* map fqdn to smf set index */
  uword *smf_set_by_fqdn;

  /* API message ID base */
  u16 msg_id_base;

  upf_adf_main_t adf_main;

  u32 pfcp_spec_version;
  u32 rand_base;

  pfcp_ie_node_id_t node_id;

  upf_ue_ip_pool_info_t *ueip_pools;
  uword *ue_ip_pool_index_by_identity;

  // cache fseid ip addresses, to reduce memory usage
  // pool of cached fseid ip addresses
  upf_cached_f_seid_t *cached_fseid_pool;
  // map upf_cached_f_seid_key_t to index in cached_fseid_pool
  mhash_t mhash_cached_fseid_id;
  // map upf_cp_fseid_key_t to session_id
  mhash_t mhash_cp_fseid_to_session_idx;

  // map upf_imsi_t to upf_imsi_sessions_list_t
  mhash_t mhash_imsi_to_session_list;
  // map upf_imsi_t to upf_imsi_capture_list_id_t
  mhash_t mhash_imsi_to_capture_list_id;

  vlib_log_class_t log_class;

  struct
  {
    bool enabled;
    netcap_class_id_t class_session_ip;
    netcap_plugin_methods_t methods;
    upf_imsi_capture_t *captures;           // pool
    upf_imsi_capture_list_t *capture_lists; // pool
  } netcap;

  struct
  {
    bool enabled;
    u32 host_table_id;
    u32 host_if_index;
    mhash_t added_ips; // map ip_addr46 to u32
    struct nl_sock *nl_sock;

    u8 *host_if_name;
    u8 *host_ns_name;
  } ueip_export;

  u32 post_mortem_events_show_limit;
  f64 start_of_traffic_event_timeout_s;
  ratelimit_atomic_t start_of_traffic_rate_limit;
} upf_main_t;

extern upf_main_t upf_main;

u8 *upf_name_to_labels (u8 *name);
void upf_post_mortem_dump (void);

__clib_unused static upf_dp_session_t *
upf_wk_get_dp_session (u16 thread_id, u32 session_id)
{
  upf_main_t *um = &upf_main;
  upf_main_wk_t *uwk = vec_elt_at_index (um->workers, thread_id);
  ASSERT (!upf_pool_claim_is_free_index (&uwk->dp_session_claims, session_id));

  return pool_elt_at_index (um->dp_sessions, session_id);
}

__clib_unused static upf_rules_t *
upf_wk_get_rules (u16 thread_id, u32 rules_id)
{
  upf_main_t *um = &upf_main;
  upf_main_wk_t *uwk = vec_elt_at_index (um->workers, thread_id);
  ASSERT (!upf_pool_claim_is_free_index (&uwk->rule_claims, rules_id));

  return pool_elt_at_index (um->rules, rules_id);
}

#define _(name, plural)                                                       \
  __clib_unused static rules_##name##_t *upf_rules_get_##name (               \
    upf_rules_t *rules, upf_lid_t lid)                                        \
  {                                                                           \
    upf_main_t *um = &upf_main;                                               \
    ASSERT (upf_lidset_get (&rules->slots.plural, lid));                      \
    return upf_hh_elt_at_index (um->heaps.plural, &rules->plural, lid);       \
  }
foreach_upf_rules_heap_nonlinear
#undef _

#define _(name, plural)                                                       \
  __clib_unused static rules_##name##_t *upf_rules_get_##name (               \
    upf_rules_t *rules, upf_lid_t lid)                                        \
  {                                                                           \
    upf_main_t *um = &upf_main;                                               \
    return upf_hh_elt_at_index (um->heaps.plural, &rules->plural, lid);       \
  }
  foreach_upf_rules_heap_linear
#undef _

#endif // UPF_UPF_H_
