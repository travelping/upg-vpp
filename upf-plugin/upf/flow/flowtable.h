/*
 * Copyright (c) 2016 Qosmos and/or its affiliates
 * Copyright (c) 2018-2025 Travelping GmbH
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

#ifndef UPF_FLOW_FLOWTABLE_H_
#define UPF_FLOW_FLOWTABLE_H_

#include <stdbool.h>

#include <vppinfra/error.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include "upf/core/upf_types.h"
#include "upf/utils/common.h"
#include "upf/utils/llist.h"
#include "upf/utils/upf_timer.h"

// Flowtable key depends on uplink order which should be known before create or
// lookup. Standart basically tells us that all traffic is either UL or DL.
// Because of this following cases are not supported:
// - UE<->UE - complicated to do proper URR processing and to define expected
// behavior, easier to manage such behavior using routing tables after
// forwarding and own UL/DL flow in each session.
// - NET<->NET - shouldn't happen by standart and makes not much sense.

typedef union __key_packed
{
  struct __key_packed
  {
    ip4_address_t ip[UPF_N_EL];
    u16 port[UPF_N_EL];
    u32 session_id : 24;
    u32 proto : 8;
  };
  u64 key[2];
} flow_hashmap_key4_16_t;
STATIC_ASSERT_SIZEOF (flow_hashmap_key4_16_t, 16);

typedef union __key_packed
{
  struct __key_packed
  {
    ip6_address_t ip[UPF_N_EL];
    u16 port[UPF_N_EL];
    u32 session_id : 24;
    u8 proto : 8;
  };
  u64 key[5];
} flow_hashmap_key6_40_t;
STATIC_ASSERT_SIZEOF (flow_hashmap_key6_40_t, 40);

typedef struct
{
  // after forwarding
  u32 pkts;
  u32 pkts_unreported;
  u64 bytes;
  u64 bytes_unreported;
} flow_side_stats_t;

typedef enum
{
  FT_TIMEOUT_TYPE_TCP_ESTABLISHED,
  FT_TIMEOUT_TYPE_TCP_OPENING,
  FT_TIMEOUT_TYPE_TCP_CLOSING,
  FT_TIMEOUT_TYPE_UDP,
  FT_TIMEOUT_TYPE_ICMP,
  FT_TIMEOUT_TYPE_UNKNOWN,
  FT_TIMEOUT_N_TYPE
} flowtable_timeout_type_t;

typedef struct
{
  u32 next_export_at; // in seconds, zero means no intermediate reporting
  u16 context_index;
  u16 forwarding_policy_id;
  u16 up_dst_nwif_index; // up_dst means "upload destination"
  u16 up_dst_sw_if_index;
  u32 up_dst_fib_index;
} flow_ipfix_t;

UPF_LLIST_TEMPLATE_TYPES (session_flows_list);

typedef struct flow_entry
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  // elements indexes are flow_direction_t
  ip46_address_t ip[UPF_N_EL];

  u16 port[UPF_N_EL]; // in network order

  u32 session_id; // owner of UE address and this flow

  u8 proto;

  u8 is_ip4 : 1;
  // When tcp proxy is used. Once it is proxied it is always stays proxied
  // until proxy state is removed (due to disconnect).
  u8 is_tcp_proxy : 1;
  u8 is_tcp_dpi_needed : 1;
  u8 is_tcp_dpi_done : 1;

  u8 ipfix_exported : 1; // exported at least once
  // Do not perform ipfix operations for this flow anymore
  u8 ipfix_disabled : 1;
  u8 is_classified_ul : 1;
  u8 is_classified_dl : 1;

  u8 tcp_state : 3; // tcp_f_state_t
  upf_dir_t initiator : 1;
  u8 ps_generation : 4;

  u8 pdr_lids[UPF_N_DIR];

  u32 ps_index;

  /* timers */
  u32 last_packet_tick;
  u32 lifetime_ticks;
  upf_timer_id_t timer_id; /* flow expiration timer */

  // elements indexes are flow_direction_t
  flow_side_stats_t stats[UPF_N_DIR];
  flow_ipfix_t ipfix;

  /* Generation ID that must match the session's if this flow is up to date */
  u16 generation;
  u16 application_idx;
  u32 nat_flow_id; /* local to thread */

  u8 *app_uri;
  upf_time_t unix_start_time; // unix
  upf_time_t unix_last_time;  // unix

  session_flows_list_anchor_t session_anchor;

  u8 created_tcp_proxies; // count of created proxy sessions
} flow_entry_t;

// for performance
STATIC_ASSERT_ALIGNOF (flow_entry_t, CLIB_CACHE_LINE_BYTES);
STATIC_ASSERT_SIZEOF (flow_entry_t, 192);

UPF_LLIST_TEMPLATE_DEFINITIONS (session_flows_list, flow_entry_t,
                                session_anchor);

#define FLOW_TIMER_MIN_LIFETIME_SEC (3)
#define FLOW_TIMER_MAX_LIFETIME_SEC (2000)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* hashtables */
  clib_bihash_16_8_t flows_ht4;
  clib_bihash_40_8_t flows_ht6;

  flow_entry_t *flows;
  u32 current_flows_count;
} flowtable_wk_t;

#define FLOWTABLE_DEFAULT_MAX_FLOWS_PER_WORKER 4000000

typedef struct
{
  u32 max_flows_per_worker;
  u32 timer_lifetime_ticks[FT_TIMEOUT_N_TYPE];

  /* vector with index being thread index */
  flowtable_wk_t *workers;
} flowtable_main_t;

extern flowtable_main_t flowtable_main;

format_function_t format_flow_entry;
format_function_t format_flow_primary_key;
format_function_t format_flow_hashmap_key4_16;
format_function_t format_flow_hashmap_key6_40;

clib_error_t *flowtable_lifetime_update (flowtable_timeout_type_t type,
                                         u32 value);
clib_error_t *flowtable_init (vlib_main_t *vm);

__clib_unused static inline flow_entry_t *
flowtable_get_flow_by_id (u32 thread_index, u32 flow_index)
{
  flowtable_main_t *fm = &flowtable_main;
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, thread_index);
  return pool_elt_at_index (fwk->flows, flow_index);
}

flow_entry_t *flowtable_entry_new (flowtable_wk_t *fwk);
void flowtable_entry_init_by_ip4 (flowtable_wk_t *fwk, flow_entry_t *f,
                                  upf_time_t unix_now, upf_dir_t initiator,
                                  u16 generation, u32 session_id,
                                  clib_bihash_kv_16_8_t *kv4);
void flowtable_entry_init_by_ip6 (flowtable_wk_t *fwk, flow_entry_t *f,
                                  upf_time_t unix_now, upf_dir_t initiator,
                                  u16 generation, u32 session_id,
                                  clib_bihash_kv_40_8_t *kv6);
void flowtable_entry_delete (flowtable_wk_t *fwk, flow_entry_t *f, u32 now);
void flowtable_entry_reset (flow_entry_t *flow, u32 generation);

void flowtable_flow_expiration_handler (u16 thread_id, upf_timer_kind_t kind,
                                        u32 opaque, u16 opaque2);

// returns timer ID for the started flow timer
__clib_unused always_inline void
flowtable_entry_start_timer (flowtable_wk_t *fwk, flow_entry_t *f)
{
  flowtable_main_t *fm = &flowtable_main;

  ASSERT (f->timer_id.as_u32 == ~0);
  ASSERT (f->lifetime_ticks > 0);

  u16 thread_id = fwk - fm->workers;
  u32 flow_index = f - fwk->flows;

  f->timer_id =
    upf_timer_start_ticks (thread_id, f->lifetime_ticks,
                           UPF_TIMER_KIND_FLOW_EXPIRATION, flow_index, 0);
}

void upf_ipfix_flow_stats_update_handler (flow_entry_t *f, u32 now);

#endif // UPF_FLOW_FLOWTABLE_H_
