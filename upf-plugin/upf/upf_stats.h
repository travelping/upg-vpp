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

#ifndef UPF_UPF_STATS_H_
#define UPF_UPF_STATS_H_

#include <vlib/vlib.h>
#include <vlib/counter.h>
#include <vlib/stats/stats.h>

#include "upf/pfcp/upf_nwi.h"

/*
  Each VPP stat entry can be populated with such named entries:
  - gauge or scalar - single u64, no allocation
  - simple counter vector - vector of vectors of u64
  - combined counter vector - vector of vectors of [2]u64
  - name vector or strings vector - vector of strings

  In addition there are helper types for counters: vlib_simple_counter_main_t
  and vlib_combined_counter_main_t. They are wrappers for simple and combined
  counter stats optimized for dataplane.

  Difference with vlib_*_counter_main_t helpers is that they assume that first
  index is thread index, so sub-vectors are per-thread, and so their
  modification is safe.
*/

// Mapping from pfcp message id to message metric id
typedef enum : u8
{
  UPF_STATS_PFCP_MSG_TYPE_UNKNOWN = 0,
#define _(N, PFCP_ID, METRIC, STR) UPF_STATS_PFCP_MSG_TYPE_##METRIC,
  foreach_pfcp_msg
#undef _
    UPF_STATS_N_PFCP_MSG_TYPE,
} upf_stats_pfcp_msg_type_t;

upf_stats_pfcp_msg_type_t
upf_stats_pfcp_msg_type_from_pfcp_msg_type (pfcp_msg_type_t type);

/* clang-format off */
// TODO: update this description below, it is not entirely correct anymore
/*
  Alghoritm to select proper type:
    Is it control plane stat:
      Is this single number (like total associations count):
        - Use gauge
      Is this vector of numbers (like sessions count per thread):
        - Group together metrics which use same indexing in enum (like NAT_BLOCKS_USED, NAT_BLOCKS_TOTAL both use nat_pool_id).
        - Use simple counter where:
          [0] first index is enum of group of metrics (like NAT_BLOCKS_USED, NAT_BLOCKS_TOTAL)
          [1] second index is your dynamic index (like nat_pool_id)
          Why: Such indexing ensures that related values are close together in memory.
        - Create named symlink to second level indexes using enum index.
          This ensures collector can distinguish them by name.
    Is it dataplane stat (per thread):
      Is this single value (like total_flows)
        - Group together mterics which use same indexing in enum (like FLOWS_TOTAL, FLOWS_USED)
          Use shared vlib_*_counter_main_t with thread index and custom enum as index
        - Create named symlink to enum.
      Is this value requires indexing (like gtpu_endpoint_id):
        - Create special vlib_*_counter_main_t with custom indexes

*/
/* clang-format on */

#define foreach_upf_counter_generic                                           \
  _ (associations_count, "associations/count")                                \
  _ (timers_ticks_per_second, "timers/ticks_per_second")                      \
                                                                              \
  /* pool stats */                                                            \
  _ (pool_sessions_used, "pool/sessions/used")                                \
  _ (pool_sessions_capacity, "pool/sessions/capacity")                        \
  _ (pool_dp_sessions_used, "pool/dp_sessions/used")                          \
  _ (pool_dp_sessions_capacity, "pool/dp_sessions/capacity")                  \
  _ (pool_nwis_used, "pool/nwis/used")                                        \
  _ (pool_nwis_capacity, "pool/nwis/capacity")                                \
  _ (pool_associations_used, "pool/associations/used")                        \
  _ (pool_associations_capacity, "pool/associations/capacity")                \
  _ (pool_smf_sets_used, "pool/smf_sets/used")                                \
  _ (pool_smf_sets_capacity, "pool/smf_sets/capacity")                        \
  _ (pool_cached_f_seids_used, "pool/cached_f_seids/used")                    \
  _ (pool_cached_f_seids_capacity, "pool/cached_f_seids/capacity")            \
  _ (pool_gtpu_endpoints_used, "pool/gtpu_endpoints/used")                    \
  _ (pool_gtpu_endpoints_capacity, "pool/gtpu_endpoints/capacity")            \
  _ (pool_pfcp_requests_used, "pool/requests/used")                           \
  _ (pool_pfcp_requests_capacity, "pool/requests/capacity")                   \
  _ (pool_pfcp_responses_used, "pool/responses/used")                         \
  _ (pool_pfcp_responses_capacity, "pool/responses/capacity")                 \
  _ (pool_session_dpo_results_used, "pool/session_dpo_results/used")          \
  _ (pool_session_dpo_results_capacity, "pool/session_dpo_results/capacity")  \
  _ (pool_forwarding_policies_used, "pool/forwarding_policies/used")          \
  _ (pool_forwarding_policies_capacity, "pool/forwarding_policies/capacity")  \
  _ (pool_adf_apps_used, "pool/adf_apps/used")                                \
  _ (pool_adf_apps_capacity, "pool/adf_apps/capacity")                        \
  _ (pool_adf_versions_used, "pool/adf_versions/used")                        \
  _ (pool_adf_versions_capacity, "pool/adf_versions/capacity")                \
  _ (pool_nat_bindings_used, "pool/nat_bindings/used")                        \
  _ (pool_nat_bindings_capacity, "pool/nat_bindings/capacity")                \
  _ (pool_nat_pools_used, "pool/nat_pools/used")                              \
  _ (pool_nat_pools_capacity, "pool/nat_pools/capacity")                      \
  _ (pool_captures_used, "pool/captures/used")                                \
  _ (pool_captures_capacity, "pool/captures/capacity")                        \
  _ (pool_capture_lists_used, "pool/capture_lists/used")                      \
  _ (pool_capture_lists_capacity, "pool/capture_lists/capacity")              \
  _ (pool_acl_cached_entries_used, "pool/acl_cached_entries/used")            \
  _ (pool_acl_cached_entries_capacity, "pool/acl_cached_entries/capacity")    \
                                                                              \
  /* rules heap stats */                                                      \
  _ (heap_pdrs_capacity, "heap/pdrs/capacity")                                \
  _ (heap_fars_capacity, "heap/fars/capacity")                                \
  _ (heap_urrs_capacity, "heap/urrs/capacity")                                \
  _ (heap_qers_capacity, "heap/qers/capacity")                                \
  _ (heap_teps_capacity, "heap/teps/capacity")                                \
  _ (heap_ep_ips4_capacity, "heap/ep_ips4/capacity")                          \
  _ (heap_ep_ips6_capacity, "heap/ep_ips6/capacity")                          \
  _ (heap_f_teids_capacity, "heap/f_teids/capacity")                          \
  _ (heap_ep_gtpus_capacity, "heap/ep_gtpus/capacity")                        \
  _ (heap_acls4_capacity, "heap/acls4/capacity")                              \
  _ (heap_acls6_capacity, "heap/acls6/capacity")                              \
  _ (heap_netcap_sets_capacity, "heap/netcap_sets/capacity")

#define foreach_upf_counter_per_nat_pool                                      \
  _ (blocks_used)                                                             \
  _ (blocks_total)                                                            \
  _ (blocks_timeout)                                                          \
  _ (ports_per_block)

#define foreach_upf_counter_per_gtpu_endpoint _ (sessions)

#define foreach_upf_counter_per_nwi _ (sessions)

// per worker stats updated by main thread
#define foreach_upf_counter_per_thread                                        \
  _ (sessions)                                                                \
  _ (mt_events_sent_m2w)                                                      \
  _ (mt_events_recv_w2m)

#define foreach_upf_counter_per_pfcp_message                                  \
  _ (rx_ok)                                                                   \
  _ (rx_error) /* no session or similar logic error */                        \
  _ (rx_fail)  /* parse failure, corruption or similar failure */             \
  _ (rx_retransmit)                                                           \
  _ (tx_ok)                                                                   \
  _ (tx_retransmit)                                                           \
  _ (tx_fail) /* network or queue failure */                                  \
  _ (tx_drop_ratelimit)                                                       \
  /* request timeout does not belog here, since it counted in requests, not   \
   * packets. But it is more convenient to present it this way. */            \
  _ (tx_req_timeout)

#define foreach_upf_wk_counter_generic                                        \
  _ (flows_count, "flows/count")                                              \
  _ (flows_tcp_proxied_count, "flows/tcp_proxied_count")                      \
  _ (flows_tcp_stitched_count, "flows/tcp/stitched_count")                    \
  _ (flows_tcp_not_stitched_mss_mismatch,                                     \
     "flows/tcp/not_stitched_mss_mismatch")                                   \
  _ (flows_tcp_not_stitched_tcp_ops_timestamp,                                \
     "flows/tcp/not_stitched_tcp_ops_timestamp")                              \
  _ (flows_tcp_not_stitched_tcp_ops_sack_permit,                              \
     "flows/tcp/not_stitched_tcp_ops_sack_permit")                            \
                                                                              \
  /* should be sequentially for buckets math */                               \
  /* also take care of ordering from least changed to most changed */         \
  /* ip_version => direction => size */                                       \
  /* - ip4 ul buckets - */                                                    \
  _ (packet_size_ip4_ul_64b, "packets/size/ip4/ul/64b")                       \
  _ (packet_size_ip4_ul_128b, "packets/size/ip4/ul/128b")                     \
  _ (packet_size_ip4_ul_256b, "packets/size/ip4/ul/256b")                     \
  _ (packet_size_ip4_ul_512b, "packets/size/ip4/ul/512b")                     \
  _ (packet_size_ip4_ul_1024b, "packets/size/ip4/ul/1024b")                   \
  _ (packet_size_ip4_ul_infinity, "packets/size/ip4/ul/infinity")             \
  _ (packet_size_ip4_ul_sum_bytes, "packets/size/ip4/ul/sum_bytes")           \
  _ (packet_proto_ip4_ul_tcp, "packets/proto/ip4/ul/tcp")                     \
  _ (packet_proto_ip4_ul_udp, "packets/proto/ip4/ul/udp")                     \
  _ (packet_proto_ip4_ul_icmp, "packets/proto/ip4/ul/icmp")                   \
  _ (packet_proto_ip4_ul_unknown, "packets/proto/ip4/ul/unknown")             \
  /* - ip4 dl buckets - */                                                    \
  _ (packet_size_ip4_dl_64b, "packets/size/ip4/dl/64b")                       \
  _ (packet_size_ip4_dl_128b, "packets/size/ip4/dl/128b")                     \
  _ (packet_size_ip4_dl_256b, "packets/size/ip4/dl/256b")                     \
  _ (packet_size_ip4_dl_512b, "packets/size/ip4/dl/512b")                     \
  _ (packet_size_ip4_dl_1024b, "packets/size/ip4/dl/1024b")                   \
  _ (packet_size_ip4_dl_infinity, "packets/size/ip4/dl/infinity")             \
  _ (packet_size_ip4_dl_sum_bytes, "packets/size/ip4/dl/sum_bytes")           \
  _ (packet_proto_ip4_dl_tcp, "packets/proto/ip4/dl/tcp")                     \
  _ (packet_proto_ip4_dl_udp, "packets/proto/ip4/dl/udp")                     \
  _ (packet_proto_ip4_dl_icmp, "packets/proto/ip4/dl/icmp")                   \
  _ (packet_proto_ip4_dl_unknown, "packets/proto/ip4/dl/unknown")             \
  /* - ip6 ul buckets - */                                                    \
  _ (packet_size_ip6_ul_64b, "packets/size/ip6/ul/64b")                       \
  _ (packet_size_ip6_ul_128b, "packets/size/ip6/ul/128b")                     \
  _ (packet_size_ip6_ul_256b, "packets/size/ip6/ul/256b")                     \
  _ (packet_size_ip6_ul_512b, "packets/size/ip6/ul/512b")                     \
  _ (packet_size_ip6_ul_1024b, "packets/size/ip6/ul/1024b")                   \
  _ (packet_size_ip6_ul_infinity, "packets/size/ip6/ul/infinity")             \
  _ (packet_size_ip6_ul_sum_bytes, "packets/size/ip6/ul/sum_bytes")           \
  _ (packet_proto_ip6_ul_tcp, "packets/proto/ip6/ul/tcp")                     \
  _ (packet_proto_ip6_ul_udp, "packets/proto/ip6/ul/udp")                     \
  _ (packet_proto_ip6_ul_icmp, "packets/proto/ip6/ul/icmp")                   \
  _ (packet_proto_ip6_ul_unknown, "packets/proto/ip6/ul/unknown")             \
  /* - ip6 dl buckets - */                                                    \
  _ (packet_size_ip6_dl_64b, "packets/size/ip6/dl/64b")                       \
  _ (packet_size_ip6_dl_128b, "packets/size/ip6/dl/128b")                     \
  _ (packet_size_ip6_dl_256b, "packets/size/ip6/dl/256b")                     \
  _ (packet_size_ip6_dl_512b, "packets/size/ip6/dl/512b")                     \
  _ (packet_size_ip6_dl_1024b, "packets/size/ip6/dl/1024b")                   \
  _ (packet_size_ip6_dl_infinity, "packets/size/ip6/dl/infinity")             \
  _ (packet_size_ip6_dl_sum_bytes, "packets/size/ip6/dl/sum_bytes")           \
  _ (packet_proto_ip6_dl_tcp, "packets/proto/ip6/dl/tcp")                     \
  _ (packet_proto_ip6_dl_udp, "packets/proto/ip6/dl/udp")                     \
  _ (packet_proto_ip6_dl_icmp, "packets/proto/ip6/dl/icmp")                   \
  _ (packet_proto_ip6_dl_unknown, "packets/proto/ip6/dl/unknown")             \
  /* - end of buckets - */                                                    \
                                                                              \
  _ (timers_scheduled, "timers/scheduled")                                    \
  _ (timers_started_total, "timers/started")                                  \
  _ (timers_stopped_total, "timers/stopped")                                  \
  _ (timers_expirations_total, "timers/expirations")                          \
  _ (timers_lag_sum_ticks, "timers/lag/sum_ticks")                            \
                                                                              \
  /* - timer buckets - */                                                     \
  _ (timers_lag_5ms, "timers/lag/5ms")                                        \
  _ (timers_lag_25ms, "timers/lag/25ms")                                      \
  _ (timers_lag_100ms, "timers/lag/100ms")                                    \
  _ (timers_lag_250ms, "timers/lag/250ms")                                    \
  _ (timers_lag_1000ms, "timers/lag/1000ms")                                  \
  _ (timers_lag_infinity, "timers/lag/infinity")                              \
  /* - end of buckets - */                                                    \
                                                                              \
  _ (mt_events_sent_w2m, "mt/events_sent_w2m")                                \
  _ (mt_events_recv_m2w, "mt/events_recv_m2w")                                \
  _ (ipfix_records_sent, "ipfix/records_sent")                                \
  _ (ipfix_messages_sent, "ipfix/messages_sent")                              \
  _ (session_reports_generated, "session/reports_generated")                  \
  _ (unsolicited_ip_reports, "session/unsolicited_ip_reports")                \
  _ (unsolicited_packets_dropped, "session/unsolicited_packets_dropped")      \
                                                                              \
  /* pool stats */                                                            \
  _ (pool_timers_used, "pool/timers/used")                                    \
  _ (pool_timers_capacity, "pool/timers/capacity")                            \
  _ (pool_flows_used, "pool/flows/used")                                      \
  _ (pool_flows_capacity, "pool/flows/capacity")                              \
  _ (pool_proxy_sessions_used, "pool/proxy_sessions/used")                    \
  _ (pool_proxy_sessions_capacity, "pool/proxy_sessions/capacity")            \
  _ (pool_nat_flows_used, "pool/nat_flows/used")                              \
  _ (pool_nat_flows_capacity, "pool/nat_flows/capacity")                      \
  _ (pool_nat_icmp_flows_used, "pool/nat_icmp_flows/used")                    \
  _ (pool_nat_icmp_flows_capacity, "pool/nat_icmp_flows/capacity")

typedef enum
{
#define _(N, PATH) UPF_STAT_GENERIC_##N,
  foreach_upf_counter_generic
#undef _
    UPF_STAT_N_GENERIC,
} upf_stat_generic_counter_t;
typedef enum
{
#define _(N) UPF_STAT_NAT_POOL_##N,
  foreach_upf_counter_per_nat_pool
#undef _
    UPF_STAT_N_NAT_POOL,
} upf_stat_nat_pool_counter_t;
typedef enum
{
#define _(N) UPF_STAT_GTPU_ENDPOINT_##N,
  foreach_upf_counter_per_gtpu_endpoint
#undef _
    UPF_STAT_N_GTPU_ENDPOINT,
} upf_stat_gtpu_endpoint_counter_t;
typedef enum
{
#define _(N) UPF_STAT_NWI_##N,
  foreach_upf_counter_per_nwi
#undef _
    UPF_STAT_N_NWI,
} upf_stat_nwi_counter_t;
typedef enum
{
#define _(N) UPF_STAT_THREAD_##N,
  foreach_upf_counter_per_thread
#undef _
    UPF_STAT_N_THREAD,
} upf_stat_thread_counter_t;
typedef enum
{
#define _(N) UPF_STAT_PFCP_MESSAGE_##N,
  foreach_upf_counter_per_pfcp_message
#undef _
    UPF_STAT_N_PFCP_MESSAGE,
} upf_stat_pfcp_message_counter_t;
typedef enum
{
#define _(N, PATH) UPF_STAT_WK_GENERIC_COUNTER_##N,
  foreach_upf_wk_counter_generic
#undef _
    UPF_STAT_N_WK_GENERIC_COUNTER,
} upf_stat_wk_generic_counter_t;

// Stats related to worker thread
typedef struct
{
  // [thread_id, upf_stat_wk_generic_counter_t]
  vlib_simple_counter_main_t generic;

  // [thread_id, nat_pool_id]
  vlib_combined_counter_main_t nat_pool_in2out;
  vlib_combined_counter_main_t nat_pool_out2in;
  vlib_simple_counter_main_t nat_pool_flows;
  vlib_simple_counter_main_t nat_pool_icmp_flows;

  // [thread_id, gtpu_endpoint_id]
  vlib_combined_counter_main_t gtpu_endpoint_rx;
  vlib_combined_counter_main_t gtpu_endpoint_tx;
} upf_stats_wk_t;

typedef struct
{
  // often accessed fields first
  struct
  {
    // [upf_stat_generic_counter_t]
    counter_t *generic;
    // [nat_pool_id, upf_stat_nat_pool_counter_t]
    counter_t **nat_pool;
    // [gtpu_endpoint_id, upf_stat_gtpu_endpoint_counter_t]
    counter_t **gtpu_endpoint;
    // [nwi_id, upf_stat_nwi_counter_t]
    counter_t **nwi;
    // [thread_id, upf_stat_thread_counter_t]
    counter_t **thread;
    // [upf_stats_pfcp_msg_type_t, upf_stat_pfcp_message_counter_t]
    counter_t **pfcp_message;
  } counters;

  upf_stats_wk_t wk;

  // rarely accessed fields below
  struct
  {
    // [0, upf_stat_generic_counter_t]
    u32 generic_counters;

    // [nat_pool_id]
    vlib_stats_string_vector_t nat_pool_names;
    vlib_stats_string_vector_t nat_pool_nwi_names;
    // [nat_pool_id, upf_stat_nat_pool_counter_t]
    u32 nat_pool_counters;

    // [gtpu_endpoint_id]
    vlib_stats_string_vector_t gtpu_endpoint_nwi_names;
    vlib_stats_string_vector_t gtpu_endpoint_ip4;
    vlib_stats_string_vector_t gtpu_endpoint_ip6;
    // [gtpu_endpoint_id, upf_stat_gtpu_endpoint_counter_t]
    u32 gtpu_counters;

    // [nwi_id]
    vlib_stats_string_vector_t nwi_names;
    // [nwi_id, upf_stat_nwi_counter_t]
    u32 nwi_counters;

    // [thread_id, upf_stat_thread_counter_t]
    u32 thread_counters;

    // [upf_stats_pfcp_msg_type_t]
    vlib_stats_string_vector_t pfcp_message_names;
    // [upf_stats_pfcp_msg_type_t, upf_stat_pfcp_message_counter_t]
    u32 pfcp_message_counters;
  } entries;
} upf_stats_main_t;

extern upf_stats_main_t upf_stats_main;

void upf_stats_init ();
void upf_periodic_stats_init ();

// If index is invalid, then entire counter vector is cleared.
void upf_stats_clear_counter_vector (u32 entry_index, u32 index0);

void upf_stats_ensure_thread (u32 n_threads);
void upf_stats_ensure_nat_pool (u32 nat_pool_id, u8 *name,
                                upf_nwi_name_t nwi_name);
void upf_stats_ensure_nwi (u32 nwi_id, upf_nwi_name_t name);
void upf_stats_ensure_gtpu_endpoint (u32 gtpu_endpoint_id,
                                     upf_nwi_name_t nwi_name,
                                     ip4_address_t *ip4, ip6_address_t *ip6);
void upf_stats_ensure_pfcp_message ();

int
upf_vlib_validate_simple_counter_will_expand (vlib_simple_counter_main_t *cm,
                                              u32 index);

typedef union
{
  struct
  {
#define _(N, PATH) counter_t N;
    foreach_upf_counter_generic
#undef _
  };
  counter_t _counters[UPF_STAT_N_GENERIC];
} upf_stats_generic_t;

static_always_inline upf_stats_generic_t *
upf_stats_get_generic ()
{
  return (upf_stats_generic_t *) upf_stats_main.counters.generic;
}

typedef union
{
  struct
  {
#define _(N) counter_t N;
    foreach_upf_counter_per_nat_pool
#undef _
  };
  counter_t _counters[UPF_STAT_N_NAT_POOL];
} upf_stats_nat_pool_t;

static_always_inline upf_stats_nat_pool_t *
upf_stats_get_nat_pool (u32 nat_pool_id)
{
  return (upf_stats_nat_pool_t *) vec_elt (upf_stats_main.counters.nat_pool,
                                           nat_pool_id);
}

typedef union
{
  struct
  {
#define _(N) counter_t N;
    foreach_upf_counter_per_gtpu_endpoint
#undef _
  };
  counter_t _counters[UPF_STAT_N_GTPU_ENDPOINT];
} upf_stats_gtpu_endpoint_t;

static_always_inline upf_stats_gtpu_endpoint_t *
upf_stats_get_gtpu_endpoint (u32 gtpu_endpoint_id)
{
  return (upf_stats_gtpu_endpoint_t *) vec_elt (
    upf_stats_main.counters.gtpu_endpoint, gtpu_endpoint_id);
}

typedef union
{
  struct
  {
#define _(N) counter_t N;
    foreach_upf_counter_per_nwi
#undef _
  };
  counter_t _counters[UPF_STAT_N_NWI];
} upf_stats_nwi_t;

static_always_inline upf_stats_nwi_t *
upf_stats_get_nwi (u32 nwi_id)
{
  return (upf_stats_nwi_t *) vec_elt (upf_stats_main.counters.nwi, nwi_id);
}

typedef union
{
  struct
  {
#define _(N) counter_t N;
    foreach_upf_counter_per_thread
#undef _
  };
  counter_t _counters[UPF_STAT_N_THREAD];
} upf_stats_thread_t;

static_always_inline upf_stats_thread_t *
upf_stats_get_thread (u32 thread_id)
{
  return (upf_stats_thread_t *) vec_elt (upf_stats_main.counters.thread,
                                         thread_id);
}

typedef union
{
  struct
  {
#define _(N) counter_t N;
    foreach_upf_counter_per_pfcp_message
#undef _
  };
  counter_t _counters[UPF_STAT_N_PFCP_MESSAGE];
} upf_stats_pfcp_message_t;

static_always_inline upf_stats_pfcp_message_t *
upf_stats_get_pfcp_message (pfcp_msg_type_t pfcp_msg_type)
{
  upf_stats_pfcp_msg_type_t stats_id =
    upf_stats_pfcp_msg_type_from_pfcp_msg_type (pfcp_msg_type);
  return (upf_stats_pfcp_message_t *) vec_elt (
    upf_stats_main.counters.pfcp_message, stats_id);
}

typedef union
{
  struct
  {
#define _(N, PATH) counter_t N;
    foreach_upf_wk_counter_generic
#undef _
  };
  counter_t _counters[UPF_STAT_N_WK_GENERIC_COUNTER];
} upf_stats_wk_generic_t;

static_always_inline upf_stats_wk_generic_t *
upf_stats_get_wk_generic (u32 thread_id)
{
  return (upf_stats_wk_generic_t *) vec_elt (
    upf_stats_main.wk.generic.counters, thread_id);
}

#endif // UPF_UPF_STATS_H_
