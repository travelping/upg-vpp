/*
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

#ifndef UPF_RULES_UPF_RULES_H_
#define UPF_RULES_UPF_RULES_H_

#include "upf/utils/upf_localids.h"
#include "upf/utils/heap_handle.h"
#include "upf/utils/upf_timer.h"
#include "upf/utils/tokenbucket.h"
#include "upf/core/upf_types.h"
#include "upf/pfcp/upf_nwi.h"
#include "upf/pfcp/pfcp_proto.h"
#include "upf/external/netcap.h"
#include "upf/integrations/upf_netcap.h"

typedef struct
{
  u64 ul;
  u64 dl;
  u64 tot; // total (not always ul+dl)
} urr_counter_t;

// Quota consumption measurement since last usage report.
// Resets every usage report.
typedef struct
{
  urr_counter_t packets;
  urr_counter_t bytes;
} urr_measure_t;

// Periodic timer with relative time base
typedef struct
{
  upf_time_t base; // Usually last time period was updated, or other base
  u32 period;      // Relative duration in seconds, 0 - means unset
} urr_based_timer_t;

typedef enum : u16
{
  URR_UPDATE_F_VOLUME_QUOTA = 1 << 0,
  URR_UPDATE_F_VOLUME_THRESHOLD = 1 << 1,
  URR_UPDATE_F_TIME_QUOTA = 1 << 2,
  URR_UPDATE_F_TIME_THRESHOLD = 1 << 3,
  URR_UPDATE_F_MONITORING_TIME = 1 << 4,
  URR_UPDATE_F_MEASUREMENT_PERIOD = 1 << 5,
  URR_UPDATE_F_QUOTA_VALIDITY_TIME = 1 << 6,
  URR_UPDATE_F_QUOTA_HOLDING_TIME = 1 << 7,
} urr_update_flags_t;

typedef struct __key_packed
{
  ip46_address_t ue_ip;
  u16 nwi_id;
  u8 _pad[2];
} urr_start_of_traffic_ev_t;

// Monitoring time split measurement
typedef struct
{
  urr_measure_t vol_measure;
  u32 time_measure;

  upf_time_t split_time;
  upf_time_t first_packet;
  upf_time_t last_packet;
} urr_split_measurement_t;

// Usage Reporting Rules
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0); // workers do writes
  pfcp_ie_urr_id_t pfcp_id;

  // long name for reporting triggers fields to not confuse them
  pfcp_ie_reporting_triggers_t enabled_triggers;
  pfcp_ie_usage_report_trigger_t next_report_triggers;

  urr_update_flags_t update_flags; // changed fields during updated
  pfcp_ie_ur_seqn_t seq_no;

  // should we measure volume at all
  u8 measurement_method_volume : 1;
  // should we measure time at all
  u8 measurement_method_duration : 1;
  u8 measurement_method_event : 1;
  u8 has_pdr_references : 1;

  // because quota of zero is valid quota these flags are needed to check which
  // quota values we should process
  u8 has_quota_ul : 1;
  u8 has_quota_dl : 1;
  u8 has_quota_tot : 1;
  u8 has_quota_time : 1;

  //  group of status flag for easier copy during update
  struct
  {
    u8 out_of_volume_quota : 1;
    u8 out_of_time_quota : 1;

    // If threshold sent since last quota update.
    // > A UP Function complying with Release 14 or Release 15 of the
    // > specification only sends one usage report when the threshold is
    // > reached, even if both reporting triggers (for the threshold and
    // > the quota) are set.
    u8 did_sent_volume_threshold : 1;
    u8 did_sent_time_threshold : 1;

    // To prevent disable timers after they been triggered. To be able to print
    // timer values
    u8 disarmed_monitoring_time : 1;
    u8 disarmed_quota_holding_time : 1;
    u8 disarmed_quota_validity_time : 1;
  } status;

  // Min of all timers, needed to schedule shared URRs timer.
  // Default value is INFINITY, for clib_min to work.
  upf_time_t next_timer_at;

  struct
  {
    // Start of current report time. Resetted after every report.
    upf_time_t start;
    // First packet time. Zeroed after each report
    upf_time_t first_packet;
    // Last packet time. Zeroed only during URR creation.
    // Not zeroed after reports because of Quota Holding Time.
    upf_time_t last_packet;
  } timestamps;

  struct
  {
    // adjusted since last report
    urr_counter_t threshold_left;
    urr_counter_t quota_left;

    // quota used since last report
    urr_measure_t measure;

    // zero means "not set"
    urr_counter_t threshold_set;
    // zero is valid value. bit fields should be used for presence check
    urr_counter_t quota_set;
  } vol;

  struct
  {
    // Measure calculated relative to it. Can be behind, since increments
    // by integer instead of float if there is quota, to keep measurement
    // correct.
    upf_time_t time_of_last_measure_update;

    // adjusted since last report
    u32 threshold_left; // relative to last report
    u32 quota_left;     // relative to last report

    // quota used since last report in seconds
    u32 measure;

    // zero means "not set"
    u32 threshold_set;
    // zero is valid value. bit fields should be used for presence check
    u32 quota_set;
  } time;

  // > the period to generate periodic usage reports
  // relative to time when set
  urr_based_timer_t measurement_period;

  // > when no packets have been received for the duration
  // > any remaining quota for the URR is discarded in the UP function
  // relative to last packet time or when set (what was later)
  urr_based_timer_t quota_holding_time;

  // > send a usage report after the validity duration is over
  // > any remaining quota for the URR is discarded in the UP function
  // relative to time when set
  urr_based_timer_t quota_validity_time;

  // > measure the network resources usage before and after the monitoring time
  // > in separate counts and to re-apply the volume and/or time, and/or event
  // > thresholds at the monitoring time
  upf_time_t monitoring_time; // absolute time

  // URRs linked BY this URR. They should be reported when this URR is
  // reporting. Reversed direction of references from sxu. So its not "Linked
  // URR Ids", but more like "Linked BY URR Ids".
  upf_lidset_t liusa_urrs_lids;

  /* pool of urr traffic info */
  // TODO: optimize memory usage somehow, we do not need this values very often
  mhash_t *mhash_traffic_by_ue;
  urr_start_of_traffic_ev_t *events_start_of_traffic;

  u32 montioring_split_measurement_id;
} rules_urr_t;

STATIC_ASSERT_SIZEOF (rules_urr_t, 320); // control of optimizations

// QoS Enforcement Rules
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0); // workers do writes
  pfcp_ie_qer_id_t pfcp_id;
  u8 gate_closed_ul : 1;
  u8 gate_closed_dl : 1;
  u8 has_mbr : 1;
  u32 maximum_bitrate[UPF_N_DIR];
  tokenbucket_t policer_bytes[UPF_N_DIR];
} rules_qer_t;

STATIC_ASSERT_SIZEOF (rules_qer_t, 64); // control of optimizations

// Represents teid allocation
typedef struct
{
  u16 nwi_id;
  u8 choose_id;
  upf_interface_type_t intf;
  u8 gtpu_endpoint_lid;
} rules_f_teid_t;

STATIC_ASSERT_SIZEOF (rules_f_teid_t, 6); // control of optimizations

// Represents ownership of teid on gtpu endpoint
typedef struct
{
  u32 teid;
  u16 gtpu_ep_id;
  u8 is_uplink : 1;

  upf_lidset_t pdr_lids;
} rules_ep_gtpu_t;

STATIC_ASSERT_SIZEOF (rules_ep_gtpu_t, 16); // control of optimizations

// Represents ownership of ip4 address in fib
typedef struct
{
  upf_lidset_t pdr_lids;

  u32 dpo_result_id;
  u16 fib_index;
  u8 traffic_ep_lid;
  u8 is_ue_side : 1;
} rules_ep_ip_t, rules_ep_ip4_t, rules_ep_ip6_t;

STATIC_ASSERT_SIZEOF (rules_ep_ip_t, 16); // control of optimizations

// Traffic endpoint. Represents generalized ownership of PDRs "global" objects
// like gtpu/ip addresses on fibs and NWIs
typedef struct
{
  u8 is_gtpu : 1; // GTP tunnel
  u8 is_destination_ip : 1;
  u8 is_ue_ip4 : 1; // if has assigned ueip4
  u8 is_ue_ip6 : 1; // if has assigned ueip6

  upf_interface_type_t intf;
  u16 nwi_id;

  union
  {
    struct
    {
      u8 fteid_allocation_lid;
      u8 gtpu_ep_lid; // always present, even if UP allocated
    } gtpu;
    struct
    {
      u8 traffic_ep4_lid;
      u8 traffic_ep6_lid;
    } ip;
  } match;

  u8 capture_set_lid;

  ip6_address_t ue_addr6;
  ip4_address_t ue_addr4;
} rules_tep_t;

STATIC_ASSERT_SIZEOF (rules_tep_t, 28); // control of optimizations

// Single NetCap stream
typedef struct
{
  upf_imsi_capture_id_t imsi_capture_id;
  netcap_stream_id_t netcap_stream_id;
  u16 packet_max_bytes;
} rules_netcap_stream_t;

// NetCap streams set per traffic endpoint
typedef struct
{
  u16 nwi_id;
  upf_interface_type_t intf;
  rules_netcap_stream_t *streams;
} rules_netcap_set_t;

/* Packet Detection Rules */
typedef struct
{
  pfcp_ie_pdr_id_t pfcp_id;
  u16 nwi_id;

  u8 is_uplink : 1; // otherwise downlink
  u8 gtpu_outer_header_removal : 1;
  u8 has_event_urrs : 1; // do event urrs iteration
  u8 need_http_redirect : 1;

  u8 is_tdf_unsolicited : 1;
  u8 can_recv_ip4 : 1;
  u8 can_recv_ip6 : 1;

  u8 far_lid;
  u8 traffic_ep_lid;
  upf_interface_type_t src_intf;
  u16 application_id;
  u16 precedence;
  u32 acl_cached_id;

  upf_hh_32_16_compact_t acls4;
  upf_hh_32_16_compact_t acls6;

  upf_lidset_t volume_urr_lids;
  upf_lidset_t urr_lids;
  upf_lidset_t qer_lids;

  // manually pad to 64 to avoid multi cache line access on following pdrs
  u8 _pad[8];
} rules_pdr_t;

STATIC_ASSERT_SIZEOF (rules_pdr_t, 64); // control of optimizations

typedef struct
{
  u8 has_outer_header_creation : 1;
  u8 has_redirect_information : 1;
  u8 has_forwarding_policy : 1;
  u8 has_outer_addr4 : 1;
  u8 has_outer_addr6 : 1;
  u8 do_nat : 1;
  u8 do_send_end_marker : 1;

  upf_interface_type_t dst_intf;

  u16 nwi_id; // always present

  struct
  {
    ip6_address_t addr6;
    ip4_address_t addr4;
    u32 teid;
    u16 src_gtpu_endpoint_id;
  } ohc;

  u16 forwarding_policy_id;

  u8 *redirect_uri;
} rules_far_forward_t;

typedef enum : u8
{
  UPF_FAR_ACTION_DROP,
  UPF_FAR_ACTION_FORWARD,
  // TODO: buffer
  // TODO: duplicate
  // TODO: notify CP
} rules_far_action_t;

/* Forward Action Rules */
typedef struct
{
  pfcp_ie_far_id_t pfcp_id;
  rules_far_action_t apply_action;

  upf_ipfix_policy_t ipfix_policy_set : 4;
  upf_ipfix_policy_t ipfix_policy_used : 4;
  u16 ipfix_context4_id;
  u16 ipfix_context6_id;

  rules_far_forward_t forward;
} rules_far_t;

STATIC_ASSERT_SIZEOF (rules_far_t, 64); // control of optimizations

// nonlinear - means can have "holes" between lids, and needs slot.X checking
#define foreach_upf_rules_heap_nonlinear                                      \
  _ (urr, urrs)                                                               \
  _ (tep, teps)                                                               \
  _ (ep_gtpu, ep_gtpus)                                                       \
  _ (ep_ip4, ep_ips4)                                                         \
  _ (ep_ip6, ep_ips6)

// linear - means that all used lids are in range [0, elements_count)
#define foreach_upf_rules_heap_linear                                         \
  _ (pdr, pdrs)                                                               \
  _ (far, fars)                                                               \
  _ (qer, qers)                                                               \
  _ (f_teid, f_teids)                                                         \
  _ (netcap_set, netcap_sets)

#define foreach_upf_rules_heap                                                \
  foreach_upf_rules_heap_linear foreach_upf_rules_heap_nonlinear

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  // it is safe to use 24_8 here, since we can have up to (1<<24) sessions and
  // up to (1<<8) lids of each object
#define _(name, plural) upf_hh_24_8_t plural;
  foreach_upf_rules_heap
#undef _

    u8 flag_inactivity_timeout_reset : 1;
  u8 is_flowless_optimized : 1;
  u8 want_netcap : 1;

  u32 inactivity_timeout; // in seconds

  // uplink pdr lids, to get downlink xor with slots.pdrs
  upf_lidset_t pdr_ul_lids;
  upf_lidset_t pdr_ip4_lids;
  upf_lidset_t pdr_ip6_lids;

  struct
  {
#define _(name, plural) upf_lidset_t plural;
    foreach_upf_rules_heap_nonlinear
#undef _
  } slots;

  u32 nat_binding_id;
  u16 nat_pool_id;
  upf_lid_t nat_netcap_set_lid;
} upf_rules_t;

STATIC_ASSERT_SIZEOF (upf_rules_t, 192);

void upf_urr_time_measure_advance (rules_urr_t *urr, upf_time_t now);

void upf_rules_free (upf_rules_t *rules);

format_function_t format_upf_rules_urr_lidset;
format_function_t format_upf_rules_qer_lidset;

format_function_t format_upf_pdr;
format_function_t format_upf_far;
format_function_t format_upf_urr;

#endif // UPF_RULES_UPF_RULES_H_
