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

#ifndef UPF_SXU_UPF_SESSION_UPDATE_H_
#define UPF_SXU_UPF_SESSION_UPDATE_H_

#include "upf/utils/upf_localids.h"
#include "upf/utils/heap_handle.h"
#include "upf/utils/common.h"
#include "upf/rules/upf_rules.h"
#include "upf/rules/upf_ipfilter.h"
#include "upf/pfcp/pfcp_proto.h"
#include "upf/pfcp/upf_nwi.h"
#include "upf/integrations/upf_netcap.h"

// === SXU Types ===
// Each type should have _key_t type which will be key for searching

typedef pfcp_ie_pdr_id_t sxu_pdr_key_t;

typedef struct
{
  u8 gtpu_outer_header_removal : 1;
  u8 do_reuse_acls : 1; // keep old acls during update

  u32 precedence; // mandatory
  struct
  {
    u16 nwi_id;                            // always valid
    upf_interface_type_t source_interface; // mandatory
    u8 ref_traffic_ep_xid; // always present, otherwise pointless?
    u8 ref_application_xid;

    ipfilter_rule_t *sdf_filters_new; // only when !do_reuse_acls
  } pdi;                              // mandatory

  u8 ref_far_xid;
  upf_lidset_t refs_urr_xids;
  upf_lidset_t refs_qer_xids;

  // try to reuse acls from before update
  u32 _old_acl_cached_id;
} sxu_pdr_t;

typedef pfcp_ie_far_id_t sxu_far_key_t;

typedef struct
{
  rules_far_action_t apply_action; // mandatory

  struct
  {
    u8 has_redirect_information : 1;
    u8 has_outer_header_creation : 1;
    u8 bbf_apply_action_nat : 1;
    u8 do_send_end_marker : 1;

    upf_interface_type_t destination_interface; // mandatory
    u16 nwi_id; // always valid if action forward

    struct __clib_packed
    {
      u32 teid;
      ip4_address_t addr4;
      ip6_address_t addr6;
    } ohc; // outer_header_creation

    u16 policy_id; // forwarding_policy id

    pfcp_ie_redirect_information_t redirect_information;
  } fp; // forwarding_parameters

  upf_ipfix_policy_t ipfix_policy;
  upf_xid_t nat_binding_xid;

  // fields below initialized during pdr compile
  upf_lidset_t _pdr_lids;
  u8 _is_ip4 : 1;
  u8 _is_ip6 : 1;
} sxu_far_t;

typedef pfcp_ie_urr_id_t sxu_urr_key_t;

typedef struct
{
  pfcp_ie_reporting_triggers_t reporting_triggers;

  urr_update_flags_t update_flags;

  u8 measurement_method_volume : 1;
  u8 measurement_method_duration : 1;
  u8 measurement_method_event : 1;
  u8 has_volume_quota_ul : 1;
  u8 has_volume_quota_dl : 1;
  u8 has_volume_quota_tot : 1;
  u8 has_time_quota : 1;

  u32 measurement_period;
  u32 time_threshold;
  u32 time_quota;
  u32 quota_holding_time;
  u32 quota_validity_time;
  u32 monitoring_time;

  u64 volume_threshold_total;
  u64 volume_threshold_ul;
  u64 volume_threshold_dl;
  u64 volume_quota_total;
  u64 volume_quota_ul;
  u64 volume_quota_dl;

  upf_lidset_t refs_linked_urr_xids;
} sxu_urr_t;

typedef pfcp_ie_qer_id_t sxu_qer_key_t;

typedef struct
{
  u8 gate_closed_ul : 1; // required
  u8 gate_closed_dl : 1; // required
  u8 has_maximum_bitrate : 1;
  u32 maximum_bitrate[UPF_N_DIR]; // in kilobits/s (1000 bits/s)
} sxu_qer_t;

// Traffic endpoint merges common fields of PDRs together. Similar to Traffic
// Endpoint from PDI Optimization feature, but not exact.
typedef struct __key_packed
{
  u8 is_destination_ip : 1; // is UE ip expected to be dst or src of packet
  // is_ip4 and is_ip6 can be both false in case of GTP proxy (no UE IP)
  u8 is_ip4 : 1; // it can be gtpu and ip4
  u8 is_ip6 : 1; // it can be gtpu and ip6
  u8 is_gtpu : 1;
  u8 _pad0 : 4;

  upf_interface_type_t intf; // always present
  u16 nwi_id;                // always present

  u8 ref_f_teid_allocation_xid; // preent if GTPU and UP allocated TEID
  u8 ref_gtpu_ep_xid;           // present if GTPU and CP provided TEID

  u8 _pad1[6];

  ip4_address_t ue_addr4; // zero ip means match any
  ip6_address_t ue_addr6; // zero ip means match any
} sxu_traffic_ep_key_t;
STATIC_ASSERT_SIZEOF (sxu_traffic_ep_key_t, 32);

typedef struct
{
  u8 ref_ue_ip4_xid; // if IP
  u8 ref_ue_ip6_xid; // if IP
  upf_xid_t capture_set_xid;
} sxu_traffic_ep_t;

typedef struct __key_packed
{
  u16 nwi_id;
  upf_interface_type_t intf;
  u8 choose_id;
} sxu_f_teid_allocation_key_t;
STATIC_ASSERT_SIZEOF (sxu_f_teid_allocation_key_t, 4);

typedef struct
{
  u8 ref_gtpu_ep_xid;
} sxu_f_teid_allocation_t;

typedef struct __key_packed
{
  u32 teid;
  u16 gtpu_ep_id;
  u8 _pad[2];
} sxu_gtpu_ep_key_t;
STATIC_ASSERT_SIZEOF (sxu_gtpu_ep_key_t, 8);

typedef struct
{
  // we need to know if this is uplink or not, but make it even more generic by
  // not allowing different interface types to use same fteid and nwi
  upf_interface_type_t intf;
  u16 nwi_id;
} sxu_gtpu_ep_t;

typedef struct __key_packed
{
  ip4_address_t addr;
  u16 fib_id;
  u8 is_source_matching : 1; // TDF
  u8 _pad0 : 7;
  u8 _pad1[1];
} sxu_ue_ip_ep4_key_t;
STATIC_ASSERT_SIZEOF (sxu_ue_ip_ep4_key_t, 8);

typedef struct
{
  index_t dpo_result_id;
} sxu_ue_ip_ep4_t;

typedef struct __key_packed
{
  ip6_address_t addr;
  u16 fib_id;
  u8 is_source_matching : 1; // TDF
  u8 _pad0 : 7;
  u8 _pad1[5];
} sxu_ue_ip_ep6_key_t;
STATIC_ASSERT_SIZEOF (sxu_ue_ip_ep6_key_t, 24);

typedef struct
{
  index_t dpo_result_id;
} sxu_ue_ip_ep6_t;

// application ID, so we reference it only "session" amount of times
typedef struct __key_packed
{
  u16 application_id;
} sxu_adf_application_key_t;

typedef struct
{
} sxu_adf_application_t;

typedef struct __key_packed
{
  u16 nwi_id;
} sxu_nwi_stat_key_t;

typedef struct
{
} sxu_nwi_stat_t;

typedef struct __key_packed
{
  u16 gtpu_ep_id;
} sxu_gtpu_ep_stat_key_t;

typedef struct
{
} sxu_gtpu_ep_stat_t;

typedef struct __key_packed
{
  u16 policy_id;
} sxu_policy_ref_key_t;

typedef struct
{
} sxu_policy_ref_t;

typedef struct
{
  u16 pool_id;
} sxu_nat_binding_key_t;

typedef struct
{
  u32 binding_id;
  upf_xid_t capture_set_xid;
} sxu_nat_binding_t;

typedef struct
{
  upf_imsi_capture_id_t imsi_capture_id;
} sxu_imsi_capture_key_t;

// Requested IMSI captures
typedef struct
{
} sxu_imsi_capture_t;

typedef struct
{
  u16 nwi_id;
  upf_interface_type_t intf;
} sxu_capture_set_key_t;

// Enabled netcap streams for each capture
typedef struct
{
  // only here to transfer already created ids
  netcap_stream_id_t *capture_streams; // index is imsi_capture xid
} sxu_capture_set_t;

// === End of SXU Types ===

typedef struct
{
  u16 references;

  u8 has_existed : 1;
  u8 will_exist : 1;
  u8 is_pfcp_action_taken : 1; // Spec limits to 1 action per modify request
  u8 _pad0 : 5;

  // Before remapping - old rules lid. After remapping - new rules lid
  upf_lid_t lid;
} sxu_slot_state_t;

// objects which are managed by pfcp
#define foreach_sxu_pfcp_type                                                 \
  _ (pdr, pdrs)                                                               \
  _ (far, fars)                                                               \
  _ (urr, urrs)                                                               \
  _ (qer, qers)

// refcounted objects, which are created dynamically
#define foreach_sxu_dynamic_type                                              \
  _ (traffic_ep, traffic_eps)                                                 \
  _ (f_teid_allocation, f_teid_allocations)                                   \
  _ (gtpu_ep, gtpu_eps)                                                       \
  _ (ue_ip_ep4, ue_ip_eps4)                                                   \
  _ (ue_ip_ep6, ue_ip_eps6)                                                   \
  _ (capture_set, capture_sets)

// objects which are needed only during update and not saved later
#define foreach_sxu_temporary_type                                            \
  _ (adf_application, adf_applications)                                       \
  _ (nwi_stat, nwi_stats)                                                     \
  _ (gtpu_ep_stat, gtpu_ep_stats)                                             \
  _ (nat_binding, nat_bindings)                                               \
  _ (imsi_capture, imsi_captures)                                             \
  _ (policy_ref, policy_refs)

// objects which have corresponding rules type
#define foreach_sxu_nontemporary_type                                         \
  foreach_sxu_pfcp_type foreach_sxu_dynamic_type

#define foreach_sxu_nonpfcp_type                                              \
  foreach_sxu_dynamic_type foreach_sxu_temporary_type

#define foreach_sxu_type                                                      \
  foreach_sxu_nontemporary_type foreach_sxu_temporary_type

#define _(name, plural)                                                       \
  typedef struct                                                              \
  {                                                                           \
    sxu_slot_state_t state;                                                   \
    sxu_##name##_key_t key;                                                   \
    sxu_##name##_t val;                                                       \
  } sxu_slot_##name##_t;                                                      \
                                                                              \
  typedef struct                                                              \
  {                                                                           \
    sxu_##name##_key_t key;                                                   \
    sxu_##name##_t val;                                                       \
  } sxu_kv_##name##_t;
foreach_sxu_type
#undef _

typedef enum
{
#define _(name, plural) UPF_SXU_TYPE_##name,
  foreach_sxu_type
#undef _
    UPF_SXU_N_TYPES
} upf_sxu_type_t;

typedef struct
{
  upf_sxu_type_t type;
  pfcp_ie_cause_t cause;
  upf_xid_t xid;
  u32 pfcp_id;
  pfcp_ie_offending_ie_t offending_ie;

  u8 *message; // vec string
} upf_sxu_error_t;

typedef struct
{
  u32 conflicted_session_id;
  upf_sxu_type_t type;
  upf_xid_t xid;
} upf_sxu_conflict_t;

typedef struct
{
  u32 session_id;
  u32 new_rules_id; // -1 during session removal
  u32 old_rules_id; // -1 during session creation
  u16 thread_id;
  u16 session_generation;
  upf_imsi_capture_list_id_t capture_list_id;
  u8 is_session_deletion : 1;
  u8 is_compiled : 1;
  u8 has_error : 1;

  union
  {
    struct
    {
#define _(name, plural) sxu_slot_##name##_t *plural;
      foreach_sxu_type
#undef _
    };
    void *slots_array[UPF_SXU_N_TYPES];
  };

  // Active elements max index after rules application.
  // Includes gaps from id allocation.
  struct
  {
#define _(name, plural) u8 plural;
    foreach_sxu_nontemporary_type
#undef _
  } next_vec_len;

  // Allocation map
  struct
  {
#define _(name, plural) upf_lidset_t plural;
    foreach_sxu_nontemporary_type
#undef _
  } next_slots;

  // to return created values
  upf_lidset_t created_pdr_lids;

  // to init or remove timers and etc
  upf_lidset_t created_urr_lids;
  upf_lidset_t removed_urr_lids;

  upf_sxu_error_t error;
  upf_sxu_conflict_t *endpoint_conflicts;

  u32 inactivity_timeout;
} upf_sxu_t;

void upf_sxu_init (upf_sxu_t *sxu, u32 session_id, u16 session_generation,
                   u16 thread_id, u32 old_rules_id);
void upf_sxu_1_init_from_rules (upf_sxu_t *sxu, upf_rules_t *rules);
void upf_sxu_deinit (upf_sxu_t *sxu);

typedef struct
{
  pfcp_ie_create_pdr_t *create_pdrs;
  pfcp_ie_update_pdr_t *update_pdrs;
  pfcp_ie_remove_pdr_t *remove_pdrs;
  pfcp_ie_create_far_t *create_fars;
  pfcp_ie_update_far_t *update_fars;
  pfcp_ie_remove_far_t *remove_fars;
  pfcp_ie_create_urr_t *create_urrs;
  pfcp_ie_update_urr_t *update_urrs;
  pfcp_ie_remove_urr_t *remove_urrs;
  pfcp_ie_create_qer_t *create_qers;
  pfcp_ie_update_qer_t *update_qers;
  pfcp_ie_remove_qer_t *remove_qers;
} upf_sxu_pfcp_actions_t;

int upf_sxu_stage_1_provide_pfcp_actions (upf_sxu_t *sxu,
                                          upf_sxu_pfcp_actions_t *actions);
void upf_sxu_stage_1_provide_delete_actions (upf_sxu_t *sxu);
int upf_sxu_stage_2_update_dynamic (upf_sxu_t *sxu);
void upf_sxu_stage_3_compile_rules (upf_sxu_t *sxu);
void upf_sxu_stage_4_before_rpc (upf_sxu_t *sxu);
void upf_sxu_stage_5_after_rpc (upf_sxu_t *sxu);

format_function_t format_upf_sxu_keys;
format_function_t format_upf_sxu;
format_function_t format_sxu_slot_state;
format_function_t format_upf_sxu_type;

#define _(name, plural)                                                       \
  int upf_sxu_##name##_error_set_by_pfcp_id (                                 \
    upf_sxu_t *sxu, u32 pfcp_id, pfcp_ie_cause_t cause,                       \
    pfcp_ie_offending_ie_t offending_ie, const char *message);                \
                                                                              \
  int upf_sxu_##name##_error_wrap (upf_sxu_t *sxu, upf_xid_t xid,             \
                                   const char *message);
foreach_sxu_pfcp_type
#undef _

#define _(name, plural)                                                       \
  int upf_sxu_##name##_error_set_by_xid (                                     \
    upf_sxu_t *sxu, upf_xid_t xid, pfcp_ie_cause_t cause,                     \
    pfcp_ie_offending_ie_t offending_ie, const char *message);
  foreach_sxu_type
#undef _

#define _(name, plural)                                                       \
  format_function_t format_sxu_##name##_key;                                  \
  format_function_t format_sxu_##name;
foreach_sxu_type
#undef _

typedef struct
{
  u16 offset;
  u8 is_lidset : 1;    // if not, then xid
  upf_sxu_type_t type; // target type
} upf_sxu_type_meta_ref_t;

typedef struct
{
  upf_sxu_type_meta_ref_t *refs;
  u16 ref_count;
  u16 slot_size;
} upf_sxu_type_meta_t;

// array with index being upf_sxu_type_t
extern const upf_sxu_type_meta_t sxu_types_meta_walk[UPF_SXU_N_TYPES];

__clib_unused static bool
sxu_types_is_pfcp_type (upf_sxu_type_t type)
{
  return type == UPF_SXU_TYPE_pdr || type == UPF_SXU_TYPE_far ||
         type == UPF_SXU_TYPE_qer || type == UPF_SXU_TYPE_urr;
}

bool upf_sxu_type_backwalk_to_pfcp_type (upf_sxu_t *sxu,
                                         upf_sxu_type_t search_t,
                                         upf_xid_t search_xid,
                                         upf_sxu_type_t *result_t,
                                         upf_xid_t *result_xid);

bool upf_sxu_type_backwalk_to_pfcp_failed_rule_id (
  upf_sxu_t *sxu, upf_sxu_type_t t, upf_xid_t xid, u32 pfcp_id,
  pfcp_ie_failed_rule_id_t *r_failed_rule_id);

#endif // UPF_SXU_UPF_SESSION_UPDATE_H_
