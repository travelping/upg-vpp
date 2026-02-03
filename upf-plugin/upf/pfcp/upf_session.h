/*
 * Copyright (c) 2020-2025 Travelping GmbH
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

#ifndef UPF_PFCP_UPF_SESSION_H_
#define UPF_PFCP_UPF_SESSION_H_

#include <vnet/ip/ip.h>

#include "upf/pfcp/upf_pfcp_assoc.h"
#include "upf/utils/upf_mt.h"
#include "upf/flow/flowtable.h"
#include "upf/rules/upf_rules.h"
#include "upf/integrations/upf_netcap.h"
#include "upf/sxu/upf_session_update.h"

/* sessions for association */
UPF_LLIST_TEMPLATE_TYPES (upf_assoc_sessions_list);
/* requests in flight for session */
UPF_LLIST_TEMPLATE_TYPES (upf_session_requests_list);
/* sessions for imsi */
UPF_LLIST_TEMPLATE_TYPES (upf_imsi_sessions_list);
/* procedures for session */
UPF_LLIST_TEMPLATE_TYPES (upf_session_procedures_list);

typedef enum : u8
{
  // association removed or report
  UPF_SESSION_TERMINATION_REASON_ASSOCIATION_LOST,
  // report response with cause session not found
  UPF_SESSION_TERMINATION_REASON_CP_DESYNC,
  // report response without answer
  UPF_SESSION_TERMINATION_REASON_NO_ANSWER,
  // new session attempts to use same fteid or ip
  UPF_SESSION_TERMINATION_REASON_ENDPOINT_COLLISION,
  // dataplane requested termination
  UPF_SESSION_TERMINATION_REASON_DATAPLANE,
} upf_session_termination_reason_t;

typedef enum : u8
{
  // Used when ipfix or nat is needed
  UPF_SESSION_FLOW_MODE_CREATE, // create flows

  // Used when updated rules are flowless, but there are proxy flows remaining
  // TODO: also can be used in case of simple rules and rare redirects
  UPF_SESSION_FLOW_MODE_NO_CREATE, // lookup, but do not create flows

  UPF_SESSION_FLOW_MODE_DISABLED, // do not lookup or create flows
} upf_session_flow_mode_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u64 up_seid;
  u16 rules_generation;   // increased every time rule is updated
  u16 session_generation; // increased every time session is created
  u16 thread_id;

  session_flows_list_t flows;

  upf_time_t last_ul_traffic; // on PDR, before QER/URR/FAR
  upf_time_t last_dl_traffic; // on PDR, before QER/URR/FAR

  u32 rules_id;

  upf_timer_id_t inactivity_timer_id;

  upf_timer_id_t urr_timer_id;
  upf_lidset_t scheduled_usage_reports_lids;
  upf_time_t next_urr_timer_time;

  upf_time_t creation_time;

  upf_session_flow_mode_t flow_mode : 2;
  u8 inactivity_timeout_sent : 1;
  u8 is_created : 1;
  u8 is_removed : 1;

  // Session was terminated by dataplane. Keep objects in usual state to not
  // modify overall logic, but do not process traffic or timers to avoid
  // generation of usage or other reports
  u8 is_dp_terminated : 1;

  upf_timer_id_t clear_traffic_by_ue_timer_id;
} upf_dp_session_t;

// threads access separation is done based on cache lines
STATIC_ASSERT_ALIGNOF (upf_dp_session_t, CLIB_CACHE_LINE_BYTES);

typedef enum u8
{
  UPF_SESSION_STATE_INIT,
  UPF_SESSION_STATE_CREATED, // normal operation
  UPF_SESSION_STATE_DELETED, // dp state removed
} upf_session_state_t;

// Procedure keeps state of PFCP request context while waiting for worker
typedef struct
{
  // When procedure finishes, response promise will be complete with data
  // and sent to requester
  u32 response_id;

  u8 has_sxu : 1;
  u8 is_up_termination : 1;
  u8 is_rules_refresh : 1;
  u8 is_sent : 1; // only for debug
  upf_session_state_t prev_state : 4;
  upf_mt_session_req_kind_t mt_req_kind : 4;

  u32 old_rules_id;

  struct
  {
    upf_session_procedures_list_anchor_t list_anchor;
    u32 id;
  } session;

  upf_sxu_t sxu;
  upf_lidset_t immediate_report_urrs;
} upf_session_procedure_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u64 up_seid; // up_seid generated locally and assigned once
  u64 cp_seid; // cp_seid can be changed by SMF or in SMFSet case be invalid

  struct
  {
    u32 id; // node is always valid. Even in case of SMFSet
    upf_assoc_sessions_list_anchor_t anchor;
  } assoc;

  // control plane state, dataplane state is behind
  upf_session_state_t c_state;

  /* remote cp peer is down, f_seid is invalid */
  u8 is_lost_smfset_cp : 1;
  /* dp removed, waits for deletion from cp, reports kept */
  u8 is_up_terminated : 1;
  u8 is_dp_terminated : 1;

  upf_session_procedures_list_t procedures;

  u16 thread_index;
  // generation of this pool slot, increased every session create
  u16 session_generation;

  upf_imsi_capture_list_id_t imsi_capture_list_id;

  pfcp_ie_user_id_t user_id;

  u32 cached_fseid_id; // always set

  upf_session_requests_list_t requests;
  upf_imsi_sessions_list_anchor_t imsi_list_anchor;

  u32 rules_id; // -1 during creation or removal

  upf_session_termination_reason_t termination_reason;
} upf_session_t;

// for fast access and better cachelines separation
STATIC_ASSERT_ALIGNOF (upf_session_t, CLIB_CACHE_LINE_BYTES);

// Same as pfcp_ie_f_seid_t, but without seid
typedef struct __key_packed
{
  ip6_address_t ip6;
  ip4_address_t ip4;
  u8 flags;
  u8 _pad[7];
} upf_cached_f_seid_key_t;
STATIC_ASSERT_SIZEOF (upf_cached_f_seid_key_t, 28);

typedef struct
{
  upf_cached_f_seid_key_t key;
  u32 refcount;
} upf_cached_f_seid_t;

// Same as pfcp_ie_f_seid_t, but uses cached ip fields to save memory.
// Seems like this is preventive over-optimization, since with 1mil sessions
// memory saving is only around 15Mb.
typedef struct __key_packed
{
  u64 seid;
  u32 cached_f_seid_id;
  u8 _pad[4];
} upf_cp_fseid_key_t;
STATIC_ASSERT_SIZEOF (upf_cp_fseid_key_t, 16);

UPF_LLIST_TEMPLATE_DEFINITIONS (upf_imsi_sessions_list, upf_session_t,
                                imsi_list_anchor);
UPF_LLIST_TEMPLATE_DEFINITIONS (upf_assoc_sessions_list, upf_session_t,
                                assoc.anchor);
UPF_LLIST_TEMPLATE_DEFINITIONS (upf_session_procedures_list,
                                upf_session_procedure_t, session.list_anchor);

upf_session_t *upf_session_new (u64 up_seid);
void upf_session_init (upf_session_t *sx, upf_assoc_t *assoc,
                       pfcp_ie_f_seid_t *cp_f_seid);
void upf_session_deinit (upf_session_t *sx);
void upf_session_delete (upf_session_t *sx);
void upf_session_free (upf_session_t *sx);

upf_session_procedure_t *upf_session_enqueue_procedure (
  upf_session_t *sx, upf_mt_session_req_kind_t req_kind, upf_sxu_t *sxu,
  upf_lidset_t *p_immediate_report_urrs, bool is_up_termination,
  bool is_rules_refresh);
void upf_session_send_next_procedure (upf_session_t *sx);
void upf_session_queue_rules_refresh (upf_session_t *sx);
void upf_session_trigger_deletion (upf_session_t *sx,
                                   upf_session_termination_reason_t reason);

void upf_session_set_cp_fseid (upf_session_t *sx, pfcp_ie_f_seid_t *f_seid);
u64 upf_session_generate_up_seid (u64 cp_seid);
void upf_session_set_user_id (upf_session_t *sx, pfcp_ie_user_id_t *new_id);

upf_session_t *upf_session_get_by_up_seid (u64 up_seid);
upf_session_t *upf_session_get_by_cached_f_seid (u32 cached_f_seid_idx,
                                                 u64 cp_seid);
upf_session_t *upf_session_get_by_cp_f_seid (pfcp_ie_f_seid_t *f_seid);

// returns number of sent reports
void upf_usage_reports_trigger (u16 thread_id, upf_dp_session_t *dsx,
                                upf_rules_t *rules, upf_time_t now,
                                upf_mt_event_t **events_vec);

format_function_t format_upf_session_state;
format_function_t format_upf_session;

#endif // UPF_PFCP_UPF_SESSION_H_
