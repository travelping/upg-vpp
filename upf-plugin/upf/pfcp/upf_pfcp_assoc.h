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

#ifndef UPF_PFCP_UPF_PFCP_ASSOC_H_
#define UPF_PFCP_UPF_PFCP_ASSOC_H_

#include <vnet/session/session_types.h>

#include "upf/utils/llist.h"
#include "upf/utils/common.h"
#include "upf/utils/upf_timer.h"
#include "upf/pfcp/pfcp_proto.h"

/* associations for smfset */
UPF_LLIST_TEMPLATE_TYPES (upf_smfset_assocs_list);
UPF_LLIST_TEMPLATE_TYPES (upf_assoc_requests_list);
UPF_LLIST_TEMPLATE_TYPES (upf_assoc_sessions_list);

#define MAX_LEN 128

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  pfcp_ie_node_id_t node_id;
  pfcp_ie_recovery_time_stamp_t recovery_time_stamp;

  // when association is no longer valid, but still kept to allow sessions to
  // be removed
  u8 is_released : 1;

  session_handle_t session_handle;
  ip46_address_t rmt_addr;
  ip46_address_t lcl_addr;

  upf_assoc_sessions_list_t sessions;
  upf_timer_id_t heartbeat_timer;

  struct
  {
    u32 id;
    upf_smfset_assocs_list_anchor_t anchor;
  } smf_set;

  upf_assoc_requests_list_t requests;
} upf_assoc_t;

// for performance
STATIC_ASSERT_ALIGNOF (upf_assoc_t, CLIB_CACHE_LINE_BYTES);

typedef struct
{
  u8 *fqdn;
  upf_smfset_assocs_list_t nodes;
} upf_smf_set_t;

UPF_LLIST_TEMPLATE_DEFINITIONS (upf_smfset_assocs_list, upf_assoc_t,
                                smf_set.anchor);

upf_assoc_t *upf_assoc_get_by_nodeid (pfcp_ie_node_id_t *node_id);
upf_assoc_t *upf_assoc_create (session_handle_t session_handle,
                               ip46_address_t *lcl_addr,
                               ip46_address_t *rmt_addr,
                               pfcp_ie_node_id_t *node_id);
void upf_assoc_delete (upf_assoc_t *n, const char *reason);

bool pfcp_can_ensure_smf_set (u8 *fqdn);
void pfcp_assoc_enter_smf_set (upf_assoc_t *n, u8 *fqdn);
u32 *pfcp_assoc_exit_smf_set (upf_assoc_t *n);

// void pfcp_send_end_marker (upf_session_t *sx, u16 far_id);

/* format functions */
format_function_t format_upf_assoc;
format_function_t format_pfcp_endpoint_key;

#endif // UPF_PFCP_UPF_PFCP_ASSOC_H_
