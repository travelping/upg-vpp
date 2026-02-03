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

/* Based on the VPP flowprobe plugin */

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "upf/upf.h"
#include "upf/nat/nat.h"
#include "upf/integrations/upf_ipfix.h"
#include "upf/integrations/upf_ipfix_templates.h"

#define IPFIX_TEMPLATE_NAT_EVENT_IPV4(F)                                      \
  IPFIX_FIELD_SOURCE_IPV4_ADDRESS (F)                                         \
  IPFIX_FIELD_DESTINATION_IPV4_ADDRESS (F)                                    \
  IPFIX_FIELD_POST_NAT_SOURCE_IPV4_ADDRESS (F)                                \
  IPFIX_FIELD_POST_NAPT_SOURCE_TRANSPORT_PORT (F)                             \
  IPFIX_FIELD_NAT_EVENT (F)

#define IPFIX_TEMPLATE_NAT_EVENT_IPV6(F)                                      \
  IPFIX_FIELD_SOURCE_IPV6_ADDRESS (F)                                         \
  IPFIX_FIELD_DESTINATION_IPV6_ADDRESS (F)

#define IPFIX_TEMPLATE_NAT_EVENT_COMMON(F)                                    \
  IPFIX_FIELD_PROTOCOL_IDENTIFIER (F)                                         \
  IPFIX_FIELD_MOBILE_IMSI (F)                                                 \
  IPFIX_FIELD_INITIATOR_OCTETS (F)                                            \
  IPFIX_FIELD_RESPONDER_OCTETS (F)                                            \
  IPFIX_FIELD_INITIATOR_PACKETS (F)                                           \
  IPFIX_FIELD_RESPONDER_PACKETS (F)                                           \
  IPFIX_FIELD_FLOW_START_MILLISECONDS (F)                                     \
  IPFIX_FIELD_FLOW_END_MILLISECONDS (F)                                       \
  IPFIX_FIELD_SOURCE_TRANSPORT_PORT (F)                                       \
  IPFIX_FIELD_DESTINATION_TRANSPORT_PORT (F)                                  \
  IPFIX_FIELD_BIFLOW_DIRECTION (F)

static ipfix_field_specifier_t *
upf_ipfix_template_nat_event_ip4_fields (ipfix_field_specifier_t *f)
{
  IPFIX_TEMPLATE_FIELDS (IPFIX_TEMPLATE_NAT_EVENT_IPV4,
                         IPFIX_TEMPLATE_NAT_EVENT_COMMON);
}

static ipfix_field_specifier_t *
upf_ipfix_template_nat_event_ip6_fields (ipfix_field_specifier_t *f)
{
  IPFIX_TEMPLATE_FIELDS (IPFIX_TEMPLATE_NAT_EVENT_IPV6,
                         IPFIX_TEMPLATE_NAT_EVENT_COMMON);
}

static u32
upf_ipfix_template_nat_event_ip4_values (u16 thread_id, vlib_buffer_t *to_b,
                                         u16 offset, u32 session_id,
                                         flow_entry_t *f,
                                         upf_interface_t *uplink_nwif,
                                         upf_ipfix_report_info_t *info,
                                         bool last)
{
  upf_nat_main_t *unm = &upf_nat_main;
  upf_main_t *um = &upf_main;

  upf_nat_flow_t *nat_flow = NULL;
  upf_nat_binding_t *nat_binding = NULL;

  upf_session_t *sx = pool_elt_at_index (um->sessions, session_id);
  upf_dp_session_t *dsx = upf_wk_get_dp_session (thread_id, session_id);

  ASSERT (dsx->thread_id == thread_id);

  if (unm->initialized)
    {
      upf_nat_wk_t *unw = vec_elt_at_index (unm->workers, thread_id);

      if (is_valid_id (f->nat_flow_id))
        {
          nat_flow = pool_elt_at_index (unw->flows, f->nat_flow_id);
          nat_binding =
            upf_worker_pool_elt_at_index (unm->bindings, nat_flow->binding_id);
        }
    }

  IPFIX_TEMPLATE_VALUES (IPFIX_TEMPLATE_NAT_EVENT_IPV4,
                         IPFIX_TEMPLATE_NAT_EVENT_COMMON);
}

static u32
upf_ipfix_template_nat_event_ip6_values (u16 thread_id, vlib_buffer_t *to_b,
                                         u16 offset, u32 session_id,
                                         flow_entry_t *f,
                                         upf_interface_t *uplink_nwif,
                                         upf_ipfix_report_info_t *info,
                                         bool last)
{
  upf_main_t *um = &upf_main;
  upf_session_t *sx = pool_elt_at_index (um->sessions, session_id);

  IPFIX_TEMPLATE_VALUES (IPFIX_TEMPLATE_NAT_EVENT_IPV6,
                         IPFIX_TEMPLATE_NAT_EVENT_COMMON);
}

#define IPFIX_TEMPLATE_FLOW_USAGE_IPV4(F)                                     \
  IPFIX_FIELD_SOURCE_IPV4_ADDRESS (F)                                         \
  IPFIX_FIELD_DESTINATION_IPV4_ADDRESS (F)

#define IPFIX_TEMPLATE_FLOW_USAGE_IPV6(F)                                     \
  IPFIX_FIELD_SOURCE_IPV6_ADDRESS (F)                                         \
  IPFIX_FIELD_DESTINATION_IPV6_ADDRESS (F)

#define IPFIX_TEMPLATE_FLOW_USAGE_COMMON(F)                                   \
  IPFIX_FIELD_PROTOCOL_IDENTIFIER (F)                                         \
  IPFIX_FIELD_INITIATOR_OCTETS (F)                                            \
  IPFIX_FIELD_RESPONDER_OCTETS (F)                                            \
  IPFIX_FIELD_INITIATOR_PACKETS (F)                                           \
  IPFIX_FIELD_RESPONDER_PACKETS (F)                                           \
  IPFIX_FIELD_FLOW_START_MILLISECONDS (F)                                     \
  IPFIX_FIELD_FLOW_END_MILLISECONDS (F)                                       \
  IPFIX_FIELD_VRF_NAME (F)                                                    \
  IPFIX_FIELD_INTERFACE_NAME (F)                                              \
  IPFIX_FIELD_OBSERVATION_DOMAIN_NAME (F)                                     \
  IPFIX_FIELD_OBSERVATION_POINT_ID (F)                                        \
  IPFIX_FIELD_BIFLOW_DIRECTION (F)

static ipfix_field_specifier_t *
upf_ipfix_template_flow_usage_ip4_fields (ipfix_field_specifier_t *f)
{
  IPFIX_TEMPLATE_FIELDS (IPFIX_TEMPLATE_FLOW_USAGE_IPV4,
                         IPFIX_TEMPLATE_FLOW_USAGE_COMMON);
}

static ipfix_field_specifier_t *
upf_ipfix_template_flow_usage_ip6_fields (ipfix_field_specifier_t *f)
{
  IPFIX_TEMPLATE_FIELDS (IPFIX_TEMPLATE_FLOW_USAGE_IPV6,
                         IPFIX_TEMPLATE_FLOW_USAGE_COMMON);
}

static u32
upf_ipfix_template_flow_usage_ip4_values (u16 thread_id, vlib_buffer_t *to_b,
                                          u16 offset, u32 session_id,
                                          flow_entry_t *f,
                                          upf_interface_t *uplink_nwif,
                                          upf_ipfix_report_info_t *info,
                                          bool last)
{
  IPFIX_TEMPLATE_VALUES (IPFIX_TEMPLATE_FLOW_USAGE_IPV4,
                         IPFIX_TEMPLATE_FLOW_USAGE_COMMON);
}

static u32
upf_ipfix_template_flow_usage_ip6_values (u16 thread_id, vlib_buffer_t *to_b,
                                          u16 offset, u32 session_id,
                                          flow_entry_t *f,
                                          upf_interface_t *uplink_nwif,
                                          upf_ipfix_report_info_t *info,
                                          bool last)
{
  IPFIX_TEMPLATE_VALUES (IPFIX_TEMPLATE_FLOW_USAGE_IPV6,
                         IPFIX_TEMPLATE_FLOW_USAGE_COMMON);
}

upf_ipfix_template_t upf_ipfix_templates[UPF_IPFIX_N_POLICIES] = {
  [UPF_IPFIX_POLICY_NONE] = {
    .name = "none",
    .per_ip={
      [FIB_PROTOCOL_IP4] = {
        .field_count = 0,
      },
      [FIB_PROTOCOL_IP6] = {
        .field_count = 0,
      },
    },
  },
  [UPF_IPFIX_POLICY_NAT_EVENT] = {
    .name = "NatEvent",
    .alt_name = "default",
    .per_ip={
      [FIB_PROTOCOL_IP4] = {
        .field_count = IPFIX_TEMPLATE_COUNT (IPFIX_TEMPLATE_NAT_EVENT_IPV4,
			  IPFIX_TEMPLATE_NAT_EVENT_COMMON),
        .add_fields = upf_ipfix_template_nat_event_ip4_fields,
        .add_values = upf_ipfix_template_nat_event_ip4_values,
      },
      [FIB_PROTOCOL_IP6] = {
        .field_count = IPFIX_TEMPLATE_COUNT (IPFIX_TEMPLATE_NAT_EVENT_IPV6,
			  IPFIX_TEMPLATE_NAT_EVENT_COMMON),
        .add_fields = upf_ipfix_template_nat_event_ip6_fields,
        .add_values = upf_ipfix_template_nat_event_ip6_values,
      },
    },
  },
  [UPF_IPFIX_POLICY_FLOW_USAGE] = {
    .name = "FlowUsage",
    .alt_name = "dest",
    .per_ip={
      [FIB_PROTOCOL_IP4] = {
        .field_count = IPFIX_TEMPLATE_COUNT (IPFIX_TEMPLATE_FLOW_USAGE_IPV4,
			  IPFIX_TEMPLATE_FLOW_USAGE_COMMON),
        .add_fields = upf_ipfix_template_flow_usage_ip4_fields,
        .add_values = upf_ipfix_template_flow_usage_ip4_values,
      },
      [FIB_PROTOCOL_IP6] = {
        .field_count = IPFIX_TEMPLATE_COUNT (IPFIX_TEMPLATE_FLOW_USAGE_IPV6,
			  IPFIX_TEMPLATE_FLOW_USAGE_COMMON),
        .add_fields = upf_ipfix_template_flow_usage_ip6_fields,
        .add_values = upf_ipfix_template_flow_usage_ip6_values,
      },
    },
  },
};
