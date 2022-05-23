/*
 * Copyright (c) 2017-2022 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Based on the VPP flowprobe plugin */

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <upf/upf.api_enum.h>
#include <upf/upf.api_types.h>

#include "upf.h"
#include "upf_ipfix.h"
#include "upf_ipfix_templates.h"
#include "upf_pfcp.h"

#define IPFIX_TEMPLATE_DEFAULT_IPV4(F)			\
  IPFIX_FIELD_SOURCE_IPV4_ADDRESS(F)			\
  IPFIX_FIELD_DESTINATION_IPV4_ADDRESS(F)		\
  IPFIX_FIELD_PROTOCOL_IDENTIFIER(F)			\
  IPFIX_FIELD_POST_NAT_SOURCE_IPV4_ADDRESS(F)		\
  IPFIX_FIELD_POST_NAPT_SOURCE_TRANSPORT_PORT(F)	\
  IPFIX_FIELD_NAT_EVENT(F)

#define IPFIX_TEMPLATE_DEFAULT_IPV6(F)		\
  IPFIX_FIELD_SOURCE_IPV6_ADDRESS(F)		\
  IPFIX_FIELD_DESTINATION_IPV6_ADDRESS(F)	\
  IPFIX_FIELD_PROTOCOL_IDENTIFIER(F)

#define IPFIX_TEMPLATE_DEFAULT_COMMON(F)	\
  IPFIX_FIELD_MOBILE_IMSI(F)			\
  IPFIX_FIELD_PACKET_DELTA_COUNT(F)		\
  IPFIX_FIELD_OCTET_DELTA_COUNT(F)		\
  IPFIX_FIELD_FLOW_START_NANOSECONDS(F)		\
  IPFIX_FIELD_FLOW_END_NANOSECONDS(F)		\
  IPFIX_FIELD_SOURCE_TRANSPORT_PORT(F)		\
  IPFIX_FIELD_DESTINATION_TRANSPORT_PORT(F)

static ipfix_field_specifier_t *
upf_ipfix_template_default_ip4_fields (ipfix_field_specifier_t * f)
{
  IPFIX_TEMPLATE_FIELDS (IPFIX_TEMPLATE_DEFAULT_IPV4,
			 IPFIX_TEMPLATE_DEFAULT_COMMON);
}

static ipfix_field_specifier_t *
upf_ipfix_template_default_ip6_fields (ipfix_field_specifier_t * f)
{
  IPFIX_TEMPLATE_FIELDS (IPFIX_TEMPLATE_DEFAULT_IPV6,
			 IPFIX_TEMPLATE_DEFAULT_COMMON);
}

static u32
upf_ipfix_template_default_ip4_values (vlib_buffer_t * to_b,
				       flow_entry_t * f,
				       flow_direction_t direction,
				       u16 offset,
				       upf_session_t *sx,
				       upf_ipfix_info_t *info,
				       bool last)
{
  IPFIX_TEMPLATE_VALUES (IPFIX_TEMPLATE_DEFAULT_IPV4,
			 IPFIX_TEMPLATE_DEFAULT_COMMON);
}

static u32
upf_ipfix_template_default_ip6_values (vlib_buffer_t * to_b,
				       flow_entry_t * f,
				       flow_direction_t direction,
				       u16 offset,
				       upf_session_t *sx,
				       upf_ipfix_info_t *info,
				       bool last)
{
  IPFIX_TEMPLATE_VALUES (IPFIX_TEMPLATE_DEFAULT_IPV6,
			 IPFIX_TEMPLATE_DEFAULT_COMMON);
}

#define IPFIX_TEMPLATE_DEST_IPV4(F)		\
  IPFIX_FIELD_SOURCE_IPV4_ADDRESS(F)		\
  IPFIX_FIELD_DESTINATION_IPV4_ADDRESS(F)

#define IPFIX_TEMPLATE_DEST_IPV6(F)		\
  IPFIX_FIELD_SOURCE_IPV6_ADDRESS(F)		\
  IPFIX_FIELD_DESTINATION_IPV6_ADDRESS(F)

#define IPFIX_TEMPLATE_DEST_COMMON(F)	       	\
  IPFIX_FIELD_OCTET_DELTA_COUNT(F)		\
  IPFIX_FIELD_FLOW_END_NANOSECONDS(F)		\
  IPFIX_FIELD_FLOW_DIRECTION(F)			\
  IPFIX_FIELD_INGRESS_VRF_ID(F)			\
  IPFIX_FIELD_EGRESS_VRF_ID(F)			\
  IPFIX_FIELD_VRF_NAME(F)			\
  IPFIX_FIELD_INTERFACE_NAME(F)			\
  IPFIX_FIELD_OBSERVATION_DOMAIN_NAME(F)	\
  IPFIX_FIELD_OBSERVATION_POINT_ID(F)

static ipfix_field_specifier_t *
upf_ipfix_template_dest_ip4_fields (ipfix_field_specifier_t * f)
{
  IPFIX_TEMPLATE_FIELDS (IPFIX_TEMPLATE_DEST_IPV4,
			 IPFIX_TEMPLATE_DEST_COMMON);
}

static ipfix_field_specifier_t *
upf_ipfix_template_dest_ip6_fields (ipfix_field_specifier_t * f)
{
  IPFIX_TEMPLATE_FIELDS (IPFIX_TEMPLATE_DEST_IPV6,
			 IPFIX_TEMPLATE_DEST_COMMON);
}

static u32
upf_ipfix_template_dest_ip4_values (vlib_buffer_t * to_b,
				    flow_entry_t * f,
				    flow_direction_t direction,
				    u16 offset,
				    upf_session_t *sx,
				    upf_ipfix_info_t *info,
				    bool last)
{
  IPFIX_TEMPLATE_VALUES (IPFIX_TEMPLATE_DEST_IPV4,
			 IPFIX_TEMPLATE_DEST_COMMON);
}

static u32
upf_ipfix_template_dest_ip6_values (vlib_buffer_t * to_b,
				    flow_entry_t * f,
				    flow_direction_t direction,
				    u16 offset,
				    upf_session_t *sx,
				    upf_ipfix_info_t *info,
				    bool last)
{
  IPFIX_TEMPLATE_VALUES (IPFIX_TEMPLATE_DEST_IPV6,
			 IPFIX_TEMPLATE_DEST_COMMON);
}

upf_ipfix_template_t upf_ipfix_templates[UPF_IPFIX_N_POLICIES] = {
  [UPF_IPFIX_POLICY_NONE] = {
    .name = "none",
    .field_count_ipv4 = 0,
    .field_count_ipv6 = 0,
  },
  [UPF_IPFIX_POLICY_DEFAULT] = {
    .name = "default",
    .field_count_ipv4 =
    IPFIX_TEMPLATE_COUNT (IPFIX_TEMPLATE_DEFAULT_IPV4,
			  IPFIX_TEMPLATE_DEFAULT_COMMON),
    .field_count_ipv6 =
    IPFIX_TEMPLATE_COUNT (IPFIX_TEMPLATE_DEFAULT_IPV6,
			  IPFIX_TEMPLATE_DEFAULT_COMMON),
    .add_ip4_fields = upf_ipfix_template_default_ip4_fields,
    .add_ip6_fields = upf_ipfix_template_default_ip6_fields,
    .add_ip4_values = upf_ipfix_template_default_ip4_values,
    .add_ip6_values = upf_ipfix_template_default_ip6_values,
  },
  [UPF_IPFIX_POLICY_DEST] = {
    .name = "dest",
    .field_count_ipv4 =
    IPFIX_TEMPLATE_COUNT (IPFIX_TEMPLATE_DEST_IPV4,
			  IPFIX_TEMPLATE_DEST_COMMON),
    .field_count_ipv6 =
    IPFIX_TEMPLATE_COUNT (IPFIX_TEMPLATE_DEST_IPV6,
			  IPFIX_TEMPLATE_DEST_COMMON),
    .add_ip4_fields = upf_ipfix_template_dest_ip4_fields,
    .add_ip6_fields = upf_ipfix_template_dest_ip6_fields,
    .add_ip4_values = upf_ipfix_template_dest_ip4_values,
    .add_ip6_values = upf_ipfix_template_dest_ip6_values,
  },
};
