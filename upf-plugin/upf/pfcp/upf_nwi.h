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

#ifndef UPF_PFCP_UPF_NWI_H_
#define UPF_PFCP_UPF_NWI_H_

#include <vnet/fib/fib_types.h>
#include <vnet/ip/ip_types.h>

#include "upf/pfcp/pfcp_proto.h"
#include "upf/utils/common.h"

// Either Domain Name or Access Point Name.
// Hint that this is not string, but DNS labels encoding
typedef pfcp_ie_network_instance_t upf_nwi_name_t;

typedef enum : u8
{
  UPF_INTERFACE_TYPE_ACCESS = 0,  // facing UE
  UPF_INTERFACE_TYPE_CORE = 1,    // no known direction
  UPF_INTERFACE_TYPE_SGI_LAN = 2, // facing Internet
  UPF_INTERFACE_TYPE_CP = 3,      // no known direction
  UPF_INTERFACE_N_TYPE = 4,
  UPF_INTERFACE_DEFAULT_TYPE = -1,
} upf_interface_type_t;

typedef enum : u8
{
  UPF_IPFIX_POLICY_NONE,
  UPF_IPFIX_POLICY_NAT_EVENT,
  UPF_IPFIX_POLICY_FLOW_USAGE,
  UPF_IPFIX_N_POLICIES,
  // used only in FAR to indicate "do not override"
  UPF_IPFIX_POLICY_UNSPECIFIED = UPF_IPFIX_N_POLICIES
} upf_ipfix_policy_t;

typedef struct
{
  u16 contexts[FIB_PROTOCOL_IP_MAX][UPF_IPFIX_N_POLICIES];

  upf_ipfix_policy_t default_policy;
  ip_address_t collector_ip;
  u32 report_interval; // zero means no intermediate reports

  u32 observation_domain_id;
  u64 observation_point_id;
  u8 *observation_domain_name;
} upf_nwi_ipfix_t;

// nwi (name) created once and newer removed
typedef struct
{
  // encoded dns
  upf_nwi_name_t name;

  // TODO: this is backward compatibility hack for pre-MT configurations
  // Ideally we want to be explicit in interface configurations and have
  // interface to be associated with upf interface type. But here we simplify
  // having "fallback" interface if type is "undefined"
  u16 _default_interface_id;
  u16 _default_gtpu_endpoint_id;

  u16 interfaces_ids[UPF_INTERFACE_N_TYPE];
  u16 gtpu_endpoints_ids[UPF_INTERFACE_N_TYPE];

  u16 nat_pool_id;
} upf_nwi_t;

typedef struct
{
  // This resource shouldn't do any ownership and it should be possible to
  // remove it at any time. Actual resource management should be done based on
  // "real" VPP resources like routing table

  // used for dst address matching of UE IP traffic (SGi-LAN case)
  // for src matching it should be mapped to TDF fib
  u32 rx_fib_index[FIB_PROTOCOL_IP_MAX];

  // used for transmit of UE IP traffic
  u32 tx_fib_index[FIB_PROTOCOL_IP_MAX];

  upf_nwi_ipfix_t ipfix;

  u16 nwi_id;
  upf_interface_type_t intf;
} upf_interface_t;

int upf_nwi_interface_add_del (
  upf_nwi_name_t fqdn, upf_interface_type_t intf, u32 rx_ip4_table_id,
  u32 rx_ip6_table_id, u32 tx_ip4_table_id, u32 tx_ip6_table_id,
  upf_ipfix_policy_t ipfix_policy, ip_address_t *ipfix_collector_ip,
  u32 ipfix_report_interval, u32 observation_domain_id,
  u8 *observation_domain_name, u64 observation_point_id, u8 add);

upf_nwi_t *upf_nwi_get_by_name (upf_nwi_name_t name);

__clib_unused static u32
upf_nwi_get_interface_id (upf_nwi_t *nwi, upf_interface_type_t type)
{
  return is_valid_id (type) ? nwi->interfaces_ids[type] :
                              nwi->_default_interface_id;
}

u32 upf_interface_get_table_id (upf_interface_t *nwif, bool is_tx,
                                bool is_ip4);

upf_interface_type_t upf_interface_type_from_pfcp_source_interface_ie (
  pfcp_ie_source_interface_t ie);
upf_interface_type_t upf_interface_type_from_pfcp_destination_interface_ie (
  pfcp_ie_destination_interface_t ie);

format_function_t format_upf_interface_type;
unformat_function_t unformat_upf_interface_type;

#define format_upf_nwi_name format_pfcp_dns_labels

#endif // UPF_PFCP_UPF_NWI_H_
