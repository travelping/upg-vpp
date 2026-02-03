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

#ifndef UPF_NAT_NAT_PRIVATE_H_
#define UPF_NAT_NAT_PRIVATE_H_

#include <vlib/vlib.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/ip/icmp46_packet.h>

#include "upf/nat/nat.h"
#include "upf/utils/common.h"

// copy from plugins/nat/lib/lib.h

typedef struct
{
  u16 identifier;
  u16 sequence;
} nat_icmp_echo_header_t;

typedef struct
{
  u16 src_port, dst_port;
} nat_tcp_udp_header_t;

// copy from plugins/nat/lib/inlines.h

always_inline __clib_unused u64
icmp_type_is_error_message (u8 icmp_type)
{
  int bmp = 0;
  bmp |= 1 << ICMP4_destination_unreachable;
  bmp |= 1 << ICMP4_time_exceeded;
  bmp |= 1 << ICMP4_parameter_problem;
  bmp |= 1 << ICMP4_source_quench;
  bmp |= 1 << ICMP4_redirect;
  bmp |= 1 << ICMP4_alternate_host_address;

  return (1ULL << icmp_type) & bmp;
}

// end of copy

typedef union __key_packed
{
  struct __key_packed
  {
    ip4_address_t src_addr;
    ip4_address_t dst_addr;
    u16 src_port; // 0 for ICMP
    u16 dst_port; // or ICMP echo identification
    u8 proto;
    u8 _pad0[1];
    u16 nat_pool_id;
  };
  u64 as_u64[2];
} upf_nat_flow_key_t;
STATIC_ASSERT_SIZEOF (upf_nat_flow_key_t, 16);

typedef union __key_packed
{
  struct __key_packed
  {
    ip4_address_t in_addr;
    ip4_address_t out_addr;
    u16 icmp_id;
    u16 nat_pool_id;
    u8 _pad0[4];
  };
  u32 as_u64[2];
} upf_nat_icmp_flow_key_t;
STATIC_ASSERT_SIZEOF (upf_nat_icmp_flow_key_t, 16);

typedef union
{
  struct
  {
    u32 flow_id;
    u16 thread_id;
    u8 _pad[2];
  };
  u64 as_u64;
} upf_nat_flow_value_t;
STATIC_ASSERT_SIZEOF (upf_nat_flow_value_t, 8);

always_inline __clib_unused void
upf_nat_flow_bihash_value_unpack (u64 value, u32 *flow_id, u16 *thread_id)
{
  upf_nat_flow_value_t v = { .as_u64 = value };
  *flow_id = v.flow_id;
  *thread_id = v.thread_id;
}
always_inline __clib_unused u64
upf_nat_flow_bihash_value_pack (u32 flow_id, u16 thread_id)
{
  upf_nat_flow_value_t v = {
    .flow_id = flow_id,
    .thread_id = thread_id,
  };
  return v.as_u64;
}

/* block_id helpers used to convert from endpoint+port to free block vector
 * index in pool to avoid creation of vector of vectors for free blocks */
always_inline __clib_unused void
upf_nat_block_id_to_components (u32 block_id, u32 blocks_per_addr,
                                u32 *endpoint_id, u32 *port_block_id)
{
  *endpoint_id = block_id / blocks_per_addr;
  *port_block_id = block_id % blocks_per_addr;
}
always_inline __clib_unused u32
upf_nat_block_id_from_components (u32 blocks_per_addr, u32 endpoint_id,
                                  u32 port_block_id)
{
  return endpoint_id * blocks_per_addr + port_block_id;
}

UPF_LLIST_TEMPLATE_DEFINITIONS (upf_nat_flows_binding_list, upf_nat_flow_t,
                                binding_anchor);
UPF_LLIST_TEMPLATE_DEFINITIONS (upf_nat_icmp_flows_binding_lru_list,
                                upf_nat_icmp_flow_t, binding_lru_anchor);
UPF_LLIST_TEMPLATE_DEFINITIONS (upf_nat_icmp_flows_lru_list,
                                upf_nat_icmp_flow_t, lru_anchor);

typedef enum
{
  UPF_NAT_ICMP_FLOW_CREATE_ERROR_LIMIT_PER_BINDING,
  UPF_NAT_ICMP_FLOW_CREATE_ERROR_OUT_OF_PORTS,
} upf_nat_icmp_flow_create_error_t;

u32 upf_nat_icmp_flow_create (u32 thread_index, u32 binding_id,
                              ip4_header_t *ip, void *l4_hdr, u32 now,
                              upf_nat_icmp_flow_create_error_t *error);
void upf_nat_icmp_flow_delete (u32 thread_index, u32 nat_flow_id);

extern vlib_node_registration_t upf_nat_ip4_dpo_node;

#endif // UPF_NAT_NAT_PRIVATE_H_
