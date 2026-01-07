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

#ifndef UPF_NAT_NAT_H_
#define UPF_NAT_NAT_H_

#include <vlib/vlib.h>
#include <vlib/stats/stats.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/fib/fib_source.h>
#include <vnet/ip/ip4_packet.h>

#include "upf/utils/upf_timer.h"
#include "upf/utils/llist.h"
#include "upf/utils/worker_pool.h"
#include "upf/pfcp/upf_nwi.h"

UPF_LLIST_TEMPLATE_TYPES (upf_nat_block_free_list);
UPF_LLIST_TEMPLATE_TYPES (upf_nat_flows_binding_list);
UPF_LLIST_TEMPLATE_TYPES (upf_nat_icmp_flows_binding_lru_list);
UPF_LLIST_TEMPLATE_TYPES (upf_nat_icmp_flows_lru_list);

typedef struct
{
  u32 binding_id; // invalid when in timeout state
  // Use vec+llist instead of pool to guarantee no vector reallocations for
  // multithreading and to have control over order of allocations for security
  upf_nat_block_free_list_anchor_t free_anchor;
  upf_timer_id_t timeout;
} upf_nat_block_t;

typedef struct
{
  ip4_address_t addr_start;
  u32 addr_count;

  u32 addr_start_hostorder;

  // usage pool of references to nat bindings
  upf_nat_block_t *vec_blocks;

  u16 blocks_per_addr;
  u16 ports_per_block;
  u16 port_min;

  u16 nwif_id;

  u32 used_blocks;
  u32 timeout_blocks;

  // list of free blocks sorted so oldest blocks are in front
  upf_nat_block_free_list_t free_blocks_list;

  u8 *name; // vec name
} upf_nat_pool_t;

// created and removed by main thread
// read only for main thread
// read/write by worker thread
typedef struct
{
  u32 session_id;
  ip4_address_t external_addr;
  u16 nat_pool_id;
  u16 port_block_id;    // ports block index, local to endpoint
  u32 pool_endpoint_id; // ip endpoint index, local to pool

  // worker stuff
  upf_nat_icmp_flows_binding_lru_list_t icmp_echo_flows_lru_list;
  upf_nat_flows_binding_list_t nat_flows_list;
  u32 icmp_flows_count : 30;
  u32 want_netcap : 1;
} upf_nat_binding_t;

typedef struct
{
  struct __clib_packed
  {
    ip4_address_t src_addr;
    ip4_address_t dst_addr;
    u16 src_port;
  } key_o2i;

  u16 nat_port;
  u8 proto;

  u32 binding_id;
  u32 upf_flow_id;

  upf_nat_flows_binding_list_anchor_t binding_anchor;
} upf_nat_flow_t;

typedef struct
{
  ip4_address_t in_addr;  // inbound, original ue address
  ip4_address_t out_addr; // outbound, remote "internet" address
  ip4_address_t nat_addr; // nat address from pool
  u16 og_identifier;
  u16 nat_identifier;

  u32 binding_id;

  u32 last_time;

  upf_nat_icmp_flows_binding_lru_list_anchor_t binding_lru_anchor;
  upf_nat_icmp_flows_lru_list_anchor_t lru_anchor;
} upf_nat_icmp_flow_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  upf_nat_flow_t *flows;
  upf_nat_icmp_flow_t *icmp_flows;

  /* head of this list is always first candidate for removal */
  upf_nat_icmp_flows_lru_list_t icmp_flow_lru;
} upf_nat_wk_t;

typedef struct
{
  // vector of thread assigned workers
  upf_nat_wk_t *workers;

  // allocated by main thread, read-write by worker
  // for this uses upf_worker_pool container
  upf_nat_binding_t *bindings;

  /* upf_nat_flow_key_t to nat flow index */
  clib_bihash_16_8_t flows_by_o2i_key;

  // pool of nat pools
  upf_nat_pool_t *nat_pools;

  /* for flows which can't reuse upf flows (ICMP) */
  clib_bihash_16_8_t icmp_flows_by_o2i_key;
  clib_bihash_16_8_t icmp_flows_by_i2o_key;

  uword *nat_pool_index_by_name;

  u32 icmp_flow_timeout; // in seconds

  // Timeout for pool block to be allocatable again.
  // Adds security by not allowing passing packets to flows from previous
  // bindings for this timeout.
  u32 binding_block_timeout; // in seconds

  // useful for network scanners overload protection
  u32 icmp_max_flows_per_binding;

  fib_source_t fib_src;

  u32 fq_nat_dpo_handoff_index;

  bool initialized;
} upf_nat_main_t;

UPF_LLIST_TEMPLATE_DEFINITIONS (upf_nat_block_free_list, upf_nat_block_t,
                                free_anchor);

// use for verification without allocation
bool upf_nat_pool_can_allocate (u32 nat_pool_id);
// actuall allocation and removal of control plane resources
u32 upf_nat_binding_create (u16 thread_id, u32 nat_pool_id, u32 session_id);
void upf_nat_binding_remove_flows (u16 thread_id, u32 binding_id);
void upf_nat_binding_delete (u32 binding_id);
void upf_nat_binding_set_netcap (u32 binding_id, bool enabled);

typedef struct
{
  ip4_address_t ext_addr;
  u16 port_min;
  u16 port_max;
  u16 nat_pool_id;
} upf_nat_binding_info_t;
void upf_nat_binding_get_information (u32 binding_id,
                                      upf_nat_binding_info_t *result);

vnet_api_error_t upf_nat_pool_add_del (upf_nwi_name_t nwi_name,
                                       upf_interface_type_t intf,
                                       ip4_address_t start_addr,
                                       ip4_address_t end_addr, u8 *name,
                                       u16 port_block_size, u16 min_port,
                                       u16 max_port, u8 is_add);
upf_nat_pool_t *upf_nat_pool_get_by_name (u8 *name);

u32 upf_nat_flow_create (u32 thread_id, u32 nat_binding_id, ip4_header_t *ip,
                         void *l4_hdr, u32 upf_flow_id);
void upf_nat_flow_delete (u32 thread_id, u32 nat_flow_id);

format_function_t format_upf_nat_pool;
format_function_t format_upf_nat_binding;
format_function_t format_upf_nat_flow;
format_function_t format_upf_nat_icmp_flow;
format_function_t format_upf_nat_flow_key;
format_function_t format_upf_nat_flow_kvp;
format_function_t format_upf_nat_icmp_flow_key;
format_function_t format_upf_nat_icmp_flow_kvp;

// From TR-459.2 Issue 1
// > Port 0 to 1,023 are well known IANA registered ports which leaves ports
// > only 1,024 to 65,535 available for NAT
#define UPF_NAT_MIN_PORT 1024

// How much attempts to look for ports
#define UPF_NAT_PORT_SEARCH_ATTEMPTS 16

#define UPF_NAT_DEFAULT_ICMP_FLOWS_TIMEOUT 20

#define UPF_NAT_DEFAULT_MAX_ICMP_FLOWS_PER_BINDING 64

#define UPF_NAT_DEFAULT_BINDING_BLOCK_TIMEOUT 30

extern upf_nat_main_t upf_nat_main;

#endif // UPF_NAT_NAT_H_
