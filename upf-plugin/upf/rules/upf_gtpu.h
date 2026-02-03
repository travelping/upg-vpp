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

#ifndef UPF_RULES_UPF_GTPU_H_
#define UPF_RULES_UPF_GTPU_H_

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_path_list.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_24_8.h>

#include "upf/utils/common.h"
#include "upf/pfcp/upf_nwi.h"

typedef struct
{
  // GTPU endpoints guaranted to not share single ip4 or ip6 address. So TEID
  // management can be attached to (ip4,ip6) pair, instead of separated ip4 and
  // ip6 management.
  ip4_address_t ip4;
  ip6_address_t ip6;
  u16 nwi_id;

  u8 has_ip4 : 1;
  u8 has_ip6 : 1;

  // optional
  upf_interface_type_t intf;

  // transmit src port hash clamping
  u16 src_port_start;
  u16 src_port_len;
  u16 src_port_len_mask;

  // TODO: ideally we should track fibs of ip addresses, since we may have same
  // addresses in different fibs. But such configuration are very unlikely, so
  // we ignore them
} upf_gtpu_endpoint_t;

typedef union __key_packed
{
  struct __key_packed
  {
    ip4_address_t ep_ip4;
    u32 teid;
    u8 _pad[0];
  };
  u64 as_u64;
} upf_gtpu4_tunnel_key_t;
STATIC_ASSERT_SIZEOF (upf_gtpu4_tunnel_key_t, 8);

typedef union __key_packed
{
  struct __key_packed
  {
    ip6_address_t ep_ip6;
    u32 teid;
    u8 _pad[4];
  };
  u64 as_u64[3];
} upf_gtpu6_tunnel_key_t;
STATIC_ASSERT_SIZEOF (upf_gtpu6_tunnel_key_t, 24);

typedef union
{
  struct
  {
    u64 session_id : 24;
    u64 rules_f_teid_id : 8;
    u64 thread_id : 12;
    u64 _pad : 3;
    u64 is_active : 1;
    u64 session_generation : 16;
  };
  u64 as_u64;
} gtpu_tunnel_lookup_value_t;
STATIC_ASSERT_SIZEOF (gtpu_tunnel_lookup_value_t, 8);

always_inline __clib_unused void
gtpu_tunnel_lookup_value_unpack (u64 value, u32 *session_id,
                                 u16 *session_generation, u16 *thread_id,
                                 u8 *rules_f_teid_id, bool *is_active)
{
  gtpu_tunnel_lookup_value_t v = { .as_u64 = value };
  *session_id = v.session_id;
  *session_generation = v.session_generation;
  *thread_id = v.thread_id;
  *rules_f_teid_id = v.rules_f_teid_id;
  *is_active = v.is_active;
}

always_inline __clib_unused u64
gtpu_tunnel_lookup_value_pack (u32 session_id, u16 session_generation,
                               u16 thread_id, u8 rules_f_teid_id,
                               bool is_active)
{
  gtpu_tunnel_lookup_value_t v = {
    .session_id = session_id,
    .session_generation = session_generation,
    .thread_id = thread_id,
    .is_active = is_active,
    .rules_f_teid_id = rules_f_teid_id,
  };
  return v.as_u64;
}

typedef struct
{
  u32 teid; // net order
  ip46_address_t addr;
  u16 port; // net order
} gtpu_error_ind_t;

typedef struct
{
  upf_gtpu_endpoint_t *endpoints;

  /* lookup tunnel by TEID */
  clib_bihash_8_8_t tunnel_by_fteid4;
  clib_bihash_24_8_t tunnel_by_fteid6;

  u32 fq_gtpu4_handoff_index;
  u32 fq_gtpu6_handoff_index;
  u32 fq_gtpu_err_ind_handoff_index;
} upf_gtpu_main_t;

int upf_gtpu_endpoint_add_del (ip4_address_t *ip4, ip6_address_t *ip6,
                               upf_nwi_name_t nwi_name,
                               upf_interface_type_t intf, u32 teid, u32 mask,
                               u8 add, u16 min_port, u16 max_port);

void upf_gtpu_endpoint_tunnel_create (upf_gtpu_endpoint_t *ep, u32 teid,
                                      u32 session_id, u16 session_generation,
                                      u16 thread_id, u8 rules_f_teid_lid);
void upf_gtpu_endpoint_tunnel_activate (upf_gtpu_endpoint_t *ep, u32 teid,
                                        u32 session_id, u16 session_generation,
                                        u16 thread_id, u8 rules_f_teid_lid);
void upf_gtpu_endpoint_tunnel_delete (upf_gtpu_endpoint_t *ep, u32 teid);

// return session id of used teid
u32 upf_gtpu_tunnel_get_session_by_teid (upf_gtpu_endpoint_t *ep, u32 teid);
// return teid
u32 upf_gtpu_tunnel_search_free_teid (upf_gtpu_endpoint_t *ep);

void upf_gtpu_send_end_marker (vlib_main_t *vm, upf_gtpu_endpoint_t *src_ep,
                               upf_interface_t *nwif, ip4_address_t *dst_addr4,
                               ip6_address_t *dst_addr6, u32 teid);

format_function_t format_gtpu_endpoint;

extern upf_gtpu_main_t upf_gtpu_main;

extern vlib_node_registration_t upf_gtpu4_input_node;
extern vlib_node_registration_t upf_gtpu6_input_node;
extern vlib_node_registration_t upf_gtpu_error_ind_node;

// extern vlib_node_registration_t upf_gtpu4_input_handoff_node;
// extern vlib_node_registration_t upf_gtpu6_input_handoff_node;
// extern vlib_node_registration_t upf_gtpu_error_ind_handoff_node;

// extern vlib_node_registration_t upf_gtp_encap4_node;
// extern vlib_node_registration_t upf_gtp_encap6_node;

__clib_unused static bool
upf_gtpu_tunnel4_lookup (u32 teid, ip4_address_t addr, u32 *session_index,
                         u16 *session_generation, u16 *thread_index,
                         u8 *rules_f_teid_id, bool *is_active)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  clib_bihash_kv_8_8_t bh_kv = {}, bh_result;
  upf_gtpu4_tunnel_key_t *key = (upf_gtpu4_tunnel_key_t *) &bh_kv.key;
  key->ep_ip4 = addr;
  key->teid = teid;

  if (clib_bihash_search_8_8 (&ugm->tunnel_by_fteid4, &bh_kv, &bh_result))
    return false;

  gtpu_tunnel_lookup_value_unpack (bh_result.value, session_index,
                                   session_generation, thread_index,
                                   rules_f_teid_id, is_active);
  return true;
}

__clib_unused static bool
upf_gtpu_tunnel6_lookup (u32 teid, ip6_address_t addr, u32 *session_id,
                         u16 *session_generation, u16 *thread_index,
                         u8 *rules_f_teid_id, bool *is_active)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  clib_bihash_kv_24_8_t bh_kv = {}, bh_result;
  upf_gtpu6_tunnel_key_t *key = (upf_gtpu6_tunnel_key_t *) &bh_kv.key;
  key->ep_ip6 = addr;
  key->teid = teid;

  if (clib_bihash_search_24_8 (&ugm->tunnel_by_fteid6, &bh_kv, &bh_result))
    return false;

  gtpu_tunnel_lookup_value_unpack (bh_result.value, session_id,
                                   session_generation, thread_index,
                                   rules_f_teid_id, is_active);
  return true;
}

#endif // UPF_RULES_UPF_GTPU_H_
