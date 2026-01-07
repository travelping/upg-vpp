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

#ifndef UPF_NAT_NAT_NODE_INLINES_H_
#define UPF_NAT_NAT_NODE_INLINES_H_

#include "upf/core/upf_types.h"
#include "upf/nat/nat.h"
#include "upf/nat/nat_private.h"

#ifndef upf_debug
#define upf_debug(...) {};
#endif

always_inline __clib_unused bool
_nat_icmp_echo_lookup (upf_nat_wk_t *unw, u32 thread_index, ip4_header_t *ip0,
                       icmp46_header_t *icmp0, u32 nat_pool_id, bool i2o,
                       upf_dir_op_t dir_op, u32 *icmp_flow_id,
                       u16 *lookup_thread_id)
{
  upf_nat_main_t *unm = &upf_nat_main;
  nat_icmp_echo_header_t *echo = (nat_icmp_echo_header_t *) (icmp0 + 1);
  clib_bihash_kv_16_8_t bh_kv = {}, bh_result;

  upf_nat_icmp_flow_key_t *key = (upf_nat_icmp_flow_key_t *) &bh_kv.key;

  *key = (upf_nat_icmp_flow_key_t){
    .icmp_id = clib_net_to_host_u16 (echo->identifier),
    .nat_pool_id = nat_pool_id,
  };
  if (i2o ^ dir_op)
    {
      key->in_addr = ip0->src_address;
      key->out_addr = ip0->dst_address;
    }
  else
    {
      key->in_addr = ip0->dst_address;
      key->out_addr = ip0->src_address;
    }

  upf_debug ("searching key %U", format_upf_nat_icmp_flow_kvp, &bh_kv);

  clib_bihash_16_8_t *h =
    i2o ? &unm->icmp_flows_by_i2o_key : &unm->icmp_flows_by_o2i_key;
  if (clib_bihash_search_16_8 (h, &bh_kv, &bh_result))
    return false;

  upf_nat_flow_bihash_value_unpack (bh_result.value, icmp_flow_id,
                                    lookup_thread_id);
  return true;
}

always_inline __clib_unused bool
_nat_tcpudp_lookup_o2i (upf_nat_wk_t *unw, ip4_header_t *ip0, void *l4_hdr0,
                        u32 nat_pool_id, upf_dir_op_t dir_op, u32 *nat_flow_id,
                        u16 *lookup_thread_id)
{
  upf_nat_main_t *unm = &upf_nat_main;

  nat_tcp_udp_header_t *h = l4_hdr0;
  u16 src_port = clib_net_to_host_u16 (h->src_port);
  u16 dst_port = clib_net_to_host_u16 (h->dst_port);

  clib_bihash_kv_16_8_t bh_kv_o2i = {}, bh_result;
  upf_nat_flow_key_t *key_o2i = (upf_nat_flow_key_t *) &bh_kv_o2i.key;
  if (dir_op == UPF_DIR_OP_SAME)
    {
      key_o2i->src_addr = ip0->src_address;
      key_o2i->dst_addr = ip0->dst_address;
      key_o2i->src_port = src_port;
      key_o2i->dst_port = dst_port;
    }
  else
    {
      key_o2i->src_addr = ip0->dst_address;
      key_o2i->dst_addr = ip0->src_address;
      key_o2i->src_port = dst_port;
      key_o2i->dst_port = src_port;
    }
  key_o2i->proto = ip0->protocol;
  key_o2i->nat_pool_id = nat_pool_id;

  upf_debug ("searching key %U", format_upf_nat_flow_key, key_o2i);

  if (clib_bihash_search_16_8 (&unm->flows_by_o2i_key, &bh_kv_o2i, &bh_result))
    return false;

  upf_nat_flow_bihash_value_unpack (bh_result.value, nat_flow_id,
                                    lookup_thread_id);
  return true;
}

// refresh LRU lists tails
always_inline __clib_unused void
_nat_icmp_echo_refresh (upf_nat_wk_t *unw, upf_nat_binding_t *binding,
                        upf_nat_icmp_flow_t *nif, u32 now)
{
  nif->last_time = now;

  upf_nat_icmp_flows_lru_list_remove (unw->icmp_flows, &unw->icmp_flow_lru,
                                      nif);
  upf_nat_icmp_flows_binding_lru_list_remove (
    unw->icmp_flows, &binding->icmp_echo_flows_lru_list, nif);

  upf_nat_icmp_flows_lru_list_insert_tail (unw->icmp_flows,
                                           &unw->icmp_flow_lru, nif);
  upf_nat_icmp_flows_binding_lru_list_insert_tail (
    unw->icmp_flows, &binding->icmp_echo_flows_lru_list, nif);
}

always_inline __clib_unused void
_nat_icmp_echo_rewrite (ip4_header_t *ip0, icmp46_header_t *icmp0,
                        ip4_address_t new_addr0, u16 new_identifier,
                        upf_el_t el, ip_csum_t *icmp_error_csum)
{
  nat_icmp_echo_header_t *echo = (nat_icmp_echo_header_t *) (icmp0 + 1);

  ip4_address_t old_addr0;
  if (el == UPF_EL_UL_SRC)
    {
      old_addr0 = ip0->src_address;
      ip0->src_address = new_addr0;
    }
  else
    {
      old_addr0 = ip0->dst_address;
      ip0->dst_address = new_addr0;
    }

  u16 old_identifier = echo->identifier;
  echo->identifier = new_identifier;

  u16 old_ip_csum = ip0->checksum;
  u16 old_icmp_csum = icmp0->checksum;

  /* restore csum */
  ip_csum_t sum_ip = ip0->checksum;
  // changed member doesn't matter here because of align
  sum_ip = ip_csum_update (sum_ip, old_addr0.as_u32, new_addr0.as_u32,
                           ip4_header_t, src_address /* changed member */);
  ip0->checksum = ip_csum_fold (sum_ip);

  ip_csum_t sum_icmp = icmp0->checksum;
  sum_icmp =
    ip_csum_update (sum_icmp, old_identifier, new_identifier,
                    nat_icmp_echo_header_t, identifier /* changed member */);
  icmp0->checksum = ip_csum_fold (sum_icmp);

  if (icmp_error_csum)
    {
      ip_csum_t c = *icmp_error_csum;
      c = ip_csum_update_inline (c, old_addr0.as_u32, new_addr0.as_u32, 0, 0);
      c = ip_csum_update_inline (c, old_identifier, new_identifier, 0, 0);
      c = ip_csum_update_inline (c, old_ip_csum, ip0->checksum, 0, 0);
      c = ip_csum_update_inline (c, old_icmp_csum, icmp0->checksum, 0, 0);
      *icmp_error_csum = c;
    }
}

always_inline __clib_unused void
_nat_tcpudp_rewrite (ip4_header_t *ip0, void *l4_hdr0, ip4_address_t new_addr0,
                     u16 new_port_net, upf_el_t el, ip_csum_t *icmp_error_csum)
{
  nat_tcp_udp_header_t *h = l4_hdr0;
  ip4_address_t old_addr0;
  u16 old_port;

  if (el == UPF_EL_UL_SRC)
    {
      old_addr0 = ip0->src_address;
      ip0->src_address = new_addr0;

      old_port = h->src_port;
      h->src_port = new_port_net;
    }
  else
    {
      old_addr0 = ip0->dst_address;
      ip0->dst_address = new_addr0;

      old_port = h->dst_port;
      h->dst_port = new_port_net;
    }

  u16 old_ip_csum = ip0->checksum;

  ip_csum_t sum_ip = ip0->checksum;
  sum_ip = ip_csum_update (sum_ip, old_addr0.as_u32, new_addr0.as_u32,
                           ip4_header_t, src_address /* changed member */);
  ip0->checksum = ip_csum_fold (sum_ip);

  if (ip0->protocol == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp0 = l4_hdr0;

      u16 old_tcp_sum = tcp0->checksum;
      ip_csum_t sum_tcp = tcp0->checksum;
      sum_tcp =
        ip_csum_update (sum_tcp, old_addr0.as_u32, new_addr0.as_u32,
                        ip4_header_t, src_address /* changed member */);
      sum_tcp = ip_csum_update_inline (sum_tcp, old_port, new_port_net, 0, 0);
      tcp0->checksum = ip_csum_fold (sum_tcp);

      if (icmp_error_csum)
        {
          *icmp_error_csum = ip_csum_update_inline (
            *icmp_error_csum, old_tcp_sum, tcp0->checksum, 0, 0);
        }
    }
  else
    {
      ASSERT (ip0->protocol == IP_PROTOCOL_UDP);
      udp_header_t *udp0 = l4_hdr0;

      if (PREDICT_FALSE (udp0->checksum))
        {
          u16 old_udp_sum = udp0->checksum;
          ip_csum_t sum_udp = udp0->checksum;
          sum_udp =
            ip_csum_update (sum_udp, old_addr0.as_u32, new_addr0.as_u32,
                            ip4_header_t, src_address /* changed member */);
          sum_udp =
            ip_csum_update_inline (sum_udp, old_port, new_port_net, 0, 0);
          udp0->checksum = ip_csum_fold (sum_udp);

          if (icmp_error_csum)
            {
              *icmp_error_csum = ip_csum_update_inline (
                *icmp_error_csum, old_udp_sum, udp0->checksum, 0, 0);
            }
        }
    }

  if (icmp_error_csum)
    {
      ip_csum_t c = *icmp_error_csum;
      c = ip_csum_update_inline (c, old_addr0.as_u32, new_addr0.as_u32, 0, 0);
      c = ip_csum_update_inline (c, old_port, new_port_net, 0, 0);
      c = ip_csum_update_inline (c, old_ip_csum, ip0->checksum, 0, 0);
      *icmp_error_csum = c;
    }
}

#endif // UPF_NAT_NAT_NODE_INLINES_H_
