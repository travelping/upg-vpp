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

#include "upf/nat/nat.h"
#include "upf/nat/nat_private.h"

#include "upf/upf_stats.h"

#define UPF_DEBUG_ENABLE 0

always_inline u16
_upf_nat_flow_search_o2i_port (upf_nat_wk_t *unw,
                               clib_bihash_kv_16_8_t *bh_kv_o2i,
                               u16 block_ports_start, u16 pool_ports_per_block,
                               u16 start_hash, u32 binding_id)
{
  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_flow_key_t *key_o2i = (upf_nat_flow_key_t *) &bh_kv_o2i->key;
  clib_bihash_kv_16_8_t val;

  u16 total_attempts =
    clib_max (pool_ports_per_block, UPF_NAT_PORT_SEARCH_ATTEMPTS);

  u16 port_in_block = start_hash % pool_ports_per_block;
  u16 nat_port = port_in_block + block_ports_start;

  for (u16 i = 0; i < total_attempts; i++)
    {
      key_o2i->dst_port = nat_port;
      if (clib_bihash_search_16_8 (&unm->flows_by_o2i_key, bh_kv_o2i, &val))
        return nat_port;

      // Check that we are not colliding bindings in search
      if (CLIB_ASSERT_ENABLE)
        {
          u32 check_flow_id;
          u16 check_thread_index;
          upf_nat_flow_bihash_value_unpack (val.value, &check_flow_id,
                                            &check_thread_index);
          ASSERT (check_thread_index == os_get_thread_index ());
          upf_nat_flow_t *check_flow =
            pool_elt_at_index (unw->flows, check_flow_id);

          ASSERT (!pool_is_free_index (unw->flows, check_flow_id));
          ASSERT (check_flow->binding_id == binding_id);
        }

      port_in_block = (port_in_block + 1) % pool_ports_per_block;
      nat_port = port_in_block + block_ports_start;
    }

  upf_debug ("out of ports");
  return 0;
}

u32
upf_nat_flow_create (u32 thread_index, u32 binding_id, ip4_header_t *ip,
                     void *l4_hdr, u32 upf_flow_id)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (thread_index);

  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_wk_t *unw = vec_elt_at_index (unm->workers, thread_index);
  ASSERT (is_valid_id (upf_flow_id));

  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, binding_id);

  ASSERT (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP);
  nat_tcp_udp_header_t *tcpudph = l4_hdr;
  u16 i2o_src_port = clib_net_to_host_u16 (tcpudph->src_port);
  u16 i2o_dst_port = clib_net_to_host_u16 (tcpudph->dst_port);

  /* now we search for ports */
  upf_nat_pool_t *nat_pool =
    pool_elt_at_index (unm->nat_pools, binding->nat_pool_id);

  /* we search using key in reverse direction, so src = dst, and dst = nat
   * dynamic endpoint */
  clib_bihash_kv_16_8_t bh_kv_o2i = {};
  upf_nat_flow_key_t *key_o2i = (upf_nat_flow_key_t *) &bh_kv_o2i.key;
  key_o2i->src_addr = ip->dst_address;
  key_o2i->dst_addr = binding->external_addr;
  key_o2i->src_port = i2o_dst_port;
  key_o2i->proto = ip->protocol;
  key_o2i->nat_pool_id = binding->nat_pool_id;

  // use original source port as "hash" for search
  u16 nat_port = _upf_nat_flow_search_o2i_port (
    unw, &bh_kv_o2i,
    nat_pool->port_min + binding->port_block_id * nat_pool->ports_per_block,
    nat_pool->ports_per_block, i2o_src_port, binding_id);

  if (nat_port == 0)
    return ~0;

  upf_nat_flow_t *nf;
  pool_get (unw->flows, nf);
  u32 nat_flow_id = nf - unw->flows;

  upf_debug ("creating key %U fid %u bid %u", format_upf_nat_flow_key, key_o2i,
             nat_flow_id, binding_id);

  bh_kv_o2i.value = upf_nat_flow_bihash_value_pack (nat_flow_id, thread_index);
  int rv = clib_bihash_add_del_16_8 (&unm->flows_by_o2i_key, &bh_kv_o2i, 1);
  ASSERT (rv == 0);

  nf->key_o2i.src_addr = key_o2i->src_addr;
  nf->key_o2i.dst_addr = key_o2i->dst_addr;
  nf->key_o2i.src_port = key_o2i->src_port;
  nf->nat_port = nat_port;
  nf->proto = key_o2i->proto;
  nf->binding_id = binding_id;
  nf->upf_flow_id = upf_flow_id;

  upf_nat_flows_binding_list_anchor_init (nf);
  upf_nat_flows_binding_list_insert_tail (unw->flows, &binding->nat_flows_list,
                                          nf);

  vlib_increment_simple_counter (&upf_stats_main.wk.nat_pool_flows,
                                 thread_index, binding->nat_pool_id, 1);

  return nat_flow_id;
}

void
upf_nat_flow_delete (u32 thread_index, u32 nat_flow_id)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (thread_index);

  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_wk_t *unw = vec_elt_at_index (unm->workers, thread_index);

  upf_nat_flow_t *nf = pool_elt_at_index (unw->flows, nat_flow_id);
  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, nf->binding_id);

  upf_nat_flows_binding_list_remove (unw->flows, &binding->nat_flows_list, nf);

  clib_bihash_kv_16_8_t bh_kv_o2i = {};
  upf_nat_flow_key_t *key_o2i = (upf_nat_flow_key_t *) &bh_kv_o2i.key;
  key_o2i->src_addr = nf->key_o2i.src_addr;
  key_o2i->dst_addr = nf->key_o2i.dst_addr;
  key_o2i->src_port = nf->key_o2i.src_port;
  key_o2i->dst_port = nf->nat_port;
  key_o2i->proto = nf->proto;
  key_o2i->nat_pool_id = binding->nat_pool_id;

  upf_debug ("removing key %U fid %u bid %d", format_upf_nat_flow_key, key_o2i,
             nat_flow_id, nf->binding_id);

  int rv = clib_bihash_add_del_16_8 (&unm->flows_by_o2i_key, &bh_kv_o2i, 0);
  ASSERT (rv == 0);

  pool_put (unw->flows, nf);

  vlib_decrement_simple_counter (&upf_stats_main.wk.nat_pool_flows,
                                 thread_index, binding->nat_pool_id, 1);
}
