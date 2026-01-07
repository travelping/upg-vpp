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

#include "upf/upf_stats.h"
#include "upf/nat/nat.h"
#include "upf/nat/nat_private.h"

#define UPF_DEBUG_ENABLE 0

always_inline u16
_upf_nat_icmp_flow_search_o2i_port (upf_nat_wk_t *unw,
                                    clib_bihash_kv_16_8_t *bh_kv_o2i,
                                    u16 block_ports_start,
                                    u16 pool_ports_per_block, u16 start_hash,
                                    u32 binding_id)
{
  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_icmp_flow_key_t *key_o2i =
    (upf_nat_icmp_flow_key_t *) &bh_kv_o2i->key;
  clib_bihash_kv_16_8_t val;

  u16 total_attempts =
    clib_max (pool_ports_per_block, UPF_NAT_PORT_SEARCH_ATTEMPTS);

  u16 port_in_block = start_hash % pool_ports_per_block;
  u16 nat_port = port_in_block + block_ports_start;

  for (u16 i = 0; i < total_attempts; i++)
    {
      key_o2i->icmp_id = nat_port;
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

always_inline bool
_upf_nat_icmp_flow_try_expire_delete (upf_nat_wk_t *unw, u32 thread_id,
                                      upf_nat_icmp_flow_t *nif, u32 now)
{
  upf_nat_main_t *unm = &upf_nat_main;

  if (nif->last_time + unm->icmp_flow_timeout <= now)
    {
      upf_nat_icmp_flow_delete (thread_id, nif - unw->icmp_flows);
      return true;
    }
  return false;
}

always_inline upf_nat_icmp_flow_t *
_upf_nat_icmp_flow_alloc (upf_nat_wk_t *unw, u32 thread_id, u32 now)
{
  upf_nat_icmp_flow_t *nif;
  if (pool_get_will_expand (unw->icmp_flows))
    {
      /*
        Here we try to expire flow to avoid reallocating memory.
        Try to expire current head flow due to timeout. Head is always "oldest"
        used flow in list.
      */
      nif = upf_nat_icmp_flows_lru_list_head (unw->icmp_flows,
                                              &unw->icmp_flow_lru);
      if (nif)
        _upf_nat_icmp_flow_try_expire_delete (unw, thread_id, nif, now);
    }

  pool_get (unw->icmp_flows, nif);
  return nif;
}

u32
upf_nat_icmp_flow_create (u32 thread_index, u32 binding_id, ip4_header_t *ip,
                          void *l4_hdr, u32 now,
                          upf_nat_icmp_flow_create_error_t *error)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (thread_index);

  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_wk_t *unw = vec_elt_at_index (unm->workers, thread_index);
  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, binding_id);

  ASSERT (ip->protocol == IP_PROTOCOL_ICMP);
  icmp46_header_t *icmp0 = l4_hdr;
  ASSERT (icmp0->type == ICMP4_echo_request);
  nat_icmp_echo_header_t *icmp_echo = (nat_icmp_echo_header_t *) (icmp0 + 1);
  u16 icmp_id = clib_net_to_host_u16 (icmp_echo->identifier);

  if (PREDICT_FALSE (binding->icmp_flows_count >=
                     unm->icmp_max_flows_per_binding))
    {
      /* try expire other flow of this binding before dropping out */
      upf_nat_icmp_flow_t *head = upf_nat_icmp_flows_binding_lru_list_head (
        unw->icmp_flows, &binding->icmp_echo_flows_lru_list);

      ASSERT (head);
      if (head)
        {
          if (!_upf_nat_icmp_flow_try_expire_delete (unw, thread_index, head,
                                                     now))
            {
              upf_debug ("fail: flows limit per binding hit");
              *error = UPF_NAT_ICMP_FLOW_CREATE_ERROR_LIMIT_PER_BINDING;
              return ~0;
            }
          else
            upf_debug ("been able to free flow to avoid limit");
        }
    }

  upf_nat_pool_t *nat_pool =
    pool_elt_at_index (unm->nat_pools, binding->nat_pool_id);

  clib_bihash_kv_16_8_t bh_kv_o2i;
  upf_nat_icmp_flow_key_t *key_o2i =
    (upf_nat_icmp_flow_key_t *) &bh_kv_o2i.key;
  *key_o2i = (upf_nat_icmp_flow_key_t){
    .in_addr = binding->external_addr,
    .out_addr = ip->dst_address,
    .nat_pool_id = binding->nat_pool_id,
  };

  // use original source port as "hash" for search
  u16 nat_port = _upf_nat_icmp_flow_search_o2i_port (
    unw, &bh_kv_o2i,
    nat_pool->port_min + binding->port_block_id * nat_pool->ports_per_block,
    nat_pool->ports_per_block, icmp_id, binding_id);

  if (nat_port == 0)
    {
      *error = UPF_NAT_ICMP_FLOW_CREATE_ERROR_OUT_OF_PORTS;
      upf_debug ("fail: can't find free port");
      return ~0;
    }

  upf_nat_icmp_flow_t *nif = _upf_nat_icmp_flow_alloc (unw, thread_index, now);
  u32 nif_id = nif - unw->icmp_flows;

  upf_debug ("creating key %U", format_upf_nat_icmp_flow_key, key_o2i);

  clib_bihash_kv_16_8_t bh_kv_i2o;
  upf_nat_icmp_flow_key_t *key_i2o =
    (upf_nat_icmp_flow_key_t *) &bh_kv_i2o.key;
  *key_i2o = (upf_nat_icmp_flow_key_t){
    .in_addr = ip->src_address,
    .out_addr = ip->dst_address,
    .icmp_id = icmp_id,
    .nat_pool_id = binding->nat_pool_id,
  };

  bh_kv_i2o.value = bh_kv_o2i.value =
    upf_nat_flow_bihash_value_pack (nif_id, thread_index);

  if (CLIB_ASSERT_ENABLE)
    {
      clib_bihash_kv_16_8_t val;
      /* should not exist */
      ASSERT (clib_bihash_search_16_8 (&unm->icmp_flows_by_i2o_key, &bh_kv_i2o,
                                       &val));
    }

  int rv0 =
    clib_bihash_add_del_16_8 (&unm->icmp_flows_by_i2o_key, &bh_kv_i2o, 1);
  ASSERT (rv0 == 0);

  int rv1 =
    clib_bihash_add_del_16_8 (&unm->icmp_flows_by_o2i_key, &bh_kv_o2i, 1);
  ASSERT (rv1 == 0);

  nif->in_addr = key_i2o->in_addr;
  nif->out_addr = key_i2o->out_addr;
  nif->nat_addr = binding->external_addr;
  nif->og_identifier = icmp_id;
  nif->nat_identifier = nat_port;
  nif->binding_id = binding_id;
  nif->last_time = now;

  upf_nat_icmp_flows_lru_list_anchor_init (nif);
  upf_nat_icmp_flows_lru_list_insert_tail (unw->icmp_flows,
                                           &unw->icmp_flow_lru, nif);

  upf_nat_icmp_flows_binding_lru_list_anchor_init (nif);
  upf_nat_icmp_flows_binding_lru_list_insert_tail (
    unw->icmp_flows, &binding->icmp_echo_flows_lru_list, nif);

  binding->icmp_flows_count += 1;
  vlib_increment_simple_counter (&upf_stats_main.wk.nat_pool_icmp_flows,
                                 thread_index, binding->nat_pool_id, 1);

  return nif_id;
}

void
upf_nat_icmp_flow_delete (u32 thread_index, u32 nat_flow_id)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (thread_index);

  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_wk_t *unw = vec_elt_at_index (unm->workers, thread_index);

  upf_nat_icmp_flow_t *nif = pool_elt_at_index (unw->icmp_flows, nat_flow_id);
  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, nif->binding_id);

  clib_bihash_kv_16_8_t bh_kv_o2i, bh_kv_i2o;
  upf_nat_icmp_flow_key_t *key_o2i =
    (upf_nat_icmp_flow_key_t *) &bh_kv_o2i.key;
  upf_nat_icmp_flow_key_t *key_i2o =
    (upf_nat_icmp_flow_key_t *) &bh_kv_i2o.key;

  *key_o2i = (upf_nat_icmp_flow_key_t){
    .in_addr = nif->nat_addr,
    .out_addr = nif->out_addr,
    .icmp_id = nif->nat_identifier,
    .nat_pool_id = binding->nat_pool_id,
  };
  *key_i2o = (upf_nat_icmp_flow_key_t){
    .in_addr = nif->in_addr,
    .out_addr = nif->out_addr,
    .icmp_id = nif->og_identifier,
    .nat_pool_id = binding->nat_pool_id,
  };

  int rv0 =
    clib_bihash_add_del_16_8 (&unm->icmp_flows_by_o2i_key, &bh_kv_o2i, 0);
  ASSERT (rv0 == 0);
  int rv1 =
    clib_bihash_add_del_16_8 (&unm->icmp_flows_by_i2o_key, &bh_kv_i2o, 0);
  ASSERT (rv1 == 0);

  upf_nat_icmp_flows_lru_list_remove (unw->icmp_flows, &unw->icmp_flow_lru,
                                      nif);
  upf_nat_icmp_flows_binding_lru_list_remove (
    unw->icmp_flows, &binding->icmp_echo_flows_lru_list, nif);

  pool_put (unw->icmp_flows, nif);

  binding->icmp_flows_count -= 1;
  vlib_decrement_simple_counter (&upf_stats_main.wk.nat_pool_icmp_flows,
                                 thread_index, binding->nat_pool_id, 1);
}
