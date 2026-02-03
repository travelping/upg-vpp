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
#include "upf/utils/worker_pool.h"

u8 *
format_upf_nat_pool (u8 *s, va_list *args)
{
  upf_nat_pool_t *v = va_arg (*args, upf_nat_pool_t *);
  upf_nat_main_t *unm = &upf_nat_main;

  ip4_address_t addr_end;
  addr_end.as_u32 =
    clib_host_to_net_u32 (v->addr_start_hostorder + v->addr_count - 1);
  u16 ports_per_endpoint = v->ports_per_block * v->blocks_per_addr;

  u32 total_blocks = (u32) v->blocks_per_addr * (u32) v->addr_count;

  ASSERT (total_blocks == vec_len (v->vec_blocks));

  s = format (s,
              "id %d name \'%v\' addr %U-%U ports {size %d in %d-%d} blocks "
              "usage %d/%d (timeout %d) nwif id %d",
              v - unm->nat_pools, v->name, format_ip4_address, &v->addr_start,
              format_ip4_address, &addr_end, v->ports_per_block, v->port_min,
              v->port_min + ports_per_endpoint - 1, v->used_blocks,
              total_blocks, v->timeout_blocks, v->nwif_id);
  return s;
}

u8 *
format_upf_nat_binding (u8 *s, va_list *args)
{
  upf_nat_binding_t *v = va_arg (*args, upf_nat_binding_t *);
  upf_nat_main_t *unm = &upf_nat_main;

  upf_nat_pool_t *np = pool_elt_at_index (unm->nat_pools, v->nat_pool_id);
  u16 port_start = np->port_min + np->ports_per_block * v->port_block_id;
  u16 port_end = port_start + np->ports_per_block - 1;

  s = format (
    s,
    "id %d pool_id %d external %U (id %d) ports %d-%d (port_block_id %d) "
    "cp_session id %d thread_id %d",
    v - unm->bindings, v->nat_pool_id, format_ip4_address, &v->external_addr,
    v->pool_endpoint_id, port_start, port_end, v->port_block_id, v->session_id,
    upf_worker_pool_elt_thread_id (unm->bindings, v - unm->bindings));

  return s;
}

u8 *
format_upf_nat_flow (u8 *s, va_list *args)
{
  upf_nat_flow_t *f = va_arg (*args, upf_nat_flow_t *);
  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, f->binding_id);

  s = format (s,
              "o2i {in %U:%d out %U:%d} proto %d bind {id %d sid "
              "%d) upf_flow %d",
              format_ip4_address, &f->key_o2i.dst_addr, f->nat_port,
              format_ip4_address, &f->key_o2i.src_addr, f->key_o2i.src_port,
              f->proto, f->binding_id, binding->session_id, f->upf_flow_id);

  return s;
}

u8 *
format_upf_nat_icmp_flow (u8 *s, va_list *args)
{
  upf_nat_icmp_flow_t *f = va_arg (*args, upf_nat_icmp_flow_t *);
  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, f->binding_id);

  s = format (s,
              "{in %U out %U nat %U} icmp_id {og %d nat %d} bind {id %d sid "
              "%d} last time %d",
              format_ip4_address, &f->in_addr, format_ip4_address,
              &f->out_addr, format_ip4_address, &f->nat_addr, f->og_identifier,
              f->nat_identifier, f->binding_id, binding->session_id,
              f->last_time);
  return s;
}

u8 *
format_upf_nat_flow_key (u8 *s, va_list *args)
{
  upf_nat_flow_key_t *k = va_arg (*args, upf_nat_flow_key_t *);
  s = format (s, "src %U:%d dst %U:%d proto %d pool id %d", format_ip4_address,
              &k->src_addr, k->src_port, format_ip4_address, &k->dst_addr,
              k->dst_port, k->proto, k->nat_pool_id);
  return s;
}

u8 *
format_upf_nat_icmp_flow_key (u8 *s, va_list *args)
{
  upf_nat_icmp_flow_key_t *k = va_arg (*args, upf_nat_icmp_flow_key_t *);
  s = format (s, "in %U out %U icmp id %d pool id %d", format_ip4_address,
              &k->in_addr, format_ip4_address, &k->out_addr, k->icmp_id,
              k->nat_pool_id);
  return s;
}

u8 *
format_upf_nat_flow_kvp (u8 *s, va_list *args)
{
  clib_bihash_kv_16_8_t *v = va_arg (*args, clib_bihash_kv_16_8_t *);

  u32 flow_id;
  u16 thread_id;
  upf_nat_flow_bihash_value_unpack (v->value, &flow_id, &thread_id);

  s = format (s, "flow key {%U} thread %d flow id %d", format_upf_nat_flow_key,
              &v->key, thread_id, flow_id);
  return s;
}

u8 *
format_upf_nat_icmp_flow_kvp (u8 *s, va_list *args)
{
  clib_bihash_kv_16_8_t *v = va_arg (*args, clib_bihash_kv_16_8_t *);

  u32 flow_id;
  u16 thread_id;
  upf_nat_flow_bihash_value_unpack (v->value, &flow_id, &thread_id);

  s = format (s, "icmp flow key {%U} thread %d flow id %d",
              format_upf_nat_icmp_flow_key, &v->key, thread_id, flow_id);
  return s;
}
