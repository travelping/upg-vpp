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

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vlib/stats/stats.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_types.h>

#include "upf/nat/nat.h"
#include "upf/nat/nat_private.h"
#include "upf/nat/nat_dpo.h"
#include "upf/utils/worker_pool.h"

#include "upf/upf.h"
#include "upf/upf_stats.h"
#include "upf/utils/upf_mt.h"

#define UPF_DEBUG_ENABLE 0

static void _upf_nat_init_late ();

upf_nat_main_t upf_nat_main;

bool
upf_nat_pool_can_allocate (u32 nat_pool_id)
{
  ASSERT_THREAD_MAIN ();
  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_pool_t *nat_pool = pool_elt_at_index (unm->nat_pools, nat_pool_id);

  return !upf_nat_block_free_list_is_empty (&nat_pool->free_blocks_list);
}

u32
upf_nat_binding_create (u16 thread_id, u32 nat_pool_id, u32 session_id)
{
  ASSERT_THREAD_MAIN ();
  upf_nat_main_t *unm = &upf_nat_main;
  vlib_main_t *vm = vlib_get_main ();

  ASSERT (unm->initialized);

  upf_nat_pool_t *nat_pool = pool_elt_at_index (unm->nat_pools, nat_pool_id);

  upf_nat_block_t *new_block = upf_nat_block_free_list_head (
    nat_pool->vec_blocks, &nat_pool->free_blocks_list);
  if (new_block == NULL)
    {
      upf_debug ("fail: no free blocks");
      return ~0;
    }

  upf_nat_block_free_list_remove (nat_pool->vec_blocks,
                                  &nat_pool->free_blocks_list, new_block);

  u32 new_block_id = new_block - nat_pool->vec_blocks;
  u32 endpoint_id, port_block_id;
  upf_nat_block_id_to_components (new_block_id, nat_pool->blocks_per_addr,
                                  &endpoint_id, &port_block_id);

  bool barrier = upf_worker_pool_get_will_expand (unm->bindings, thread_id);
  if (barrier)
    vlib_worker_thread_barrier_sync (vm);

  upf_nat_binding_t *binding = upf_worker_pool_get (unm->bindings, thread_id);

  if (barrier)
    vlib_worker_thread_barrier_release (vm);

  u32 binding_id = binding - unm->bindings;

  *binding = (upf_nat_binding_t){
    .session_id = session_id,
    .external_addr.as_u32 =
      clib_host_to_net_u32 (nat_pool->addr_start_hostorder + endpoint_id),
    .nat_pool_id = nat_pool_id,
    .port_block_id = port_block_id,
    .pool_endpoint_id = endpoint_id,
  };

  upf_nat_icmp_flows_binding_lru_list_init (
    &binding->icmp_echo_flows_lru_list);
  upf_nat_flows_binding_list_init (&binding->nat_flows_list);

  new_block->binding_id = binding_id;
  nat_pool->used_blocks += 1;

  upf_stats_get_nat_pool (nat_pool_id)->blocks_used += 1;

  return binding_id;
}

void
upf_nat_binding_remove_flows (u16 thread_id, u32 binding_id)
{
  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_wk_t *unw = vec_elt_at_index (unm->workers, thread_id);
  flowtable_main_t *fm = &flowtable_main;
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, thread_id);

  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, binding_id);

  upf_llist_foreach (flow, unw->icmp_flows, binding_lru_anchor,
                     &binding->icmp_echo_flows_lru_list)
    {
      upf_nat_icmp_flow_delete (thread_id, flow - unw->icmp_flows);
    }
  ASSERT (binding->icmp_flows_count == 0);

  upf_llist_foreach (nf, unw->flows, binding_anchor, &binding->nat_flows_list)
    {
      flow_entry_t *uf = pool_elt_at_index (fwk->flows, nf->upf_flow_id);
      uf->nat_flow_id = ~0;
      upf_nat_flow_delete (thread_id, nf - unw->flows);
    }

  ASSERT (upf_llist_list_is_empty (&binding->icmp_echo_flows_lru_list));
  ASSERT (upf_llist_list_is_empty (&binding->nat_flows_list));
}

void
upf_nat_binding_delete (u32 binding_id)
{
  ASSERT_THREAD_MAIN ();
  upf_nat_main_t *unm = &upf_nat_main;
  vlib_main_t *vm = vlib_get_main ();

  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, binding_id);
  upf_nat_pool_t *nat_pool =
    pool_elt_at_index (unm->nat_pools, binding->nat_pool_id);
  u32 nat_pool_id = nat_pool - unm->nat_pools;

  u32 nat_block_id = upf_nat_block_id_from_components (
    nat_pool->blocks_per_addr, binding->pool_endpoint_id,
    binding->port_block_id);

  upf_nat_block_t *block =
    vec_elt_at_index (nat_pool->vec_blocks, nat_block_id);

  ASSERT (block->binding_id == binding_id);

  ASSERT (upf_llist_list_is_empty (&binding->icmp_echo_flows_lru_list));
  ASSERT (upf_llist_list_is_empty (&binding->nat_flows_list));

  bool barrier = upf_worker_pool_put_will_expand (unm->bindings, binding);
  if (barrier)
    vlib_worker_thread_barrier_sync (vm);

  upf_worker_pool_put (unm->bindings, binding);

  if (barrier)
    vlib_worker_thread_barrier_release (vm);

  block->binding_id = ~0;

  nat_pool->used_blocks -= 1;
  nat_pool->timeout_blocks += 1;
  upf_stats_get_nat_pool (nat_pool_id)->blocks_used -= 1;
  upf_stats_get_nat_pool (nat_pool_id)->blocks_timeout += 1;

  block->timeout = upf_timer_start_secs (0, unm->binding_block_timeout,
                                         UPF_TIMER_KIND_NAT_BLOCK_TIMEOUT,
                                         nat_block_id, nat_pool_id);
}

static void
_upf_nat_block_timeout_handler (u16 thread_id, upf_timer_kind_t kind,
                                u32 opaque, u16 opaque2)
{
  ASSERT_THREAD_MAIN ();
  upf_nat_main_t *unm = &upf_nat_main;

  u32 nat_block_id = opaque;
  u16 nat_pool_id = opaque2;

  upf_nat_pool_t *nat_pool = pool_elt_at_index (unm->nat_pools, nat_pool_id);
  upf_nat_block_t *block =
    vec_elt_at_index (nat_pool->vec_blocks, nat_block_id);

  nat_pool->timeout_blocks -= 1;

  upf_timer_stop_safe (thread_id, &block->timeout);
  upf_stats_get_nat_pool (nat_pool_id)->blocks_timeout -= 1;

  upf_nat_block_free_list_insert_tail (nat_pool->vec_blocks,
                                       &nat_pool->free_blocks_list, block);
}

void
upf_nat_binding_set_netcap (u32 binding_id, bool enabled)
{
  upf_nat_main_t *unm = &upf_nat_main;

  u16 thread_id = upf_worker_pool_elt_thread_id (unm->bindings, binding_id);
  ASSERT_THREAD_INDEX_OR_BARRIER (thread_id);

  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, binding_id);

  binding->want_netcap = enabled;
}

void
upf_nat_binding_get_information (u32 binding_id,
                                 upf_nat_binding_info_t *result)
{
  ASSERT_THREAD_MAIN ();

  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, binding_id);
  upf_nat_pool_t *pool =
    pool_elt_at_index (unm->nat_pools, binding->nat_pool_id);

  result->ext_addr = binding->external_addr;
  result->port_min =
    pool->port_min + pool->ports_per_block * binding->port_block_id;
  result->port_max = result->port_min + pool->ports_per_block - 1;
  result->nat_pool_id = binding->nat_pool_id;
}

static void
_upf_nat_pool_addr_add_del_to_fib (upf_nat_pool_t *nat_pool,
                                   ip4_address_t addr, bool is_add)
{
  upf_nat_main_t *unm = &upf_nat_main;
  upf_main_t *um = &upf_main;

  dpo_id_t dpo = DPO_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr.ip4 = addr,
  };

  upf_nat_dpo_create (nat_pool - unm->nat_pools, &dpo);
  upf_interface_t *nwif =
    pool_elt_at_index (um->nwi_interfaces, nat_pool->nwif_id);
  u32 fib_index = nwif->rx_fib_index[FIB_PROTOCOL_IP4];

  if (is_add)
    {
      fib_table_entry_special_dpo_add (fib_index, &pfx, unm->fib_src,
                                       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
      dpo_reset (&dpo);
    }
  else
    {
      fib_table_entry_special_remove (fib_index, &pfx, unm->fib_src);
    }
}

static void
_upf_nat_pool_add_del_to_fib (upf_nat_pool_t *nat_pool, bool is_add)
{
  for (u32 endpoint_id = 0; endpoint_id < nat_pool->addr_count; endpoint_id++)
    {
      ip4_address_t addr;

      addr.as_u32 =
        clib_host_to_net_u32 (nat_pool->addr_start_hostorder + endpoint_id);

      _upf_nat_pool_addr_add_del_to_fib (nat_pool, addr, is_add);
    }
}

static vnet_api_error_t
_upf_nat_pool_add_del_nolock (upf_nwi_name_t nwi_name,
                              upf_interface_type_t intf,
                              ip4_address_t start_addr, ip4_address_t end_addr,
                              u8 *name, u16 port_block_size, u16 min_port,
                              u16 max_port, u8 is_add)
{
  upf_nat_main_t *unm = &upf_nat_main;
  upf_main_t *um = &upf_main;

  uword *p = hash_get_mem (unm->nat_pool_index_by_name, name);
  if (is_add)
    {
      if (p)
        return VNET_API_ERROR_VALUE_EXIST;

      upf_nwi_t *nwi = upf_nwi_get_by_name (nwi_name);
      if (!nwi)
        {
          clib_warning ("Invalid NWI name %U", format_pfcp_dns_labels,
                        nwi_name);
          return VNET_API_ERROR_INVALID_INTERFACE;
        }

      u32 nwif_id = upf_nwi_get_interface_id (nwi, intf);
      ASSERT (!pool_is_free_index (um->nwi_interfaces, nwif_id));

      upf_interface_t *nwif = pool_elt_at_index (um->nwi_interfaces, nwif_id);
      if (!is_valid_id (nwif->rx_fib_index[FIB_PROTOCOL_IP4]))
        {
          clib_warning ("Missing required rx table for NWI %U",
                        format_pfcp_dns_labels, nwi_name);
          return VNET_API_ERROR_NO_SUCH_TABLE;
        }

      if (min_port < UPF_NAT_MIN_PORT || min_port > max_port)
        {
          clib_warning ("Invalid port range for the NAT pool (%d <= %d <= %d)",
                        UPF_NAT_MIN_PORT, min_port, max_port);
          return VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY;
        }

      u32 addr_count = clib_net_to_host_u32 (end_addr.as_u32) -
                       clib_net_to_host_u32 (start_addr.as_u32) + 1;
      u32 ports_per_endpoint = (max_port + 1) - min_port;
      u32 blocks_per_endpoint = ports_per_endpoint / (u32) port_block_size;

      if (addr_count == 0)
        {
          clib_warning ("Addresses range is zero");
          return VNET_API_ERROR_EXCEEDED_NUMBER_OF_PORTS_CAPACITY;
        }

      if (blocks_per_endpoint == 0)
        {
          clib_warning (
            "Ports range is too small for this ports block size (%d < %d)",
            port_block_size < ports_per_endpoint);
          return VNET_API_ERROR_EXCEEDED_NUMBER_OF_PORTS_CAPACITY;
        }

      u32 total_blocks = addr_count * blocks_per_endpoint;

      upf_nat_pool_t *nat_pool;
      pool_get_zero (unm->nat_pools, nat_pool);
      u32 nat_pool_id = nat_pool - unm->nat_pools;

      nat_pool->addr_start = start_addr;
      nat_pool->addr_count = addr_count;
      nat_pool->addr_start_hostorder =
        clib_net_to_host_u32 (start_addr.as_u32);
      vec_validate (nat_pool->vec_blocks, total_blocks - 1);
      nat_pool->blocks_per_addr = blocks_per_endpoint;
      nat_pool->ports_per_block = port_block_size;
      nat_pool->port_min = min_port;
      nat_pool->nwif_id = nwif_id;
      nat_pool->used_blocks = 0;
      nat_pool->timeout_blocks = 0;
      upf_nat_block_free_list_init (&nat_pool->free_blocks_list);
      nat_pool->name = vec_dup (name);

      upf_nat_block_t *block;
      vec_foreach (block, nat_pool->vec_blocks)
        {
          block->binding_id = ~0;
          upf_nat_block_free_list_anchor_init (block);
          block->timeout.as_u32 = ~0;
        }

      // Initialize freelist, make sure it's done in first address order, so
      // first would consume addresses and only later ports
      for (u32 port_i = 0; port_i < nat_pool->blocks_per_addr; port_i++)
        for (u32 addr_i = 0; addr_i < addr_count; addr_i++)
          {
            u32 block_id = upf_nat_block_id_from_components (
              nat_pool->blocks_per_addr, addr_i, port_i);

            upf_nat_block_free_list_insert_tail (
              nat_pool->vec_blocks, &nat_pool->free_blocks_list,
              vec_elt_at_index (nat_pool->vec_blocks, block_id));
          }

      hash_set_mem (unm->nat_pool_index_by_name, nat_pool->name, nat_pool_id);

      upf_stats_ensure_nat_pool (nat_pool_id, nat_pool->name, nwi->name);

      upf_stats_get_nat_pool (nat_pool_id)->blocks_total = total_blocks;
      upf_stats_get_nat_pool (nat_pool_id)->ports_per_block = port_block_size;

      _upf_nat_pool_add_del_to_fib (nat_pool, true);
    }
  else
    {
      if (!p)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      upf_nat_pool_t *nat_pool = pool_elt_at_index (unm->nat_pools, p[0]);

      if (nat_pool->used_blocks)
        {
          clib_warning ("NAT pool in use: %U", format_upf_nat_pool, nat_pool);
          return VNET_API_ERROR_INSTANCE_IN_USE;
        }

      upf_nat_block_t *block;
      vec_foreach (block, nat_pool->vec_blocks)
        upf_timer_stop_safe (0, &block->timeout);

      _upf_nat_pool_add_del_to_fib (nat_pool, false);

      hash_unset_mem (unm->nat_pool_index_by_name, name);

      vec_free (nat_pool->vec_blocks);
      vec_free (nat_pool->name);
      pool_put (unm->nat_pools, nat_pool);
    }

  return 0;
}

vnet_api_error_t
upf_nat_pool_add_del (upf_nwi_name_t nwi_name, upf_interface_type_t intf,
                      ip4_address_t start_addr, ip4_address_t end_addr,
                      u8 *name, u16 port_block_size, u16 min_port,
                      u16 max_port, u8 is_add)
{
  ASSERT_THREAD_MAIN ();

  vlib_main_t *vm = vlib_get_main ();

  _upf_nat_init_late ();

  vlib_worker_thread_barrier_sync (vm);

  vnet_api_error_t err =
    _upf_nat_pool_add_del_nolock (nwi_name, intf, start_addr, end_addr, name,
                                  port_block_size, min_port, max_port, is_add);

  vlib_worker_thread_barrier_release (vm);

  return err;
}

upf_nat_pool_t *
upf_nat_pool_get_by_name (u8 *name)
{
  upf_nat_main_t *unm = &upf_nat_main;

  if (!unm->initialized)
    return NULL;

  uword *p = hash_get_mem (unm->nat_pool_index_by_name, name);
  if (!p)
    return NULL;

  return pool_elt_at_index (unm->nat_pools, p[0]);
}

static void
_upf_nat_init_late ()
{
  upf_nat_main_t *unm = &upf_nat_main;
  upf_mt_main_t *umm = &upf_mt_main;

  if (unm->initialized)
    return;

  unm->initialized = true;

  unm->nat_pool_index_by_name =
    hash_create_vec (0, sizeof (u8), sizeof (uword));

  vec_validate (unm->workers, vec_len (umm->workers) - 1);

  upf_nat_wk_t *worker;
  vec_foreach (worker, unm->workers)
    {
      worker->flows = NULL;
      worker->icmp_flows = NULL;
      upf_nat_icmp_flows_lru_list_init (&worker->icmp_flow_lru);
    }

  u32 nbuckets_tcpudp = 128 * 1024;
  u32 nbuckets_icmp = 16 * 1024;

  clib_bihash_init_16_8 (&unm->flows_by_o2i_key, "upf-nat-flow-o2i-hash",
                         nbuckets_tcpudp, 0);
  clib_bihash_set_kvp_format_fn_16_8 (&unm->flows_by_o2i_key,
                                      format_upf_nat_flow_kvp);

  clib_bihash_init_16_8 (&unm->icmp_flows_by_i2o_key,
                         "upf-nat-icmp-flow-i2o-hash", nbuckets_icmp, 0);
  clib_bihash_set_kvp_format_fn_16_8 (&unm->icmp_flows_by_i2o_key,
                                      format_upf_nat_icmp_flow_kvp);

  clib_bihash_init_16_8 (&unm->icmp_flows_by_o2i_key,
                         "upf-nat-icmp-flow-o2i-hash", nbuckets_icmp, 0);
  clib_bihash_set_kvp_format_fn_16_8 (&unm->icmp_flows_by_o2i_key,
                                      format_upf_nat_icmp_flow_kvp);

  clib_warning ("late NAT init done");
}

static clib_error_t *
upf_nat_init (vlib_main_t *vm)
{
  upf_nat_main_t *unm = &upf_nat_main;

  unm->initialized = false;
  unm->workers = NULL;
  unm->nat_pools = NULL;
  unm->bindings = NULL;
  unm->icmp_max_flows_per_binding = UPF_NAT_DEFAULT_MAX_ICMP_FLOWS_PER_BINDING;
  unm->icmp_flow_timeout = UPF_NAT_DEFAULT_ICMP_FLOWS_TIMEOUT;
  unm->binding_block_timeout = UPF_NAT_DEFAULT_BINDING_BLOCK_TIMEOUT;

  unm->fib_src = fib_source_allocate ("upf-nat-hi", FIB_SOURCE_PRIORITY_HI,
                                      FIB_SOURCE_BH_SIMPLE);

  upf_timer_set_handler (UPF_TIMER_KIND_NAT_BLOCK_TIMEOUT,
                         _upf_nat_block_timeout_handler);

  unm->fq_nat_dpo_handoff_index =
    vlib_frame_queue_main_init (upf_nat_ip4_dpo_node.index, 0);

  return NULL;
}

VLIB_INIT_FUNCTION (upf_nat_init);
