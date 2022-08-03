/*
 * upf.c - 3GPP TS 29.244 GTP-U UP plug-in for vpp
 *
 * Copyright (c) 2017-2019 Travelping GmbH
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <errno.h>

#include <math.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlib/unix/plugin.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_walk.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/pfcp.h>
#include <upf/upf_pfcp_server.h>
#include <upf/version.h>

/* Action function shared between message handler and debug CLI */
#include <upf/flowtable.h>
#include <upf/upf_app_db.h>
#include <upf/upf_ipfix.h>

#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

/**
 * FIB node type the attachment is registered
 */
fib_node_type_t upf_policy_fib_node_type;	// The types of nodes in a FIB graph

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)                          \
  do { } while (0)
#endif

static fib_source_t upf_fib_source;

int
vnet_upf_ue_ip_pool_add_del (u8 * identity, u8 * nwi_name, int is_add)
{
  upf_main_t *gtm = &upf_main;
  upf_ue_ip_pool_info_t *ueip_pool = NULL;
  uword *p;

  p = hash_get_mem (gtm->ue_ip_pool_index_by_identity, identity);

  if (is_add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (gtm->ueip_pools, ueip_pool);
      ueip_pool->identity = vec_dup (identity);
      ueip_pool->nwi_name = vec_dup (nwi_name);

      hash_set_mem (gtm->ue_ip_pool_index_by_identity, identity,
		    ueip_pool - gtm->ueip_pools);

    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      ueip_pool = pool_elt_at_index (gtm->ueip_pools, p[0]);
      hash_unset_mem (gtm->ue_ip_pool_index_by_identity, identity);
      vec_free (ueip_pool->identity);
      vec_free (ueip_pool->nwi_name);
      pool_put (gtm->ueip_pools, ueip_pool);
    }
  return 0;
}

upf_nat_pool_t *
get_nat_pool_by_name (u8 * name)
{
  upf_main_t *gtm = &upf_main;
  uword *p;

  p = hash_get_mem (gtm->nat_pool_index_by_name, name);
  if (!p)
    return NULL;

  return pool_elt_at_index (gtm->nat_pools, p[0]);
}

int
upf_init_nat_addresses (upf_nat_pool_t * np, ip4_address_t start_addr,
			ip4_address_t end_addr)
{
  u32 i = 0;

  u32 start;
  u32 end;

  start = clib_net_to_host_u32 (start_addr.as_u32);
  end = clib_net_to_host_u32 (end_addr.as_u32);

  if (start > end)
    {
      clib_warning ("invalid address range for the NAT pool");
      return -1;
    }

  vec_alloc (np->addresses, end - start + 1);

  for (i = start; i <= end; i++)
    {
      upf_nat_addr_t *ap;

      vec_add2 (np->addresses, ap, 1);
      ap->ext_addr.as_u32 = clib_host_to_net_u32 (i);
      ap->used_blocks = 0;
    };

  return 0;
}

int
vnet_upf_nat_pool_add_del (u8 * nwi_name, ip4_address_t start_addr,
			   ip4_address_t end_addr, u8 * name,
			   u16 port_block_size, u16 min_port, u16 max_port,
			   u8 is_add)
{
  upf_main_t *gtm = &upf_main;
  upf_nat_pool_t *nat_pool = NULL;
  uword *p;

  p = hash_get_mem (gtm->nat_pool_index_by_name, name);

  if (is_add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      if (min_port < UPF_NAT_MIN_PORT ||
	  max_port > UPF_NAT_MAX_PORT || min_port > max_port)
	{
	  clib_warning
	    ("Invalid port range for the NAT pool (must be within %u - %u)",
	     UPF_NAT_MIN_PORT, UPF_NAT_MAX_PORT);
	  return VNET_API_ERROR_INVALID_ARGUMENT;
	}

      pool_get (gtm->nat_pools, nat_pool);

      if (upf_init_nat_addresses (nat_pool, start_addr, end_addr))
	{
	  pool_put (gtm->nat_pools, nat_pool);
	  return -1;
	}

      nat_pool->name = vec_dup (name);
      nat_pool->network_instance = vec_dup (nwi_name);
      nat_pool->port_block_size = port_block_size;
      nat_pool->min_port = min_port;
      nat_pool->max_port = max_port;
      nat_pool->max_blocks_per_addr =
	(u16) ((nat_pool->max_port - nat_pool->min_port) / port_block_size);

      hash_set_mem (gtm->nat_pool_index_by_name, name,
		    nat_pool - gtm->nat_pools);

    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      nat_pool = pool_elt_at_index (gtm->nat_pools, p[0]);
      vec_free (nat_pool->addresses);
      hash_unset_mem (gtm->nat_pool_index_by_name, name);
      vec_free (nat_pool->name);
      vec_free (nat_pool->network_instance);
      pool_put (gtm->nat_pools, nat_pool);
    }
  return 0;
}

void
upf_pfcp_policer_config_init (upf_main_t * gtm)
{
  qos_pol_cfg_params_st *cfg = &pfcp_rate_cfg_main;

  cfg->rate_type = QOS_RATE_PPS;
  cfg->rnd_type = QOS_ROUND_TO_CLOSEST;
  cfg->rfc = QOS_POLICER_TYPE_1R2C;
  cfg->color_aware = 0;
  cfg->conform_action.action_type = QOS_ACTION_TRANSMIT;
  cfg->exceed_action.action_type = QOS_ACTION_DROP;
  cfg->violate_action.action_type = QOS_ACTION_DROP;
  cfg->rb.pps.cir_pps = 1 << 20;
  cfg->rb.pps.cb_ms = 1000;
}

void
upf_pfcp_policers_recalculate (qos_pol_cfg_params_st * cfg)
{
  upf_main_t *gtm = &upf_main;
  policer_t *p;

  pool_foreach (p, gtm->pfcp_policers)
  {
    pol_logical_2_physical (cfg, p);
  }
}

int
vnet_upf_upip_add_del (ip4_address_t * ip4, ip6_address_t * ip6,
		       u8 * name, u8 intf, u32 teid, u32 mask, u8 add)
{
  upf_main_t *gtm = &upf_main;
  upf_upip_res_t *ip_res;
  upf_upip_res_t res = {
    .ip4 = *ip4,
    .ip6 = *ip6,
    .nwi_index = ~0,
    .intf = intf,
    .teid = teid,
    .mask = mask
  };
  uword *p;

  if (name)
    {
      p = hash_get_mem (gtm->nwi_index_by_name, name);
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      res.nwi_index = p[0];
    }

  p = mhash_get (&gtm->upip_res_index, &res);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (gtm->upip_res, ip_res);
      memcpy (ip_res, &res, sizeof (res));

      mhash_set (&gtm->upip_res_index, ip_res, ip_res - gtm->upip_res, NULL);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      ip_res = pool_elt_at_index (gtm->upip_res, p[0]);
      mhash_unset (&gtm->upip_res_index, ip_res, NULL);
      pool_put (gtm->upip_res, ip_res);
    }

  return 0;
}

int
vnet_upf_tdf_ul_table_add_del (u32 vrf, fib_protocol_t fproto, u32 table_id,
			       u8 add)
{
  u32 fib_index, vrf_fib_index;
  upf_main_t *gtm = &upf_main;

  if (add)
    {
      vrf_fib_index = fib_table_find (fproto, vrf);
      if (~0 == vrf_fib_index)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      fib_index =
	fib_table_find_or_create_and_lock (fproto, table_id, upf_fib_source);

      vec_validate_init_empty (gtm->tdf_ul_table[fproto], vrf_fib_index, ~0);
      vec_elt (gtm->tdf_ul_table[fproto], vrf_fib_index) = fib_index;
    }
  else
    {
      vrf_fib_index = fib_table_find (fproto, vrf);
      if (~0 == vrf_fib_index)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (vrf_fib_index >= vec_len (gtm->tdf_ul_table[fproto]))
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      fib_index = fib_table_find (fproto, table_id);
      if (~0 == fib_index)
	return VNET_API_ERROR_NO_SUCH_FIB;

      if (vec_elt (gtm->tdf_ul_table[fproto], vrf_fib_index) != fib_index)
	return VNET_API_ERROR_NO_SUCH_TABLE;

      vec_elt (gtm->tdf_ul_table[fproto], vrf_fib_index) = ~0;
      fib_table_unlock (fib_index, fproto, upf_fib_source);

      return (0);
    }

  return 0;
}

static int
upf_tdf_ul_lookup_add_i (u32 tdf_ul_fib_index, const fib_prefix_t * pfx,
			 u32 ue_fib_index)
{
  dpo_id_t dpo = DPO_INVALID;

  /*
   * create a data-path object to perform the source address lookup
   * in the TDF FIB
   */
  lookup_dpo_add_or_lock_w_fib_index (tdf_ul_fib_index,
				      fib_proto_to_dpo (pfx->fp_proto),
				      LOOKUP_UNICAST,
				      LOOKUP_INPUT_SRC_ADDR,
				      LOOKUP_TABLE_FROM_CONFIG, &dpo);

  /*
   * add the entry to the destination FIB that uses the lookup DPO
   */
  fib_table_entry_special_dpo_add (ue_fib_index, pfx,
				   upf_fib_source,
				   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);

  /*
   * the DPO is locked by the FIB entry, and we have no further
   * need for it.
   */
  dpo_unlock (&dpo);

  return 0;
}

int
vnet_upf_node_id_set (const pfcp_node_id_t * node_id)
{
  upf_main_t *gtm = &upf_main;

  switch (node_id->type)
    {
    case NID_IPv4:
    case NID_IPv6:
    case NID_FQDN:
      free_node_id (&gtm->node_id);
      gtm->node_id = *node_id;
      return 0;
    }

  return VNET_API_ERROR_INVALID_ARGUMENT;
}

int
vnet_upf_pfcp_heartbeat_config (u32 timeout, u32 retries)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  if (!timeout || timeout > PFCP_MAX_HB_INTERVAL
      || retries > PFCP_MAX_HB_RETRIES)
    return -1;

  psm->hb_cfg.timeout = timeout;
  psm->hb_cfg.retries = retries;

  return 0;
}

#if 0
// TODO
static int
upf_tdf_ul_lookup_delete (u32 tdf_ul_fib_index, const fib_prefix_t * pfx)
{
  fib_table_entry_special_remove (tdf_ul_fib_index, pfx, upf_fib_source);

  return (0);
}
#endif

int
vnet_upf_tdf_ul_enable_disable (fib_protocol_t fproto, u32 sw_if_index,
				int is_en)
{
  upf_main_t *gtm = &upf_main;
  fib_prefix_t pfx = {
    .fp_proto = fproto,
  };
  u32 fib_index;

  fib_index = fib_table_get_index_for_sw_if_index (fproto, sw_if_index);

  if (fib_index >= vec_len (gtm->tdf_ul_table[fproto]))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (~0 == vec_elt (gtm->tdf_ul_table[fproto], fib_index))
    return VNET_API_ERROR_NO_SUCH_FIB;

  if (is_en)
    {
      /*
       * now we know which interface the table will serve, we can add the default
       * route to use the table that the interface is bound to.
       */
      upf_tdf_ul_lookup_add_i (vec_elt (gtm->tdf_ul_table[fproto],
					fib_index), &pfx, fib_index);


      /*
         vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
         "ip4-unicast" :
         "ip6-unicast"),
         (FIB_PROTOCOL_IP4 == fproto ?
         "svs-ip4" :
         "svs-ip6"), sw_if_index, 1, NULL, 0);
       */
    }
  else
    {
      // TODO
      /*
         vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
         "ip4-unicast" :
         "ip6-unicast"),
         (FIB_PROTOCOL_IP4 == fproto ?
         "svs-ip4" :
         "svs-ip6"), sw_if_index, 0, NULL, 0);
       */
    }
  return 0;
}

static inline u8 *
format_v4_tunnel_by_key_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);
  gtpu4_tunnel_key_t *key = (gtpu4_tunnel_key_t *) & v->key;

  s = format (s, "TEID 0x%08x peer %U session idx %u rule idx %u",
	      key->teid, format_ip4_address, &key->dst,
	      v->value & 0xffffffff, v->value >> 32);
  return s;
}

static inline u8 *
format_v6_tunnel_by_key_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_24_8_t *v = va_arg (*args, clib_bihash_kv_24_8_t *);

  s = format (s, "TEID 0x%08x peer %U session idx %u rule idx %u",
	      v->key[2], format_ip6_address, &v->key[0],
	      v->value & 0xffffffff, v->value >> 32);
  return s;
}

static inline u8 *
format_peer_index_by_ip_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_24_8_t *v = va_arg (*args, clib_bihash_kv_24_8_t *);

  s = format (s, "peer %U fib idx idx %u peer idx %u",
	      format_ip46_address, &v->key[0], IP46_TYPE_ANY,
	      v->key[2], v->value);
  return s;
}

static u8 *
upf_format_buffer_opaque_helper (const vlib_buffer_t * b, u8 * s)
{
  upf_buffer_opaque_t *o = upf_buffer_opaque (b);

  s = format
    (s, "gtpu.teid: 0x%08x, gtpu.session_index: 0x%x, gtpu.ext_hdr_len: %u, "
     "gtpu.data_offset: %u, gtpu.flags: 0x%02x, gtpu.is_reverse: %u, "
     "gtpu.pdr_idx: 0x%x, gtpu.flow_id: 0x%x",
     (u32) (o->gtpu.teid),
     (u32) (o->gtpu.session_index),
     (u32) (o->gtpu.ext_hdr_len),
     (u32) (o->gtpu.data_offset),
     (u32) (o->gtpu.flags),
     (u32) (o->gtpu.is_reverse),
     (u32) (o->gtpu.pdr_idx), (u32) (o->gtpu.flow_id));
  vec_add1 (s, '\n');

  return s;
}

static int
flow_remove_counter_handler (flowtable_main_t * fm, flow_entry_t * flow,
			     flow_direction_t direction, u32 now)
{
  upf_main_t *gtm = &upf_main;

  vlib_decrement_simple_counter (&gtm->upf_simple_counters
				 [UPF_FLOW_COUNTER],
				 vlib_get_thread_index (), 0, 1);

  if (flow->is_spliced)
    vlib_decrement_simple_counter (&gtm->upf_simple_counters
				   [UPF_FLOWS_STITCHED],
				   vlib_get_thread_index (), 0, 1);

  if (flow->spliced_dirty)
    vlib_decrement_simple_counter (&gtm->upf_simple_counters
				   [UPF_FLOWS_STITCHED_DIRTY_FIFOS],
				   vlib_get_thread_index (), 0, 1);

  return 0;
}

static clib_error_t *
upf_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "pfcp-server-mode"))
	{
	  if (unformat (input, "polling"))
	    ;
	  else if (unformat (input, "interrupt"))
	    vnet_upf_pfcp_set_polling (vm, 0);
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (upf_config_fn, "upf");

static clib_error_t *
upf_init (vlib_main_t * vm)
{
  upf_main_t *sm = &upf_main;
  flowtable_main_t *fm = &flowtable_main;
  clib_error_t *error;

  sm->vnet_main = vnet_get_main ();
  sm->vlib_main = vm;
  sm->pfcp_spec_version = 15;
  sm->rand_base = random_default_seed ();
  sm->log_class = vlib_log_register_class ("upf", 0);

  if ((error = vlib_call_init_function (vm, upf_proxy_main_init)))
    return error;

  vnet_register_format_buffer_opaque2_helper
    (upf_format_buffer_opaque_helper);

  mhash_init (&sm->pfcp_endpoint_index, sizeof (uword),
	      sizeof (ip46_address_t));
  sm->nwi_index_by_name =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));
  mhash_init (&sm->upip_res_index, sizeof (uword), sizeof (upf_upip_res_t));

  sm->forwarding_policy_by_id =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));

  /* initialize the IP/TEID hash's */
  clib_bihash_init_8_8 (&sm->v4_tunnel_by_key,
			"upf_v4_tunnel_by_key", UPF_MAPPING_BUCKETS,
			UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_set_kvp_format_fn_8_8 (&sm->v4_tunnel_by_key,
				     format_v4_tunnel_by_key_kvp);
  clib_bihash_init_24_8 (&sm->v6_tunnel_by_key,
			 "upf_v6_tunnel_by_key", UPF_MAPPING_BUCKETS,
			 UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_set_kvp_format_fn_24_8 (&sm->v6_tunnel_by_key,
				      format_v6_tunnel_by_key_kvp);

  clib_bihash_init_24_8 (&sm->peer_index_by_ip,
			 "upf_peer_index_by_ip", UPF_MAPPING_BUCKETS,
			 UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_set_kvp_format_fn_24_8 (&sm->peer_index_by_ip,
				      format_peer_index_by_ip_kvp);

  sm->node_index_by_fqdn =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));
  mhash_init (&sm->node_index_by_ip, sizeof (uword), sizeof (ip46_address_t));

#if 0
  sm->vtep6 = hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
#endif

  clib_bihash_init_8_8 (&sm->qer_by_id,
			"upf_qer_by_ie", UPF_MAPPING_BUCKETS,
			UPF_MAPPING_MEMORY_SIZE);

  udp_register_dst_port (vm, UDP_DST_PORT_GTPU,
			 upf_gtpu4_input_node.index, /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_GTPU6,
			 upf_gtpu6_input_node.index, /* is_ip4 */ 0);

  sm->fib_node_type = fib_node_register_new_type ("upf", &upf_vft);

  sm->upf_app_by_name = hash_create_vec ( /* initial length */ 32,
					 sizeof (u8), sizeof (uword));

  upf_fib_source = fib_source_allocate ("upf-tdf-route",
					FIB_SOURCE_PRIORITY_HI,
					FIB_SOURCE_BH_SIMPLE);

  vec_validate (sm->upf_simple_counters, UPF_N_COUNTERS - 1);

#define _(E,n,p) \
  sm->upf_simple_counters[UPF_##E].name = #n; \
  sm->upf_simple_counters[UPF_##E].stat_segment_name = "/" #p "/" #n; \
  vlib_validate_simple_counter (&sm->upf_simple_counters[UPF_##E], 0); \
  vlib_zero_simple_counter (&sm->upf_simple_counters[UPF_##E], 0);
  foreach_upf_counter_name
#undef _
    sm->node_id.type = NID_FQDN;
  sm->node_id.fqdn = format (0, (char *) "\x03upg");

  sm->nat_pool_index_by_name =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));

  sm->ue_ip_pool_index_by_identity =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));

  error = flowtable_init (vm);
  if (!error)
    error = upf_ipfix_init (vm);
  if (!error)
    error = pfcp_server_main_init (vm);
  if (!error)
    upf_pfcp_policer_config_init (sm);

  flowtable_add_event_handler (fm, FLOW_EVENT_REMOVE,
			       flow_remove_counter_handler);
  flowtable_add_event_handler (fm, FLOW_EVENT_UNLINK,
			       session_flow_unlink_handler);

  return error;
}

VLIB_INIT_FUNCTION (upf_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (upf, static) =
{
  .arc_name = "device-input",
  .node_name = "upf",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

u8 *
format_upf_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_encap_trace_t *t = va_arg (*args, upf_encap_trace_t *);

  s = format (s, "GTPU encap to upf_session%d teid 0x%08x",
	      t->session_index, t->teid);
  return s;
}

void
upf_fpath_stack_dpo (upf_forwarding_policy_t * p)
{
  fib_path_list_contribute_forwarding(p->fib_pl,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      FIB_PATH_LIST_FWD_FLAG_COLLAPSE, &p->dpo);
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = UPG_VERSION,
  .description = "User Plane Gateway",
};
/* *INDENT-ON* */

/* ####################  dpo restacking vft #################### */
static void
upf_policy_destroy (upf_forwarding_policy_t * fp_entry)
{
  upf_main_t *gtm = &upf_main;
  /*
   * this upf_fp should not be a sibling on the path list, since
   * that was removed when the API config went
   */
  ASSERT (fp_entry->fib_sibling == ~0);
  ASSERT (fp_entry->fib_pl == FIB_NODE_INDEX_INVALID);

  hash_unset_mem (gtm->forwarding_policy_by_id, fp_entry->policy_id);
  vec_free (fp_entry->policy_id);
  vec_free (fp_entry->rpaths);
  pool_put (gtm->upf_forwarding_policies, fp_entry);
}

static upf_forwarding_policy_t *
upf_policy_get_from_fib_node (fib_node_t * node)
{
  return ((upf_forwarding_policy_t *) (((char *) node) -
				       STRUCT_OFFSET_OF
				       (upf_forwarding_policy_t, fib_node)));
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
upf_policy_fib_node_get (fib_node_index_t index)
{
  upf_main_t *gtm = &upf_main;
  upf_forwarding_policy_t *p;

  p = pool_elt_at_index (gtm->upf_forwarding_policies, index);
  return (&p->fib_node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
upf_policy_last_lock_gone (fib_node_t * node)
{
  upf_policy_destroy (upf_policy_get_from_fib_node (node));
}

/**
 * Function definition to backwalk a FIB node -
 * Here we will restack the new dpo to forward node.
 */
static fib_node_back_walk_rc_t
upf_policy_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  upf_fpath_stack_dpo (upf_policy_get_from_fib_node (node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

const fib_node_vft_t upf_fp_vft = {
  .fnv_get = upf_policy_fib_node_get,
  .fnv_last_lock = upf_policy_last_lock_gone,
  .fnv_back_walk = upf_policy_back_walk,
};

static clib_error_t *
upf_policy_init (vlib_main_t * vm)
{
  upf_policy_fib_node_type =
    fib_node_register_new_type ("upf-fp", &upf_fp_vft);
  return (NULL);
}

VLIB_INIT_FUNCTION (upf_policy_init);

u8 *
format_upf_policy (u8 * s, va_list * args)
{
  upf_main_t *gtm = &upf_main;
  upf_forwarding_policy_t *fp_entry =
    va_arg (*args, upf_forwarding_policy_t *);

  s = format (s, "upf:[%d]: policy:%v",
	      fp_entry - gtm->upf_forwarding_policies, fp_entry->policy_id);
  s = format (s, "\n ");
  if (FIB_NODE_INDEX_INVALID == fp_entry->fib_pl)
    {
      s = format (s, "no forwarding");
    }
  else
    {
      s = fib_path_list_format (fp_entry->fib_pl, s);
    }
  return (s);
}

upf_forwarding_policy_t *
upf_get_policy (vlib_main_t * vm, u8 * policy_id)
{
  upf_main_t *gtm = &upf_main;
  uword *hash_ptr;

  hash_ptr = hash_get_mem (gtm->forwarding_policy_by_id, policy_id);
  if (hash_ptr)
    return pool_elt_at_index (gtm->upf_forwarding_policies, hash_ptr[0]);
  return NULL;
}

static void
fib_path_list_create_and_child_add (upf_forwarding_policy_t * fp_entry,
				    fib_route_path_t * rpaths)
{
  upf_main_t *gtm = &upf_main;
  fp_entry->fib_pl = fib_path_list_create ((FIB_PATH_LIST_FLAG_SHARED |
					    FIB_PATH_LIST_FLAG_NO_URPF),
					   rpaths);
  /* Keep rpath for update path lists later */
  fp_entry->rpaths = vec_dup (rpaths);

  /*
   * become a child of the path list so we get poked when
   * the forwarding changes.
   */
  fp_entry->fib_sibling = fib_path_list_child_add (fp_entry->fib_pl,
						   upf_policy_fib_node_type,
						   fp_entry -
						   gtm->upf_forwarding_policies);
}

/*
 * upf policy actions
 * 0 - delete
 * 1 - add
 * 2 - update
 */
int
vnet_upf_policy_fn (fib_route_path_t * rpaths, u8 * policy_id, u8 action)
{
  upf_main_t *gtm = &upf_main;
  upf_forwarding_policy_t *fp_entry;
  fib_node_index_t old_pl;
  uword *hash_ptr;
  int rc = 0;

  hash_ptr = hash_get_mem (gtm->forwarding_policy_by_id, policy_id);
  if (!hash_ptr)
    {
      if (action == 1)
	{
	  pool_get (gtm->upf_forwarding_policies, fp_entry);
	  fib_node_init (&fp_entry->fib_node, upf_policy_fib_node_type);
	  fp_entry->policy_id = vec_dup (policy_id);
	  fp_entry->rpaths = clib_mem_alloc (sizeof (fp_entry->rpaths));

	  fib_path_list_create_and_child_add (fp_entry, rpaths);
	  hash_set_mem (gtm->forwarding_policy_by_id, fp_entry->policy_id,
			fp_entry - gtm->upf_forwarding_policies);
	  upf_fpath_stack_dpo (fp_entry);
	  fib_node_lock (&fp_entry->fib_node);
	}
      else
	rc = 1;
    }
  else
    {
      if (action == 0)
	{
	  fp_entry =
	    pool_elt_at_index (gtm->upf_forwarding_policies, hash_ptr[0]);
	  if (fp_entry->ref_cnt != 0)
	    {
	      upf_debug
		("###### Policy %v can not be removed as it is referred by %d FARs ######",
		 policy_id, fp_entry->ref_cnt);
	      rc = 1;
	    }
	  else
	    {
	      old_pl = fp_entry->fib_pl;
	      fib_path_list_lock (old_pl);
	      fp_entry->fib_pl =
		fib_path_list_copy_and_path_remove (fp_entry->fib_pl,
						    (FIB_PATH_LIST_FLAG_SHARED
						     |
						     FIB_PATH_LIST_FLAG_NO_URPF),
						    fp_entry->rpaths);
	      fib_path_list_child_remove (old_pl, fp_entry->fib_sibling);
	      fp_entry->fib_sibling = ~0;
	      fib_node_unlock (&fp_entry->fib_node);
	      vec_free (fp_entry->rpaths);
	      fib_path_list_unlock (old_pl);

	    }
	}
      else if (action == 2)
	{
	  fp_entry =
	    pool_elt_at_index (gtm->upf_forwarding_policies, hash_ptr[0]);
	  old_pl = fp_entry->fib_pl;
	  fib_path_list_lock (old_pl);
	  fp_entry->fib_pl =
	    fib_path_list_copy_and_path_remove (fp_entry->fib_pl,
						(FIB_PATH_LIST_FLAG_SHARED
						 |
						 FIB_PATH_LIST_FLAG_NO_URPF),
						fp_entry->rpaths);
	  fib_path_list_child_remove (old_pl, fp_entry->fib_sibling);
	  fp_entry->fib_sibling = ~0;
	  fib_path_list_unlock (old_pl);
	  upf_debug ("###### Old fpath list removed ######");

	  fib_path_list_create_and_child_add (fp_entry, rpaths);
	  hash_set_mem (gtm->forwarding_policy_by_id, fp_entry->policy_id,
			fp_entry - gtm->upf_forwarding_policies);
	  upf_fpath_stack_dpo (fp_entry);
	}
    }

  return rc;
}

/* Taken from VPP DNS plugin */
/* original name_to_labels() from dns.c */
/**
 * Translate "foo.com" into "0x3 f o o 0x3 c o m 0x0"
 * A historical / hysterical micro-TLV scheme. DGMS.
 */
u8 *
upf_name_to_labels (u8 * name)
{
  int i;
  int last_label_index;
  u8 *rv;

  rv = vec_dup (name);

  /* punch in space for the first length */
  vec_insert (rv, 1, 0);
  last_label_index = 0;
  i = 1;

  while (i < vec_len (rv))
    {
      if (rv[i] == '.')
	{
	  rv[last_label_index] = (i - last_label_index) - 1;
	  if ((i - last_label_index) > 63)
	    clib_warning ("stupid name, label length %d",
			  i - last_label_index);
	  last_label_index = i;
	  rv[i] = 0;
	}
      i++;
    }
  /* Set the last real label length */
  rv[last_label_index] = (i - last_label_index) - 1;

  return rv;
}

void
upf_nat_get_src_port (vlib_buffer_t * b, u16 port)
{
  flowtable_main_t *fm = &flowtable_main;
  flow_entry_t *flow;
  u32 flow_id;

  flow_id = upf_buffer_opaque (b)->gtpu.flow_id;
  flow = flowtable_get_flow (fm, flow_id);
  if (!flow)
    return;
  flow->nat_sport = clib_net_to_host_u16 (port);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
