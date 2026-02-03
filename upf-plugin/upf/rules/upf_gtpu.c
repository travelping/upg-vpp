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

#include <vnet/vnet.h>
#include <vnet/ip/ip6_hop_by_hop.h>

#include "upf/upf.h"
#include "upf/upf_stats.h"
#include "upf/utils/ip_helpers.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/rules/upf_gtpu_proto.h"

#define UPF_DEBUG_ENABLE 0

upf_gtpu_main_t upf_gtpu_main;

vnet_api_error_t
upf_gtpu_endpoint_add_del (ip4_address_t *ip4, ip6_address_t *ip6,
                           upf_nwi_name_t nwi_name, upf_interface_type_t intf,
                           u32 teid, u32 mask, u8 add, u16 min_port,
                           u16 max_port)
{
  upf_main_t *um = &upf_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  vlib_main_t *vm = vlib_get_main ();

  upf_nwi_t *nwi = upf_nwi_get_by_name (nwi_name);
  if (!nwi)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  bool is_default = !is_valid_id (intf);

  if (add)
    {
      if (is_default)
        {
          if (is_valid_id (nwi->_default_gtpu_endpoint_id))
            return VNET_API_ERROR_VALUE_EXIST;
        }
      else
        {
          if (nwi->interfaces_ids[intf] == nwi->_default_gtpu_endpoint_id)
            return VNET_API_ERROR_VALUE_EXIST;
        }

      bool has_ip4 = !ip4_address_is_zero (ip4);
      bool has_ip6 = !ip6_address_is_zero (ip6);
      if (!has_ip4 && !has_ip6)
        return VNET_API_ERROR_NO_MATCHING_INTERFACE;

      if (max_port < min_port || min_port == 0 || max_port == 0)
        return VNET_API_ERROR_INVALID_VALUE;

      // To simplify TEID management we guarantee that different endpoints will
      // not share ip4 or ip6 addresses separately.
      upf_gtpu_endpoint_t *iter_ep;
      pool_foreach (iter_ep, ugm->endpoints)
        {
          if (!iter_ep->has_ip4 || !iter_ep->has_ip6)
            continue;

          bool ip4_eq = ip4_address_is_equal (ip4, &iter_ep->ip4);
          bool ip6_eq = ip6_address_is_equal (ip6, &iter_ep->ip6);
          if (ip4_eq != ip6_eq) // if only 1 address matches
            return VNET_API_ERROR_ADDRESS_FOUND_FOR_INTERFACE;
        }

      bool barrier = pool_get_will_expand (ugm->endpoints);
      if (barrier)
        vlib_worker_thread_barrier_sync (vm);

      upf_gtpu_endpoint_t *ep;
      pool_get (ugm->endpoints, ep);

      upf_stats_ensure_gtpu_endpoint (ep - ugm->endpoints, nwi_name,
                                      has_ip4 ? ip4 : NULL,
                                      has_ip6 ? ip6 : NULL);

      if (barrier)
        vlib_worker_thread_barrier_release (vm);

      *ep = (upf_gtpu_endpoint_t){
        .ip4 = *ip4,
        .ip6 = *ip6,
        .has_ip4 = has_ip4,
        .has_ip6 = has_ip6,
        .nwi_id = nwi - um->nwis,
        .intf = intf,
        .src_port_start = min_port,
        .src_port_len = max_port - min_port + 1,
      };
      ep->src_port_len_mask = pow2_mask (min_log2 (ep->src_port_len));

      u16 ep_id = ep - ugm->endpoints;
      if (is_default)
        {
          nwi->_default_gtpu_endpoint_id = ep_id;

          for (int i = 0; i < UPF_INTERFACE_N_TYPE; i++)
            if (!is_valid_id (nwi->gtpu_endpoints_ids[i]))
              nwi->gtpu_endpoints_ids[i] = ep_id;
        }
      else
        {
          nwi->gtpu_endpoints_ids[intf] = ep_id;
        }
    }
  else
    {
      u16 ep_id = is_default ? nwi->_default_gtpu_endpoint_id :
                               nwi->gtpu_endpoints_ids[intf];
      if (!is_valid_id (ep_id))
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      upf_gtpu_endpoint_t *ep = pool_elt_at_index (ugm->endpoints, ep_id);

      if (is_default)
        {
          nwi->_default_gtpu_endpoint_id = ~0;

          for (int i = 0; i < UPF_INTERFACE_N_TYPE; i++)
            if (nwi->interfaces_ids[i] == ep_id)
              nwi->gtpu_endpoints_ids[i] = ~0;
        }
      else
        {
          nwi->gtpu_endpoints_ids[intf] = ~0;
        }

      bool barrier = pool_put_will_expand (ugm->endpoints, ep);
      if (barrier)
        vlib_worker_thread_barrier_sync (vm);

      pool_put (ugm->endpoints, ep);

      if (barrier)
        vlib_worker_thread_barrier_release (vm);
    }

  return 0;
}

void
upf_gtpu_send_end_marker (vlib_main_t *vm, upf_gtpu_endpoint_t *src_ep,
                          upf_interface_t *nwif, ip4_address_t *dst_addr4,
                          ip6_address_t *dst_addr6, u32 teid)
{
  upf_main_t *um = &upf_main;

  u32 bi = 0;
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      upf_debug ("no buffers for end marker");
      return;
    }

  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

  bool has_dst4 = !is_zero_ip4_address (dst_addr4);
  bool has_dst6 = !is_zero_ip6_address (dst_addr6);

  bool is_ip4;
  if (has_dst4 && src_ep->has_ip4)
    is_ip4 = 1;
  else if (has_dst6 && src_ep->has_ip6)
    is_ip4 = 0;
  else
    {
      vlib_log_err (um->log_class,
                    "GTPU End Marker ip versions mismatch src (%d,%d) != dst "
                    "(%d,%d) for teid 0x%x",
                    src_ep->has_ip4, src_ep->has_ip6, has_dst4, has_dst6,
                    teid);
      return;
    }

  udp_header_t *udp;
  gtpu_header_tpdu_t *gtpuh;
  void *iph = vlib_buffer_get_current (b);
  if (is_ip4)
    {
      ip4_gtpu_header_t *gtpu4 = iph;
      ip4_header_t *ip4 = &gtpu4->ip4;
      udp = &gtpu4->udp;
      gtpuh = &gtpu4->gtpu;

      b->current_length = sizeof (*gtpu4);

      ip4->ip_version_and_header_length = 0x45;
      ip4->tos = 0;
      ip4->length = clib_host_to_net_u16 (sizeof (ip4_gtpu_header_t));
      ip4->fragment_id = 0;
      ip4->flags_and_fragment_offset = 0;
      ip4->ttl = 127;
      ip4->protocol = IP_PROTOCOL_UDP;
      ip4->checksum = 0;
      ip4->src_address = src_ep->ip4;
      ip4->dst_address = *dst_addr4;
      ip4->checksum = ip4_header_checksum (ip4);
    }
  else
    {
      ip6_gtpu_header_t *gtpu6 = iph;
      ip6_header_t *ip6 = &gtpu6->ip6;
      udp = &gtpu6->udp;
      gtpuh = &gtpu6->gtpu;

      b->current_length = sizeof (*gtpu6);

      ip6->ip_version_traffic_class_and_flow_label = 0x60;
      ip6->payload_length = clib_host_to_net_u16 (sizeof (udp_header_t) +
                                                  sizeof (gtpu_header_tpdu_t));
      ip6->protocol = IP_PROTOCOL_UDP;
      ip6->hop_limit = 127;
      ip6->src_address = src_ep->ip6;
      ip6->dst_address = *dst_addr6;
    }

  udp->src_port = clib_host_to_net_u16 (src_ep->src_port_start +
                                        (teid & src_ep->src_port_len_mask));
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_GTPU);
  udp->length =
    clib_host_to_net_u16 (sizeof (gtpu_header_tpdu_t) + sizeof (udp_header_t));
  udp->checksum = 0;

  gtpuh->ver_flags = GTPU_V1_VER | GTPU_PT_GTP;
  gtpuh->teid = clib_host_to_net_u32 (teid);
  gtpuh->type = GTPU_TYPE_END_MARKER;
  gtpuh->length = 0;

  if (!is_ip4)
    {
      int bogus_length;
      udp->checksum =
        ip6_tcp_udp_icmp_compute_checksum (vm, b, iph, &bogus_length);
      ASSERT (bogus_length == 0);
    }

  vnet_buffer (b)->sw_if_index[VLIB_TX] =
    nwif->tx_fib_index[is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6];
  vnet_buffer (b)->ip.adj_index[VLIB_TX] = ~0;

  upf_debug ("sent end marker %U", format_ip_header, iph, b->current_length);

  u32 node_index = is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
  vlib_frame_t *f = vlib_get_frame_to_node (vm, node_index);
  u32 *to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, node_index, f);
}

u8 *
format_gtpu_endpoint (u8 *s, va_list *args)
{
  upf_gtpu_endpoint_t *ep = va_arg (*args, upf_gtpu_endpoint_t *);

  upf_main_t *um = &upf_main;
  upf_nwi_t *nwi = pool_elt_at_index (um->nwis, ep->nwi_id);

  if (ep->has_ip4)
    s = format (s, " ip4: %U", format_ip4_address, &ep->ip4);
  if (ep->has_ip6)
    s = format (s, " ip6: %U", format_ip6_address, &ep->ip6);

  s = format (s, ", nwi: %U", format_upf_nwi_name, nwi->name);

  if (is_valid_id (ep->intf))
    s = format (s, ", intf: %U", format_upf_interface_type, ep->intf);

  // TODO: decide if such functionality is needed
  // s = format (s, ", 0x%08x/%d (0x%08x)", ep->teid,
  //             __builtin_popcount (ep->mask), ep->mask);

  return s;
}

// get session which has same teid
u32
upf_gtpu_tunnel_get_session_by_teid (upf_gtpu_endpoint_t *ep, u32 teid)
{
  ASSERT (teid != ~0 && teid != 0);

  u32 _session_index;
  u16 _session_generation;
  u16 _thread_index;
  u8 _rules_f_teid_id;
  bool is_active;

  if (ep->has_ip4)
    if (upf_gtpu_tunnel4_lookup (teid, ep->ip4, &_session_index,
                                 &_session_generation, &_thread_index,
                                 &_rules_f_teid_id, &is_active))
      return _session_index;

  if (ep->has_ip6)
    if (upf_gtpu_tunnel6_lookup (teid, ep->ip6, &_session_index,
                                 &_session_generation, &_thread_index,
                                 &_rules_f_teid_id, &is_active))
      return _session_index;

  return ~0;
}

// search TEID, but do not claim it (do not create tunnels)
u32
upf_gtpu_tunnel_search_free_teid (upf_gtpu_endpoint_t *ep)
{
  upf_main_t *um = &upf_main;

  u32 seed = unix_time_now_nsec () ^ random_u32 (&um->rand_base);
  u8 retry_cnt = 20;

  // Randomly search for unused teid
  do
    {
      u32 teid = random_u32 (&seed);
      if (teid == 0 || teid == ~0)
        continue;

      u32 existing_session_id = upf_gtpu_tunnel_get_session_by_teid (ep, teid);
      if (is_valid_id (existing_session_id))
        continue;

      return teid;
    }
  while (retry_cnt--);

  return 0;
}

static void
_upf_gtpu_tunnel4_create (u32 teid, ip4_address_t addr, u32 session_id,
                          u16 session_generation, u16 thread_id,
                          u8 rules_f_teid_lid, bool is_active)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  clib_bihash_kv_8_8_t bh_kv;

  upf_gtpu4_tunnel_key_t *key = (upf_gtpu4_tunnel_key_t *) &bh_kv.key;
  *key = (upf_gtpu4_tunnel_key_t){
    .ep_ip4 = addr,
    .teid = teid,
  };

  bh_kv.value = gtpu_tunnel_lookup_value_pack (
    session_id, session_generation, thread_id, rules_f_teid_lid, is_active);

  int rv = clib_bihash_add_del_8_8 (&ugm->tunnel_by_fteid4, &bh_kv, 1);
  ASSERT (rv == 0);
}

static void
_upf_gtpu_tunnel6_create (u32 teid, ip6_address_t addr, u32 session_id,
                          u16 session_generation, u16 thread_id,
                          u8 rules_f_teid_lid, bool is_active)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  clib_bihash_kv_24_8_t bh_kv;

  upf_gtpu6_tunnel_key_t *key = (upf_gtpu6_tunnel_key_t *) &bh_kv.key;
  *key = (upf_gtpu6_tunnel_key_t){
    .ep_ip6 = addr,
    .teid = teid,
  };

  bh_kv.value = gtpu_tunnel_lookup_value_pack (
    session_id, session_generation, thread_id, rules_f_teid_lid, is_active);

  int rv = clib_bihash_add_del_24_8 (&ugm->tunnel_by_fteid6, &bh_kv, 1);
  ASSERT (rv == 0);
}

static void
_upf_gtpu_tunnel4_delete (u32 teid, ip4_address_t addr)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  clib_bihash_kv_8_8_t bh_kv;

  upf_gtpu4_tunnel_key_t *key = (upf_gtpu4_tunnel_key_t *) &bh_kv.key;
  *key = (upf_gtpu4_tunnel_key_t){
    .ep_ip4 = addr,
    .teid = teid,
  };

  int rv = clib_bihash_add_del_8_8 (&ugm->tunnel_by_fteid4, &bh_kv, 0);
  ASSERT (rv == 0);
}

static void
_upf_gtpu_tunnel6_delete (u32 teid, ip6_address_t addr)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  clib_bihash_kv_24_8_t bh_kv;

  upf_gtpu6_tunnel_key_t *key = (upf_gtpu6_tunnel_key_t *) &bh_kv.key;
  *key = (upf_gtpu6_tunnel_key_t){
    .ep_ip6 = addr,
    .teid = teid,
  };

  int rv = clib_bihash_add_del_24_8 (&ugm->tunnel_by_fteid6, &bh_kv, 0);
  ASSERT (rv == 0);
}

void
upf_gtpu_endpoint_tunnel_create (upf_gtpu_endpoint_t *ep, u32 teid,
                                 u32 session_id, u16 session_generation,
                                 u16 thread_id, u8 rules_f_teid_lid)
{
  if (ep->has_ip4)
    _upf_gtpu_tunnel4_create (teid, ep->ip4, session_id, session_generation,
                              thread_id, rules_f_teid_lid, false);
  if (ep->has_ip6)
    _upf_gtpu_tunnel6_create (teid, ep->ip6, session_id, session_generation,
                              thread_id, rules_f_teid_lid, false);
}

void
upf_gtpu_endpoint_tunnel_activate (upf_gtpu_endpoint_t *ep, u32 teid,
                                   u32 session_id, u16 session_generation,
                                   u16 thread_id, u8 rules_f_teid_lid)
{
  if (ep->has_ip4)
    _upf_gtpu_tunnel4_create (teid, ep->ip4, session_id, session_generation,
                              thread_id, rules_f_teid_lid, true);
  if (ep->has_ip6)
    _upf_gtpu_tunnel6_create (teid, ep->ip6, session_id, session_generation,
                              thread_id, rules_f_teid_lid, true);
}

void
upf_gtpu_endpoint_tunnel_delete (upf_gtpu_endpoint_t *ep, u32 teid)
{
  if (ep->has_ip4)
    _upf_gtpu_tunnel4_delete (teid, ep->ip4);
  if (ep->has_ip6)
    _upf_gtpu_tunnel6_delete (teid, ep->ip6);
}

static inline u8 *
format_v4_tunnel_by_fteid_kvp (u8 *s, va_list *args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);
  upf_gtpu4_tunnel_key_t *key = (upf_gtpu4_tunnel_key_t *) &v->key;
  u32 session_id;
  u16 session_generation;
  u16 thread_id;
  u8 rules_f_teid_id;
  bool is_active;
  gtpu_tunnel_lookup_value_unpack (v->value, &session_id, &session_generation,
                                   &thread_id, &rules_f_teid_id, &is_active);

  s = format (
    s, "TEID 0x%08x ip %U session %u (gen 0x%x) thread %u rules_fteid %u",
    key->teid, format_ip4_address, &key->ep_ip4, session_id,
    session_generation, thread_id, rules_f_teid_id);
  return s;
}

static inline u8 *
format_v6_tunnel_by_fteid_kvp (u8 *s, va_list *args)
{
  clib_bihash_kv_24_8_t *v = va_arg (*args, clib_bihash_kv_24_8_t *);
  upf_gtpu6_tunnel_key_t *key = (upf_gtpu6_tunnel_key_t *) &v->key;
  u32 session_id;
  u16 session_generation;
  u16 thread_id;
  u8 rules_f_teid_id;

  bool is_active;
  gtpu_tunnel_lookup_value_unpack (v->value, &session_id, &session_generation,
                                   &thread_id, &rules_f_teid_id, &is_active);

  s = format (
    s, "TEID 0x%08x ip %U session %u (gen 0x%x) thread %u rules_fteid %u",
    key->teid, format_ip6_address, &key->ep_ip6, session_id,
    session_generation, thread_id, rules_f_teid_id);
  return s;
}

static clib_error_t *
upf_gtpu_init (vlib_main_t *vm)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  clib_bihash_init_8_8 (&ugm->tunnel_by_fteid4, "upf_v4_tunnel_by_fteid",
                        UPF_MAPPING_BUCKETS, UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_set_kvp_format_fn_8_8 (&ugm->tunnel_by_fteid4,
                                     format_v4_tunnel_by_fteid_kvp);
  clib_bihash_init_24_8 (&ugm->tunnel_by_fteid6, "upf_v6_tunnel_by_fteid",
                         UPF_MAPPING_BUCKETS, UPF_MAPPING_MEMORY_SIZE);
  clib_bihash_set_kvp_format_fn_24_8 (&ugm->tunnel_by_fteid6,
                                      format_v6_tunnel_by_fteid_kvp);

  ugm->fq_gtpu4_handoff_index =
    vlib_frame_queue_main_init (upf_gtpu4_input_node.index, 0);
  ugm->fq_gtpu6_handoff_index =
    vlib_frame_queue_main_init (upf_gtpu6_input_node.index, 0);
  ugm->fq_gtpu_err_ind_handoff_index =
    vlib_frame_queue_main_init (upf_gtpu_error_ind_node.index, 0);
  return NULL;
}

VLIB_INIT_FUNCTION (upf_gtpu_init);
