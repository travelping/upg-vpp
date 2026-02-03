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

#include "upf/upf.h"
#include "upf/utils/ip_helpers.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/rules/upf_session_dpo.h"
#include "upf/nat/nat.h"
#include "upf/sxu/upf_session_update.h"
#include "upf/sxu/upf_sxu_inlines.h"

#define UPF_DEBUG_ENABLE 0

static void
_upf_sxu_error_add_session_collision (upf_sxu_t *sxu,
                                      u32 conflicted_session_id,
                                      upf_sxu_type_t type, upf_xid_t xid)
{
  upf_sxu_conflict_t c = {
    .conflicted_session_id = conflicted_session_id,
    .type = type,
    .xid = xid,
  };
  vec_add1 (sxu->endpoint_conflicts, c);
}

static __clib_warn_unused_result int
_upf_sxu_traffic_endpoint_init (upf_sxu_t *sxu, sxu_slot_traffic_ep_t *slot,
                                u8 self_xid)
{
  upf_main_t *um = &upf_main;

  sxu_traffic_ep_t *el = &slot->val;
  sxu_traffic_ep_key_t *key = &slot->key;

  *el = (sxu_traffic_ep_t){
    .ref_ue_ip4_xid = ~0,
    .ref_ue_ip6_xid = ~0,
  };

  if (!key->is_gtpu)
    {
      // if not gtpu, then IP matching
      upf_nwi_t *nwi = pool_elt_at_index (um->nwis, key->nwi_id);
      if (!is_valid_id (key->intf))
        return upf_sxu_traffic_ep_error_set_by_xid (
          sxu, self_xid, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_SOURCE_INTERFACE, "no such interface configured for NWI");

      upf_interface_t *nwif =
        pool_elt_at_index (um->nwi_interfaces, nwi->interfaces_ids[key->intf]);

      bool match_any = false;
      if (!key->is_ip4 && !key->is_ip6)
        {
          ASSERT (ip4_address_is_zero (&key->ue_addr4));
          ASSERT (ip6_address_is_zero (&key->ue_addr6));
          match_any = true;
        }

      if (key->is_ip4 || match_any)
        {
          u16 nwif_fib_id = nwif->rx_fib_index[FIB_PROTOCOL_IP4];
          if (!is_valid_id (nwif_fib_id))
            {
              if (match_any)
                goto _skip_ip4;

              return upf_sxu_traffic_ep_error_set_by_xid (
                sxu, self_xid, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
                PFCP_IE_SOURCE_INTERFACE,
                "no destination matching fib configured for ipv4");
            }

          sxu_ue_ip_ep4_key_t mk4 = {
            .addr = key->ue_addr4,
            .fib_id = nwif_fib_id,
            .is_source_matching = !key->is_destination_ip,
          };

          if (!key->is_destination_ip)
            {
              if (mk4.fib_id >= vec_len (um->tdf_ul_table[FIB_PROTOCOL_IP4]))
                {
                  if (match_any)
                    goto _skip_ip4;

                  return upf_sxu_traffic_ep_error_set_by_xid (
                    sxu, self_xid,
                    PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
                    PFCP_IE_SOURCE_INTERFACE,
                    "no source matching fib configured for ipv4");
                }

              mk4.fib_id = um->tdf_ul_table[FIB_PROTOCOL_IP4][mk4.fib_id];
            }

          if (!is_valid_id (mk4.fib_id))
            {
              if (match_any)
                goto _skip_ip4;

              return upf_sxu_traffic_ep_error_set_by_xid (
                sxu, self_xid, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
                PFCP_IE_SOURCE_INTERFACE, "no fib configured for ipv4");
            }

          el->ref_ue_ip4_xid = sxu_ref_ue_ip_ep4_by_key (sxu, mk4);
        }
    _skip_ip4:

      if (key->is_ip6)
        {
          u16 nwif_fib_id = nwif->rx_fib_index[FIB_PROTOCOL_IP6];
          if (!is_valid_id (nwif_fib_id))
            {
              if (match_any)
                goto _skip_ip6;

              return upf_sxu_traffic_ep_error_set_by_xid (
                sxu, self_xid, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
                PFCP_IE_SOURCE_INTERFACE,
                "no destination matching fib configured for ipv6");
            }

          sxu_ue_ip_ep6_key_t mk6 = {
            .addr = key->ue_addr6,
            .fib_id = nwif_fib_id,
            .is_source_matching = !key->is_destination_ip,
          };

          if (!key->is_destination_ip)
            {
              if (mk6.fib_id >= vec_len (um->tdf_ul_table[FIB_PROTOCOL_IP6]))
                {
                  if (match_any)
                    goto _skip_ip6;

                  return upf_sxu_traffic_ep_error_set_by_xid (
                    sxu, self_xid,
                    PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
                    PFCP_IE_SOURCE_INTERFACE,
                    "no source matching fib configured for ipv6");
                }

              mk6.fib_id = um->tdf_ul_table[FIB_PROTOCOL_IP6][mk6.fib_id];
            }

          if (!is_valid_id (mk6.fib_id))
            {
              if (match_any)
                goto _skip_ip6;

              return upf_sxu_traffic_ep_error_set_by_xid (
                sxu, self_xid, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
                PFCP_IE_SOURCE_INTERFACE, "no fib configured for ipv6");
            }

          el->ref_ue_ip6_xid = sxu_ref_ue_ip_ep6_by_key (sxu, mk6);
        }
    _skip_ip6:

      {
      }
    }

  return 0;
}

static void
_upf_sxu_traffic_endpoint_deinit (upf_sxu_t *sxu, sxu_slot_traffic_ep_t *slot,
                                  u8 self_xid)
{
  sxu_traffic_ep_t *el = &slot->val;
  sxu_traffic_ep_key_t *key = &slot->key;

  sxu_unref_ue_ip_ep4 (sxu, &el->ref_ue_ip4_xid);
  sxu_unref_ue_ip_ep6 (sxu, &el->ref_ue_ip6_xid);

  sxu_unref_gtpu_ep (sxu, &key->ref_gtpu_ep_xid);
  sxu_unref_f_teid_allocation (sxu, &key->ref_f_teid_allocation_xid);
}

static __clib_warn_unused_result int
_upf_sxu_traffic_endpoint_update_if_needed (upf_sxu_t *sxu, u8 self_xid)
{
  sxu_slot_traffic_ep_t *slot = vec_elt_at_index (sxu->traffic_eps, self_xid);
  sxu_slot_state_t *state = &slot->state;

  if (!state->has_existed)
    {
      ASSERT (state->references);

      state->will_exist = 1;
      if (_upf_sxu_traffic_endpoint_init (sxu, slot, self_xid))
        return -1;
    }
  else if (state->has_existed && state->references == 0)
    {
      state->will_exist = 0;
      _upf_sxu_traffic_endpoint_deinit (sxu, slot, self_xid);
    }

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_traffic_endpoint_check_gtpu_ep (upf_sxu_t *sxu, u8 self_xid)
{
  sxu_slot_traffic_ep_t *slot = vec_elt_at_index (sxu->traffic_eps, self_xid);

  if (!slot->state.will_exist)
    return 0;

  if (!slot->key.is_gtpu)
    return 0;

  u8 gtpu_ep_xid;
  if (is_valid_id (slot->key.ref_f_teid_allocation_xid))
    {
      sxu_slot_f_teid_allocation_t *fteida = vec_elt_at_index (
        sxu->f_teid_allocations, slot->key.ref_f_teid_allocation_xid);
      gtpu_ep_xid = fteida->val.ref_gtpu_ep_xid;
    }
  else
    {
      gtpu_ep_xid = slot->key.ref_gtpu_ep_xid;
    }

  sxu_slot_gtpu_ep_t *gtpu_ep = vec_elt_at_index (sxu->gtpu_eps, gtpu_ep_xid);
  if (is_valid_id (gtpu_ep->val.intf))
    {
      // allow only single type of interface per gtpu_ep
      if (gtpu_ep->val.intf != slot->key.intf ||
          gtpu_ep->val.nwi_id != slot->key.nwi_id)
        return upf_sxu_traffic_ep_error_set_by_xid (
          sxu, self_xid, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_SOURCE_INTERFACE,
          "different source interfaces used for the same GTPU endpoint");
    }
  else
    {
      gtpu_ep->val.intf = slot->key.intf;
      gtpu_ep->val.nwi_id = slot->key.nwi_id;
    }
  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_f_teid_allocation_init (upf_sxu_t *sxu,
                                 sxu_slot_f_teid_allocation_t *slot,
                                 u8 self_xid)
{
  upf_main_t *um = &upf_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  sxu_f_teid_allocation_t *el = &slot->val;
  sxu_f_teid_allocation_key_t *key = &slot->key;

  *el = (sxu_f_teid_allocation_t){
    .ref_gtpu_ep_xid = ~0,
  };

  upf_nwi_t *nwi = pool_elt_at_index (um->nwis, key->nwi_id);

  if (!is_valid_id (nwi->gtpu_endpoints_ids[key->intf]))
    return upf_sxu_gtpu_ep_error_set_by_xid (
      sxu, self_xid, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
      PFCP_IE_SOURCE_INTERFACE, "no GTPU endpoint defined for interface type");

  upf_gtpu_endpoint_t *ep =
    pool_elt_at_index (ugm->endpoints, nwi->gtpu_endpoints_ids[key->intf]);

  sxu_gtpu_ep_key_t epk = {
    .gtpu_ep_id = ep - ugm->endpoints,
  };

  u32 retry_cnt = 10;
  do
    {
      epk.teid = upf_gtpu_tunnel_search_free_teid (ep);
      if (epk.teid == 0)
        continue;

      // check that we do not yet allocated such F-TEID for this sxu
      if (!is_valid_id (sxu_get_gtpu_ep_xid_by_key (sxu, epk)))
        break;

      epk.teid = 0;
    }
  while (retry_cnt--);

  if (epk.teid == 0)
    return upf_sxu_gtpu_ep_error_set_by_xid (
      sxu, self_xid, PFCP_CAUSE_NO_RESOURCES_AVAILABLE, PFCP_IE_F_TEID,
      "failed to allocate TEID");

  el->ref_gtpu_ep_xid = sxu_ref_gtpu_ep_by_key (sxu, epk);

  return 0;
}

static void
_upf_sxu_f_teid_allocation_deinit (upf_sxu_t *sxu,
                                   sxu_slot_f_teid_allocation_t *slot,
                                   u8 self_xid)
{
  sxu_f_teid_allocation_t *el = &slot->val;
  // sxu_f_teid_allocation_key_t *key = &slot->key;

  sxu_unref_gtpu_ep (sxu, &el->ref_gtpu_ep_xid);
}

static __clib_warn_unused_result int
_upf_sxu_f_teid_allocation_update_if_needed (upf_sxu_t *sxu, u8 self_xid)
{
  sxu_slot_f_teid_allocation_t *slot =
    vec_elt_at_index (sxu->f_teid_allocations, self_xid);
  sxu_slot_state_t *state = &slot->state;

  if (!state->has_existed)
    {
      ASSERT (state->references);

      state->will_exist = 1;
      if (_upf_sxu_f_teid_allocation_init (sxu, slot, self_xid))
        return -1;
    }
  else if (state->has_existed && state->references == 0)
    {
      state->will_exist = 0;
      _upf_sxu_f_teid_allocation_deinit (sxu, slot, self_xid);
    }

  return 0;
}

static void
_upf_sxu_gtpu_ep_update_if_needed (upf_sxu_t *sxu, u8 self_xid)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  sxu_slot_gtpu_ep_t *slot = vec_elt_at_index (sxu->gtpu_eps, self_xid);
  sxu_slot_state_t *state = &slot->state;

  // will be set again later by _upf_sxu_traffic_endpoint_check_gtpu_ep
  slot->val.intf = ~0;
  slot->val.nwi_id = ~0;

  if (!state->has_existed)
    {
      ASSERT (state->references);

      upf_gtpu_endpoint_t *ep =
        pool_elt_at_index (ugm->endpoints, slot->key.gtpu_ep_id);

      u32 conflicting_session_id =
        upf_gtpu_tunnel_get_session_by_teid (ep, slot->key.teid);

      if (is_valid_id (conflicting_session_id))
        {
          upf_debug ("teid 0x%x for ep %d is taken by sid %d", slot->key.teid,
                     slot->key.gtpu_ep_id, conflicting_session_id);

          _upf_sxu_error_add_session_collision (
            sxu, conflicting_session_id, UPF_SXU_TYPE_gtpu_ep, self_xid);
          // soft fail, will be handled by collision logic
        }

      state->will_exist = 1;
    }
  else if (state->has_existed && state->references == 0)
    state->will_exist = 0;
}

static __clib_warn_unused_result int
_upf_sxu_ue_ip_ep4_init (upf_sxu_t *sxu, sxu_slot_ue_ip_ep4_t *slot,
                         u8 self_xid)
{
  upf_dpo_main_t *udm = &upf_dpo_main;
  sxu_ue_ip_ep4_t *el = &slot->val;
  sxu_ue_ip_ep4_key_t *key = &slot->key;

  *el = (sxu_ue_ip_ep4_t){
    .dpo_result_id = ~0,
  };

  bool match_any = ip4_address_is_zero (&key->addr);
  if (!key->is_source_matching && match_any)
    return upf_sxu_ue_ip_ep4_error_set_by_xid (
      sxu, self_xid, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
      PFCP_IE_UE_IP_ADDRESS,
      "destination matching without ipv4 address is not supported");

  upf_debug ("lookup match4 fib %u ip %U source %u", key->fib_id,
             format_ip4_address, &key->addr, key->is_source_matching);
  index_t existing_index = upf_session_match4_dpo_lookup (
    key->fib_id, key->addr, key->is_source_matching);
  if (is_valid_id (existing_index))
    {
      u32 conflicting_session_id =
        vec_elt_at_index (udm->cp_dpos_results, existing_index)->session_id;

      upf_debug ("address %U in fib %d is taken by sid %d", format_ip4_address,
                 &key->addr, key->fib_id, conflicting_session_id);

      _upf_sxu_error_add_session_collision (sxu, conflicting_session_id,
                                            UPF_SXU_TYPE_ue_ip_ep4, self_xid);
      // soft fail, will be handled by collision logic
    }

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_ue_ip_ep6_init (upf_sxu_t *sxu, sxu_slot_ue_ip_ep6_t *slot,
                         u8 self_xid)
{
  upf_dpo_main_t *udm = &upf_dpo_main;
  sxu_ue_ip_ep6_t *el = &slot->val;
  sxu_ue_ip_ep6_key_t *key = &slot->key;

  *el = (sxu_ue_ip_ep6_t){
    .dpo_result_id = ~0,
  };

  bool match_any = ip6_address_is_zero (&key->addr);
  if (!key->is_source_matching && match_any)
    return upf_sxu_ue_ip_ep6_error_set_by_xid (
      sxu, self_xid, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
      PFCP_IE_UE_IP_ADDRESS,
      "destination matching without ipv4 address is not supported");

  index_t existing_index = upf_session_match6_dpo_lookup (
    key->fib_id, key->addr, key->is_source_matching);
  if (is_valid_id (existing_index))
    {
      u32 conflicting_session_id =
        vec_elt_at_index (udm->cp_dpos_results, existing_index)->session_id;

      upf_debug ("address %U in fib %d is taken by sid %d", format_ip6_address,
                 &key->addr, key->fib_id, conflicting_session_id);

      _upf_sxu_error_add_session_collision (sxu, conflicting_session_id,
                                            UPF_SXU_TYPE_ue_ip_ep6, self_xid);
      return 0; // soft fail, will be handled by collision logic
    }

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_ue_ip_ep4_update_if_needed (upf_sxu_t *sxu, u8 self_xid)
{
  sxu_slot_ue_ip_ep4_t *slot = vec_elt_at_index (sxu->ue_ip_eps4, self_xid);
  sxu_slot_state_t *state = &slot->state;

  if (!state->has_existed)
    {
      ASSERT (state->references);

      state->will_exist = 1;
      if (_upf_sxu_ue_ip_ep4_init (sxu, slot, self_xid))
        return -1;
    }
  else if (state->has_existed && state->references == 0)
    state->will_exist = 0;

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_ue_ip_ep6_update_if_needed (upf_sxu_t *sxu, u8 self_xid)
{
  sxu_slot_ue_ip_ep6_t *slot = vec_elt_at_index (sxu->ue_ip_eps6, self_xid);
  sxu_slot_state_t *state = &slot->state;

  if (!state->has_existed)
    {
      ASSERT (state->references);

      state->will_exist = 1;
      if (_upf_sxu_ue_ip_ep6_init (sxu, slot, self_xid))
        return -1;
    }
  else if (state->has_existed && state->references == 0)
    state->will_exist = 0;

  return 0;
}

static int
_upf_sxu_nat_binding_update_if_needed (upf_sxu_t *sxu, u8 self_xid)
{
  sxu_slot_nat_binding_t *slot =
    vec_elt_at_index (sxu->nat_bindings, self_xid);
  sxu_slot_state_t *state = &slot->state;

  if (!state->has_existed)
    {
      ASSERT (state->references);
      state->will_exist = 1;

      if (!upf_nat_pool_can_allocate (slot->key.pool_id))
        return upf_sxu_nat_binding_error_set_by_xid (
          sxu, self_xid, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_BBF_NAT_PORT_BLOCK, "no blocks left in pool");
    }
  else if (state->has_existed && state->references == 0)
    state->will_exist = 0;

  return 0;
}

static void
_upf_sxu_capture_streams_update_if_needed (upf_sxu_t *sxu)
{
  upf_main_t *um = &upf_main;

  // mark all imsi captures as removed by default
  upf_xid_t imsi_cap_xid;
  vec_foreach_index (imsi_cap_xid, sxu->imsi_captures)
    {
      sxu_slot_imsi_capture_t *slot =
        vec_elt_at_index (sxu->imsi_captures, imsi_cap_xid);
      slot->state.references = 0;
      slot->state.will_exist = 0;
    }

  // mark all streams sets as removed by default
  upf_xid_t cap_set_xid;
  vec_foreach_index (cap_set_xid, sxu->capture_sets)
    {
      sxu_slot_capture_set_t *slot =
        vec_elt_at_index (sxu->capture_sets, cap_set_xid);
      slot->state.references = 0;
      slot->state.will_exist = 0;
    }

  // reset capture_set_xid in nat_bindings
  upf_xid_t nat_binding_xid;
  vec_foreach_index (nat_binding_xid, sxu->nat_bindings)
    {
      sxu_slot_nat_binding_t *nat_binding =
        vec_elt_at_index (sxu->nat_bindings, nat_binding_xid);
      nat_binding->val.capture_set_xid = ~0;
    }

  if (!is_valid_id (sxu->capture_list_id) || ((sxu->is_session_deletion)))
    // no capture is required anymore for this session
    return;

  upf_imsi_capture_list_t *cap_list =
    pool_elt_at_index (um->netcap.capture_lists, sxu->capture_list_id);

  // mark created imsi captures as existing
  upf_llist_foreach (cap, um->netcap.captures, imsi_list_anchor, cap_list)
    {
      sxu_imsi_capture_key_t key = {
        .imsi_capture_id = cap - um->netcap.captures,
      };

      // use ref, since we recrete all keys every update anyways.
      upf_xid_t imsi_cap_xid = sxu_ref_imsi_capture_by_key (sxu, key);
      sxu_slot_imsi_capture_t *slot =
        vec_elt_at_index (sxu->imsi_captures, imsi_cap_xid);
      slot->state.will_exist = 1;
    }

  // walk trough objects which can use capture_set and mark them as existing
  upf_xid_t tep_xid;
  vec_foreach_index (tep_xid, sxu->traffic_eps)
    {
      sxu_slot_traffic_ep_t *tep =
        vec_elt_at_index (sxu->traffic_eps, tep_xid);
      if (!tep->state.will_exist)
        continue;

      sxu_capture_set_key_t key = {
        .nwi_id = tep->key.nwi_id,
        .intf = tep->key.intf,
      };

      upf_xid_t cap_set_xid = sxu_ref_capture_set_by_key (sxu, key);
      sxu_slot_capture_set_t *slot =
        vec_elt_at_index (sxu->capture_sets, cap_set_xid);
      slot->state.will_exist = 1;
    }

  vec_foreach_index (nat_binding_xid, sxu->nat_bindings)
    {
      sxu_slot_nat_binding_t *nat_binding =
        vec_elt_at_index (sxu->nat_bindings, nat_binding_xid);

      if (!nat_binding->state.will_exist)
        continue;

      upf_nat_main_t *unm = &upf_nat_main;
      upf_nat_pool_t *nat_pool =
        pool_elt_at_index (unm->nat_pools, nat_binding->key.pool_id);
      upf_interface_t *nwif =
        pool_elt_at_index (um->nwi_interfaces, nat_pool->nwif_id);

      sxu_capture_set_key_t key = {
        .nwi_id = nwif->nwi_id,
        .intf = nwif->intf,
      };

      upf_xid_t cap_set_xid = sxu_ref_capture_set_by_key (sxu, key);
      sxu_slot_capture_set_t *slot =
        vec_elt_at_index (sxu->capture_sets, cap_set_xid);
      slot->state.will_exist = 1;
      nat_binding->val.capture_set_xid = cap_set_xid;
    }
}

void
_upf_sxu_stats_update_if_needed (upf_sxu_t *sxu)
{
  upf_main_t *um = &upf_main;

  sxu_slot_nwi_stat_t *nwi_stat;
  vec_foreach (nwi_stat, sxu->nwi_stats)
    nwi_stat->state.references = 0;

  sxu_slot_policy_ref_t *fp_ref;
  vec_foreach (fp_ref, sxu->policy_refs)
    fp_ref->state.references = 0;

  sxu_slot_gtpu_ep_stat_t *gtpu_stat;
  vec_foreach (gtpu_stat, sxu->gtpu_ep_stats)
    gtpu_stat->state.references = 0;

  sxu_slot_traffic_ep_t *tep;
  vec_foreach (tep, sxu->traffic_eps)
    {
      if (!tep->state.will_exist)
        continue;

      sxu_nwi_stat_key_t nwi_stat_key = { .nwi_id = tep->key.nwi_id };
      (void) sxu_ref_nwi_stat_by_key (sxu, nwi_stat_key);
    }

  sxu_slot_gtpu_ep_t *ep_gtpu;
  vec_foreach (ep_gtpu, sxu->gtpu_eps)
    {
      if (!ep_gtpu->state.will_exist)
        continue;

      sxu_gtpu_ep_stat_key_t gtpu_stat_key = { .gtpu_ep_id =
                                                 ep_gtpu->key.gtpu_ep_id };
      (void) sxu_ref_gtpu_ep_stat_by_key (sxu, gtpu_stat_key);
    }

  sxu_slot_far_t *far;
  vec_foreach (far, sxu->fars)
    {
      if (!far->state.will_exist)
        continue;

      if (!is_valid_id (far->val.fp.nwi_id))
        continue;

      if (far->val.apply_action != UPF_FAR_ACTION_FORWARD)
        continue;

      sxu_nwi_stat_key_t nwi_stat_key = { .nwi_id = far->val.fp.nwi_id };
      (void) sxu_ref_nwi_stat_by_key (sxu, nwi_stat_key);

      if (far->val.fp.has_outer_header_creation)
        {
          upf_nwi_t *nwi = pool_elt_at_index (um->nwis, far->val.fp.nwi_id);

          u16 gtpu_ep_id =
            nwi->gtpu_endpoints_ids[far->val.fp.destination_interface];
          if (is_valid_id (gtpu_ep_id))
            {
              sxu_gtpu_ep_stat_key_t gtpu_stat_key = { .gtpu_ep_id =
                                                         gtpu_ep_id };
              (void) sxu_ref_gtpu_ep_stat_by_key (sxu, gtpu_stat_key);
            }
        }

      if (is_valid_id (far->val.fp.policy_id))
        {
          sxu_policy_ref_key_t fp_ref_key = { .policy_id =
                                                far->val.fp.policy_id };
          (void) sxu_ref_policy_ref_by_key (sxu, fp_ref_key);
        }
    }

  vec_foreach (nwi_stat, sxu->nwi_stats)
    nwi_stat->state.will_exist = (nwi_stat->state.references != 0);
  vec_foreach (fp_ref, sxu->policy_refs)
    fp_ref->state.will_exist = (fp_ref->state.references != 0);
  vec_foreach (gtpu_stat, sxu->gtpu_ep_stats)
    gtpu_stat->state.will_exist = (gtpu_stat->state.references != 0);
}

/*
Stategy for lid allocation which keeps lid unchanged for existing
objects. Such "lid stability" required for lids referenced in global hashmaps
and other places which can return old state and use old lids. Also, it is
simplifies state transition (URR), by avoiding keeping 2 versions of lids (old
and new).
*/
#define _(name, plural)                                                       \
  static int _upf_sxu_stage_2_remap_lids_##plural (upf_sxu_t *sxu)            \
  {                                                                           \
    upf_xid_t xid;                                                            \
                                                                              \
    /* use i8, so -1 compares properly with clib_max */                       \
    i8 maxid = -1;                                                            \
    /* First reserve all previously existed slots to guarantee lid stability. \
     It is needed to keep endoint id stable in hashmaps, since we can't do    \
     atomic updates. Also to simplify URR state transfer. */                  \
    vec_foreach_index (xid, sxu->plural)                                      \
      {                                                                       \
        sxu_slot_##name##_t *slot = vec_elt_at_index (sxu->plural, xid);      \
        if (slot->state.has_existed && slot->state.will_exist)                \
          {                                                                   \
            upf_lidset_set (&sxu->next_slots.plural, slot->state.lid);        \
            maxid = clib_max (maxid, (i8) slot->state.lid);                   \
          }                                                                   \
      }                                                                       \
    /* Now allocate lids for newly created slots */                           \
    vec_foreach_index (xid, sxu->plural)                                      \
      {                                                                       \
        sxu_slot_##name##_t *slot = vec_elt_at_index (sxu->plural, xid);      \
        if (!slot->state.has_existed && slot->state.will_exist)               \
          {                                                                   \
            upf_lid_t lid =                                                   \
              upf_lidset_get_first_unset_idx (&sxu->next_slots.plural);       \
            slot->state.lid = lid;                                            \
            upf_lidset_set (&sxu->next_slots.plural, lid);                    \
            maxid = clib_max (maxid, (i8) lid);                               \
          }                                                                   \
      }                                                                       \
                                                                              \
    sxu->next_vec_len.plural = maxid + 1;                                     \
    if (sxu->next_vec_len.plural >= UPF_LIDSET_MAX)                           \
      return upf_sxu_##name##_error_set_by_xid (                              \
        sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE, ~0,           \
        "amount of objects is over limit");                                   \
                                                                              \
    return 0;                                                                 \
  }
/* manually list all types which need this method */
_ (urr, urrs)
_ (traffic_ep, traffic_eps)
_ (gtpu_ep, gtpu_eps)
_ (ue_ip_ep4, ue_ip_eps4)
_ (ue_ip_ep6, ue_ip_eps6)
#undef _

/*
Basic strategy for lid allocation which uses first bits. Can't be used in
hashmaps or other global non-atomic references. Can be used in other rules
objects references, since rules upates are atomic.
*/
#define _(name, plural)                                                       \
  static int _upf_sxu_stage_2_remap_lids_##plural (upf_sxu_t *sxu)            \
  {                                                                           \
    upf_xid_t xid;                                                            \
    upf_lid_t next_lid = 0;                                                   \
    vec_foreach_index (xid, sxu->plural)                                      \
      {                                                                       \
        sxu_slot_##name##_t *slot = vec_elt_at_index (sxu->plural, xid);      \
        if (slot->state.will_exist)                                           \
          {                                                                   \
            slot->state.lid = next_lid;                                       \
            next_lid += 1;                                                    \
          }                                                                   \
      }                                                                       \
                                                                              \
    if (next_lid >= UPF_LIDSET_MAX)                                           \
      return upf_sxu_##name##_error_set_by_xid (                              \
        sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE, ~0,           \
        "amount of objects is over limit");                                   \
                                                                              \
    sxu->next_vec_len.plural = next_lid;                                      \
    upf_lidset_set_first_n (&sxu->next_slots.plural, next_lid);               \
    return 0;                                                                 \
  }
/* manually list all types which need this method */
_ (far, fars)
_ (qer, qers)
_ (f_teid_allocation, f_teid_allocations)
_ (capture_set, capture_sets)
#undef _

static upf_sxu_t *__last_pdrs_sort_sxu = NULL;
static int
_sxu_pdr_lids_sort_precedence (void *a1, void *a2)
{
  upf_xid_t xid1 = *((upf_xid_t *) a1), xid2 = *((upf_xid_t *) a2);

  sxu_slot_pdr_t *slot1 = vec_elt_at_index (__last_pdrs_sort_sxu->pdrs, xid1);
  sxu_slot_pdr_t *slot2 = vec_elt_at_index (__last_pdrs_sort_sxu->pdrs, xid2);

  if (slot1->val.precedence < slot2->val.precedence)
    return -1;
  if (slot1->val.precedence > slot2->val.precedence)
    return 1;
  return 0;
}

/*
PDR lids benefit from being sorted by priority for classificaiton.
It is safe, since PDRs are not referenced globally outside of objects in rules.
*/
static int
_upf_sxu_stage_2_remap_lids_pdrs (upf_sxu_t *sxu)
{
  static upf_xid_t *_sort_buf = NULL;
  vec_reset_length (_sort_buf);
  upf_xid_t xid;

  vec_foreach_index (xid, sxu->pdrs)
    {
      sxu_slot_pdr_t *slot = vec_elt_at_index (sxu->pdrs, xid);

      if (slot->state.will_exist)
        vec_add1 (_sort_buf, xid);
    }

  sxu->next_vec_len.pdrs = vec_len (_sort_buf);

  if (vec_len (_sort_buf) >= UPF_LIDSET_MAX)
    {
      return upf_sxu_pdr_error_set_by_xid (
        sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE, ~0,
        "amount of PDRs exceeds limit");
    }
  if (vec_len (_sort_buf) == 0)
    {
      upf_lidset_clear (&sxu->next_slots.pdrs);
      return 0;
    }

  __last_pdrs_sort_sxu = sxu;
  vec_sort_with_function (_sort_buf, _sxu_pdr_lids_sort_precedence);

  upf_lid_t lid;
  vec_foreach_index (lid, _sort_buf)
    {
      upf_xid_t xid = vec_elt (_sort_buf, lid);
      vec_elt_at_index (sxu->pdrs, xid)->state.lid = lid;
    }

  upf_lidset_set_first_n (&sxu->next_slots.pdrs, vec_len (_sort_buf));

  return 0;
}

static int
_upf_sxu_stage_2_remap_lids (upf_sxu_t *sxu)
{
#define _(name, plural)                                                       \
  if (_upf_sxu_stage_2_remap_lids_##plural (sxu))                             \
    return -1;                                                                \
  ASSERT (sxu->next_vec_len.plural ==                                         \
          upf_lidset_count (&sxu->next_slots.plural));
  foreach_sxu_nontemporary_type
#undef _

    return 0;
}

// Check that all non provided objects have no references.
// This covers cases when object was references, but not provided and when
// object dependency was removed.
#define _(name, plural)                                                       \
  static __clib_unused __clib_warn_unused_result int                          \
    _upf_sxu_validate_##plural##_references (upf_sxu_t *sxu)                  \
  {                                                                           \
    sxu_slot_##name##_t *slot;                                                \
    vec_foreach (slot, sxu->plural)                                           \
      {                                                                       \
        /* if will not exist and has references */                            \
        if (!slot->state.will_exist && slot->state.references != 0)           \
          {                                                                   \
            upf_debug ("invalid reference to " #name ": %U",                  \
                       format_sxu_##name##_key, &slot->key);                  \
            upf_sxu_##name##_error_set_by_xid (                               \
              sxu, slot - sxu->plural,                                        \
              PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE, ~0,              \
              "reference to nonexisting object");                             \
            return -1;                                                        \
          }                                                                   \
      }                                                                       \
    return 0;                                                                 \
  }
foreach_sxu_type
#undef _

// provide dynamic objects from keys
int
upf_sxu_stage_2_update_dynamic (upf_sxu_t *sxu)
{
  uword xid;
  // create or remove internal objects

  // start collecting collisions here
  ASSERT (vec_len (sxu->endpoint_conflicts) == 0);

  vec_foreach_index (xid, sxu->traffic_eps)
    if (_upf_sxu_traffic_endpoint_update_if_needed (sxu, xid))
      return -1;

  vec_foreach_index (xid, sxu->f_teid_allocations)
    if (_upf_sxu_f_teid_allocation_update_if_needed (sxu, xid))
      return -1;

  vec_foreach_index (xid, sxu->gtpu_eps)
    _upf_sxu_gtpu_ep_update_if_needed (sxu, xid);

  vec_foreach_index (xid, sxu->ue_ip_eps4)
    if (_upf_sxu_ue_ip_ep4_update_if_needed (sxu, xid))
      return -1;

  vec_foreach_index (xid, sxu->ue_ip_eps6)
    if (_upf_sxu_ue_ip_ep6_update_if_needed (sxu, xid))
      return -1;

  vec_foreach_index (xid, sxu->nat_bindings)
    if (_upf_sxu_nat_binding_update_if_needed (sxu, xid))
      return -1;

  _upf_sxu_stats_update_if_needed (sxu);

  vec_foreach_index (xid, sxu->adf_applications)
    {
      sxu_slot_adf_application_t *slot =
        vec_elt_at_index (sxu->adf_applications, xid);
      sxu_slot_state_t *state = &slot->state;
      if (!state->has_existed)
        {
          ASSERT (state->references);
          state->will_exist = 1;
        }
      else if (state->has_existed && state->references == 0)
        {
          state->will_exist = 0;
        }
    }

  // now check validity

  vec_foreach_index (xid, sxu->traffic_eps)
    if (_upf_sxu_traffic_endpoint_check_gtpu_ep (sxu, xid))
      return -1;

  {
    bool has_binding = false;
    sxu_slot_nat_binding_t *nat_slot;
    vec_foreach (nat_slot, sxu->nat_bindings)
      {
        if (nat_slot->state.will_exist)
          {
            if (has_binding)
              // only single NAT binding is allowed per session
              return upf_sxu_nat_binding_error_set_by_xid (
                sxu, nat_slot - sxu->nat_bindings,
                PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
                PFCP_IE_BBF_NAT_PORT_BLOCK,
                "only single nat block allowed per session");
            has_binding = true;
          }
      }
  }

  // require nwi_id and intf set for gptu and teps
  _upf_sxu_capture_streams_update_if_needed (sxu);

  // check PDRs, FARs and etc as well, since we could have invalid reference
  // between them
#define _(name, plural)                                                       \
  if (_upf_sxu_validate_##plural##_references (sxu))                          \
    return -1;
  foreach_sxu_type
#undef _

  // prepare xid to lid mapping
  if (_upf_sxu_stage_2_remap_lids (sxu))
    return -1;

  if (vec_len (sxu->endpoint_conflicts))
    return -1;

  return 0;
}
