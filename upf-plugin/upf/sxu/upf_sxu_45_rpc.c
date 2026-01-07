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
#include "upf/rules/upf_gtpu.h"
#include "upf/rules/upf_session_dpo.h"
#include "upf/nat/nat.h"
#include "upf/sxu/upf_session_update.h"
#include "upf/upf_stats.h"

#define UPF_DEBUG_ENABLE 0

// Stop directing traffic for old objects and init new ones
void
upf_sxu_stage_4_before_rpc (upf_sxu_t *sxu)
{
  upf_main_t *um = &upf_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  uword xid;

  upf_rules_t *rules = NULL;
  if (is_valid_id (sxu->new_rules_id))
    rules = pool_elt_at_index (um->rules, sxu->new_rules_id);

  vec_foreach_index (xid, sxu->policy_refs)
    {
      sxu_slot_policy_ref_t *slot = vec_elt_at_index (sxu->policy_refs, xid);
      if (!slot->state.has_existed && slot->state.will_exist)
        upf_forwarding_policy_ref (
          pool_elt_at_index (um->forwarding_policies, slot->key.policy_id));
    }

  vec_foreach_index (xid, sxu->nwi_stats)
    {
      sxu_slot_nwi_stat_t *slot = vec_elt_at_index (sxu->nwi_stats, xid);
      if (slot->state.has_existed != slot->state.will_exist)
        {
          if (slot->state.will_exist)
            upf_stats_get_nwi (slot->key.nwi_id)->sessions += 1;
          else
            upf_stats_get_nwi (slot->key.nwi_id)->sessions -= 1;
        }
    }

  vec_foreach_index (xid, sxu->gtpu_ep_stats)
    {
      sxu_slot_gtpu_ep_stat_t *slot =
        vec_elt_at_index (sxu->gtpu_ep_stats, xid);
      if (slot->state.has_existed != slot->state.will_exist)
        {
          if (slot->state.will_exist)
            upf_stats_get_gtpu_endpoint (slot->key.gtpu_ep_id)->sessions += 1;
          else
            upf_stats_get_gtpu_endpoint (slot->key.gtpu_ep_id)->sessions -= 1;
        }
    }

  vec_foreach_index (xid, sxu->ue_ip_eps4)
    {
      sxu_slot_ue_ip_ep4_t *slot = vec_elt_at_index (sxu->ue_ip_eps4, xid);
      sxu_slot_state_t *state = &slot->state;
      sxu_ue_ip_ep4_t *el = &slot->val;

      if (state->has_existed == state->will_exist)
        continue; // no state change

      if (!state->will_exist)
        {
          ASSERT (state->references == 0);
          upf_debug ("match_dpo_del fib %d ip %U source %d", slot->key.fib_id,
                     format_ip4_address, &slot->key.addr,
                     slot->key.is_source_matching);

          if (upf_session_match4_dpo_add_del (
                slot->key.fib_id, slot->key.addr, el->dpo_result_id,
                slot->key.is_source_matching, false))
            ASSERT (0); // TODO: shouldn't happen, but better to handle

          upf_dpo_result_delete (el->dpo_result_id);
          el->dpo_result_id = ~0;
        }
    }

  vec_foreach_index (xid, sxu->ue_ip_eps6)
    {
      sxu_slot_ue_ip_ep6_t *slot = vec_elt_at_index (sxu->ue_ip_eps6, xid);
      sxu_slot_state_t *state = &slot->state;
      sxu_ue_ip_ep6_t *el = &slot->val;

      if (state->has_existed == state->will_exist)
        continue; // no state change

      if (!state->will_exist)
        {
          ASSERT (state->references == 0);
          upf_debug ("match_dpo_del fib %d ip %U source %d", slot->key.fib_id,
                     format_ip4_address, &slot->key.addr,
                     slot->key.is_source_matching);

          if (upf_session_match6_dpo_add_del (
                slot->key.fib_id, slot->key.addr, el->dpo_result_id,
                slot->key.is_source_matching, false))
            ASSERT (0); // TODO: shouldn't happen, but better to handle

          upf_dpo_result_delete (el->dpo_result_id);
          el->dpo_result_id = ~0;
        }
    }

  vec_foreach_index (xid, sxu->gtpu_eps)
    {
      sxu_slot_gtpu_ep_t *slot = vec_elt_at_index (sxu->gtpu_eps, xid);
      sxu_slot_state_t *state = &slot->state;
      // sxu_gtpu_ep_t *gtpu_ep = &slot->val;

      if (state->will_exist)
        continue;

      ASSERT (state->references == 0);

      upf_gtpu_endpoint_t *ep =
        pool_elt_at_index (ugm->endpoints, slot->key.gtpu_ep_id);

      upf_gtpu_endpoint_tunnel_delete (ep, slot->key.teid);
    }

  if (vec_len (sxu->capture_sets) && vec_len (sxu->imsi_captures))
    {
      u8 *common_metadata = NULL;
      upf_session_t *sx = pool_elt_at_index (um->sessions, sxu->session_id);

      clib_error_t *err = um->netcap.methods.add_metadata (
        &common_metadata, "imsi", sx->user_id.imsi,
        (u16) sizeof (sx->user_id.imsi));
      if (err)
        {
          clib_warning ("failed to add metadata 'imsi': %U", format_clib_error,
                        err);
          ASSERT (0);
          vec_free (common_metadata);
        }

      upf_xid_t cap_set_xid;
      vec_foreach_index (cap_set_xid, sxu->capture_sets)
        {
          upf_xid_t imsi_cap_xid;
          sxu_slot_capture_set_t *u_cap_set =
            vec_elt_at_index (sxu->capture_sets, cap_set_xid);

          if (!u_cap_set->state.will_exist)
            continue;

          rules_netcap_set_t *r_cap_set =
            upf_rules_get_netcap_set (rules, u_cap_set->state.lid);

          u8 *metadata = vec_dup (common_metadata);

          upf_nwi_t *nwi = pool_elt_at_index (um->nwis, u_cap_set->key.nwi_id);

          u8 *nwi_name = format (NULL, "%U", format_upf_nwi_name, nwi->name);

          err = um->netcap.methods.add_metadata (
            &metadata, "nwi", nwi_name,
            (u16) strnlen ((char *) nwi_name, vec_len (nwi_name)));
          if (err)
            {
              clib_warning ("failed to add metadata 'nwi': %v: %U", nwi_name,
                            format_clib_error, err);
              ASSERT (0);
            }

          err = um->netcap.methods.add_metadata (
            &metadata, "src_intf", (u8 *) &u_cap_set->key.intf,
            (u16) sizeof (pfcp_ie_source_interface_t));
          if (err)
            {
              clib_warning ("failed to add metadata 'src_intf': %d: %U",
                            (int) u_cap_set->key.intf, format_clib_error, err);
              ASSERT (0);
            }

          u8 *iface_name =
            format (NULL, "%U-%U-%U", format_pfcp_tbcd, &sx->user_id.imsi,
                    sizeof (sx->user_id.imsi), nwi_name,
                    format_upf_interface_type, u_cap_set->key.intf);

          vec_foreach_index (imsi_cap_xid, sxu->imsi_captures)
            {
              sxu_slot_imsi_capture_t *imsi_cap =
                vec_elt_at_index (sxu->imsi_captures, imsi_cap_xid);

              if (!imsi_cap->state.will_exist)
                continue;

              bool stream_existed =
                imsi_cap->state.has_existed && u_cap_set->state.has_existed;

              bool actually_existed = false;
              rules_netcap_stream_t *stream;
              vec_foreach (stream, r_cap_set->streams)
                {
                  if (stream->imsi_capture_id == imsi_cap->key.imsi_capture_id)
                    {
                      ASSERT (!actually_existed);
                      actually_existed = true;
                    }
                }
              ASSERT (actually_existed == stream_existed);
              if (stream_existed)
                // nothing to do here
                continue;

              upf_imsi_capture_t *request = pool_elt_at_index (
                um->netcap.captures, imsi_cap->key.imsi_capture_id);

              netcap_stream_id_t netcap_stream_id = ~0;
              err = um->netcap.methods.create_stream (
                &netcap_stream_id, um->netcap.class_session_ip, iface_name,
                request->target, metadata);
              if (err)
                {
                  clib_warning ("failed to create stream %v for %v: %U",
                                iface_name, request->target, format_clib_error,
                                err);
                  ASSERT (0);
                }
              else
                {
                  rules_netcap_stream_t rule_stream = {
                    .netcap_stream_id = netcap_stream_id,
                    .imsi_capture_id = imsi_cap->key.imsi_capture_id,
                    .packet_max_bytes = request->packet_max_bytes,
                  };
                  vec_add1 (r_cap_set->streams, rule_stream);
                  rules->want_netcap = vec_len (sxu->capture_sets) != 0;
                }
            }

          vec_free (iface_name);
          vec_free (nwi_name);
          vec_free (metadata);
        }
      vec_free (common_metadata);
    }
}

// Finally cleanup old objects and start directing traffic for new ones
void
upf_sxu_stage_5_after_rpc (upf_sxu_t *sxu)
{
  upf_main_t *um = &upf_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  uword xid;

  vec_foreach_index (xid, sxu->policy_refs)
    {
      sxu_slot_policy_ref_t *slot = vec_elt_at_index (sxu->policy_refs, xid);
      if (slot->state.has_existed && !slot->state.will_exist)
        upf_forwarding_policy_unref (
          pool_elt_at_index (um->forwarding_policies, slot->key.policy_id));
    }

  vec_foreach_index (xid, sxu->pdrs)
    {
      sxu_slot_pdr_t *slot = vec_elt_at_index (sxu->pdrs, xid);
      sxu_slot_state_t *state = &slot->state;
      sxu_pdr_t *el = &slot->val;

      if ((state->has_existed && !el->do_reuse_acls) || (!state->will_exist))
        {
          // free old acls if they existed and will not be reused
          if (is_valid_id (el->_old_acl_cached_id))
            upf_acl_cache_unref_by_id (el->_old_acl_cached_id);
        }
    }

  vec_foreach_index (xid, sxu->ue_ip_eps4)
    {
      sxu_slot_ue_ip_ep4_t *slot = vec_elt_at_index (sxu->ue_ip_eps4, xid);
      sxu_slot_state_t *state = &slot->state;
      sxu_ue_ip_ep4_t *el = &slot->val;

      // if created
      if (state->will_exist && !state->has_existed)
        {
          ASSERT (state->references);
          upf_dpo_result_activate (el->dpo_result_id);
        }
    }
  vec_foreach_index (xid, sxu->ue_ip_eps6)
    {
      sxu_slot_ue_ip_ep6_t *slot = vec_elt_at_index (sxu->ue_ip_eps6, xid);
      sxu_slot_state_t *state = &slot->state;
      sxu_ue_ip_ep6_t *el = &slot->val;

      // if created
      if (state->will_exist && !state->has_existed)
        {
          ASSERT (state->references);
          upf_dpo_result_activate (el->dpo_result_id);
        }
    }

  vec_foreach_index (xid, sxu->gtpu_eps)
    {
      sxu_slot_gtpu_ep_t *slot = vec_elt_at_index (sxu->gtpu_eps, xid);
      sxu_slot_state_t *state = &slot->state;

      if (state->has_existed == state->will_exist)
        continue; // no state change

      if (state->will_exist)
        {
          ASSERT (state->references);

          upf_gtpu_endpoint_t *ep =
            pool_elt_at_index (ugm->endpoints, slot->key.gtpu_ep_id);
          upf_gtpu_endpoint_tunnel_activate (
            ep, slot->key.teid, sxu->session_id, sxu->session_generation,
            sxu->thread_id, state->lid);
        }
    }

  vec_foreach_index (xid, sxu->nat_bindings)
    {
      sxu_slot_nat_binding_t *slot = vec_elt_at_index (sxu->nat_bindings, xid);
      sxu_slot_state_t *state = &slot->state;

      if (state->will_exist)
        continue;

      ASSERT (state->references == 0);
      upf_nat_binding_delete (slot->val.binding_id);
      slot->val.binding_id = ~0;
    }

  upf_xid_t cap_set_xid;
  vec_foreach_index (cap_set_xid, sxu->capture_sets)
    {
      sxu_slot_capture_set_t *cap_set =
        vec_elt_at_index (sxu->capture_sets, cap_set_xid);

      if (!cap_set->state.has_existed)
        continue; // nothing to remove

      upf_xid_t imsi_cap_xid;
      vec_foreach_index (imsi_cap_xid, sxu->imsi_captures)
        {
          sxu_slot_imsi_capture_t *imsi_cap =
            vec_elt_at_index (sxu->imsi_captures, imsi_cap_xid);

          if (!imsi_cap->state.has_existed)
            continue; // nothing to remove

          if (cap_set->state.will_exist && imsi_cap->state.will_exist)
            continue; // no state change

          netcap_stream_id_t netcap_stream_id =
            vec_elt (cap_set->val.capture_streams, imsi_cap_xid);
          ASSERT (is_valid_id (netcap_stream_id));

          um->netcap.methods.delete_stream (netcap_stream_id);
        }
    }
}
