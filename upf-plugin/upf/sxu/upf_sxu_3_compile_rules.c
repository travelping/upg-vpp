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
#include "upf/rules/upf_ipfilter.h"
#include "upf/integrations/upf_ipfix.h"
#include "upf/sxu/upf_session_update.h"
#include "upf/rules/upf_session_dpo.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/nat/nat.h"

#define UPF_DEBUG_ENABLE 0

#define _remap_to_lid(plural, xid)                                            \
  ({                                                                          \
    upf_lid_t lid;                                                            \
    if (!is_valid_id (xid))                                                   \
      lid = -1;                                                               \
    else                                                                      \
      {                                                                       \
        sxu_slot_state_t *state =                                             \
          &vec_elt_at_index (sxu->plural, xid)->state;                        \
        ASSERT (state->will_exist);                                           \
        lid = state->lid;                                                     \
      }                                                                       \
    lid;                                                                      \
  })

static void
_upf_sxu_stage_3_compile_pdr (upf_sxu_t *sxu, u8 xid, sxu_slot_pdr_t *slot,
                              rules_pdr_t *result, bool *took_barrier)
{
  sxu_pdr_t *el = &slot->val;
  sxu_slot_traffic_ep_t *tep =
    vec_elt_at_index (sxu->traffic_eps, el->pdi.ref_traffic_ep_xid);

  bool far_redirect_http = false;
  if (is_valid_id (el->ref_far_xid))
    {
      sxu_slot_far_t *far = vec_elt_at_index (sxu->fars, el->ref_far_xid);
      upf_lidset_set (&far->val._pdr_lids, slot->state.lid);
      if (tep->key.is_ip4)
        far->val._is_ip4 = 1;
      if (tep->key.is_ip6)
        far->val._is_ip6 = 1;

      if (far->val.apply_action == UPF_FAR_ACTION_FORWARD &&
          far->val.fp.redirect_information.type ==
            PFCP_REDIRECT_INFORMATION_HTTP)
        far_redirect_http = true;
    }

  // From 5.2.1A.2A of TS 29.244
  // > when the Source Interface is ACCESS, this indicates that the
  // > filter is for uplink data flow
  bool is_uplink = el->pdi.source_interface == PFCP_SRC_INTF_ACCESS;

  upf_debug ("src if %U is_uplink=%d tep->is_destination_ip=%d",
             format_pfcp_ie_source_interface, &el->pdi.source_interface,
             is_uplink, tep->key.is_destination_ip);

  // This is should and is validated during tep key creation
  if (tep->key.is_ip4 || tep->key.is_ip6)
    ASSERT (tep->key.is_destination_ip != is_uplink);

  // what kind of traffic we can receive
  bool is_tep_can_ip_any = tep->key.is_ip4 == tep->key.is_ip6;
  bool is_tep_can_ip4 = is_tep_can_ip_any || tep->key.is_ip4;
  bool is_tep_can_ip6 = is_tep_can_ip_any || tep->key.is_ip6;

  rules_pdr_t pdr = {};
  pdr.pfcp_id = slot->key;
  pdr.is_uplink = is_uplink;
  pdr.need_http_redirect = far_redirect_http;
  pdr.gtpu_outer_header_removal = el->gtpu_outer_header_removal;
  pdr.far_lid = _remap_to_lid (fars, el->ref_far_xid);
  pdr.precedence = el->precedence;
  pdr.traffic_ep_lid = _remap_to_lid (traffic_eps, el->pdi.ref_traffic_ep_xid);

  upf_lidset_foreach (xid, &el->refs_urr_xids)
    upf_lidset_set (&pdr.urr_lids, _remap_to_lid (urrs, xid));
  upf_lidset_foreach (xid, &el->refs_qer_xids)
    upf_lidset_set (&pdr.qer_lids, _remap_to_lid (qers, xid));

  pdr.nwi_id = el->pdi.nwi_id;
  pdr.src_intf = el->pdi.source_interface;
  pdr.can_recv_ip4 = is_tep_can_ip4;
  pdr.can_recv_ip6 = is_tep_can_ip6;

  pdr.application_id = ~0;
  if (is_valid_id (el->pdi.ref_application_xid))
    {
      sxu_slot_adf_application_t *app =
        vec_elt_at_index (sxu->adf_applications, el->pdi.ref_application_xid);
      pdr.application_id = app->key.application_id;
    }

  if (el->do_reuse_acls)
    {
      pdr.acl_cached_id = el->_old_acl_cached_id;
    }
  else if (!vec_len (el->pdi.sdf_filters_new))
    {
      pdr.acl_cached_id = ~0;
    }
  else
    {
      // to have proper cache hit
      upf_ipfilter_vec_sort (el->pdi.sdf_filters_new);

      pdr.acl_cached_id =
        upf_acl_cache_ref_from_rules (el->pdi.sdf_filters_new);

      el->pdi.sdf_filters_new = NULL; // consumed by cache
    }

  if (is_valid_id (pdr.acl_cached_id))
    {
      if (is_tep_can_ip4)
        pdr.acls4 = upf_acl_cache_ensure4 (pdr.acl_cached_id);

      if (is_tep_can_ip6)
        pdr.acls6 = upf_acl_cache_ensure6 (pdr.acl_cached_id);
    }

  *result = pdr;
}

static void
_upf_sxu_stage_3_compile_traffic_ep (upf_sxu_t *sxu, u8 xid,
                                     sxu_slot_traffic_ep_t *slot,
                                     rules_tep_t *result)
{
  sxu_traffic_ep_t *el = &slot->val;

  rules_tep_t tep = {
    .capture_set_lid = ~0,
  };
  tep.is_destination_ip = slot->key.is_destination_ip;
  tep.is_gtpu = slot->key.is_gtpu;
  tep.is_ue_ip4 = slot->key.is_ip4;
  tep.is_ue_ip6 = slot->key.is_ip6;
  tep.nwi_id = slot->key.nwi_id;
  tep.intf = slot->key.intf;
  if (slot->key.is_gtpu)
    {
      u8 f_teid_a_xid = slot->key.ref_f_teid_allocation_xid;

      if (is_valid_id (f_teid_a_xid))
        {
          sxu_slot_f_teid_allocation_t *f_teid_a = vec_elt_at_index (
            sxu->f_teid_allocations, slot->key.ref_f_teid_allocation_xid);

          tep.match.gtpu.fteid_allocation_lid = _remap_to_lid (
            f_teid_allocations, slot->key.ref_f_teid_allocation_xid);
          tep.match.gtpu.gtpu_ep_lid =
            _remap_to_lid (gtpu_eps, f_teid_a->val.ref_gtpu_ep_xid);
        }
      else
        {
          tep.match.gtpu.fteid_allocation_lid = ~0;
          tep.match.gtpu.gtpu_ep_lid =
            _remap_to_lid (gtpu_eps, slot->key.ref_gtpu_ep_xid);
        }
    }
  else
    {
      tep.match.ip.traffic_ep4_lid =
        _remap_to_lid (ue_ip_eps4, el->ref_ue_ip4_xid);
      tep.match.ip.traffic_ep6_lid =
        _remap_to_lid (ue_ip_eps6, el->ref_ue_ip6_xid);
    }
  tep.ue_addr4 = slot->key.ue_addr4;
  tep.ue_addr6 = slot->key.ue_addr6;

  *result = tep;
}

static void
_upf_sxu_stage_3_compile_far (upf_sxu_t *sxu, u8 xid, sxu_slot_far_t *slot,
                              rules_far_t *result)
{
  upf_main_t *um = &upf_main;

  sxu_far_t *el = &slot->val;

  rules_far_t far = {};

  bool is_forward = el->apply_action == UPF_FAR_ACTION_FORWARD;

  far.pfcp_id = slot->key;
  far.ipfix_policy_set = el->ipfix_policy;
  far.ipfix_policy_used = UPF_IPFIX_POLICY_NONE;
  far.ipfix_context4_id = ~0;
  far.ipfix_context6_id = ~0;
  far.apply_action = el->apply_action;

  rules_far_forward_t *ff = &far.forward;

  ff->nwi_id = el->fp.nwi_id;
  ff->dst_intf = el->fp.destination_interface;
  ff->forwarding_policy_id = el->fp.policy_id;

  ff->do_send_end_marker = el->fp.do_send_end_marker;
  ff->has_outer_header_creation = el->fp.has_outer_header_creation;
  ff->has_redirect_information = el->fp.has_redirect_information;
  if (el->fp.has_redirect_information)
    ff->redirect_uri = vec_dup (el->fp.redirect_information.uri);

  ff->has_forwarding_policy = is_valid_id (el->fp.policy_id);
  ff->do_nat = is_forward && el->fp.bbf_apply_action_nat;

  upf_nwi_t *nwi;
  if (is_forward)
    nwi = pool_elt_at_index (um->nwis, el->fp.nwi_id);

  if (el->fp.has_outer_header_creation)
    {
      ASSERT (el->fp.ohc.teid);

      ff->ohc.teid = el->fp.ohc.teid;
      ff->ohc.addr4 = el->fp.ohc.addr4;
      ff->ohc.addr6 = el->fp.ohc.addr6;

      ff->has_outer_addr4 = !ip4_address_is_zero (&el->fp.ohc.addr4);
      ff->has_outer_addr6 = !ip6_address_is_zero (&el->fp.ohc.addr6);

      if (is_forward)
        {
          u16 gtpu_ep_id =
            nwi->gtpu_endpoints_ids[el->fp.destination_interface];

          // this is be verified before, during ohc parsing
          ASSERT (is_valid_id (gtpu_ep_id));

          ff->ohc.src_gtpu_endpoint_id = gtpu_ep_id;
        }
    }

  if (is_forward)
    {
      u32 nwif_id = upf_nwi_get_interface_id (nwi, ff->dst_intf);
      upf_interface_t *nwif = pool_elt_at_index (um->nwi_interfaces, nwif_id);

      far.ipfix_policy_used = el->ipfix_policy;
      if (far.ipfix_policy_used == UPF_IPFIX_POLICY_UNSPECIFIED)
        far.ipfix_policy_used = nwif->ipfix.default_policy;
      ASSERT (far.ipfix_policy_used != UPF_IPFIX_POLICY_UNSPECIFIED);

      if (far.ipfix_policy_used != UPF_IPFIX_POLICY_NONE)
        {
          upf_ipfix_context_key_t context_key = {};
          if (el->_is_ip4 || el->_is_ip6)
            {
              ip_address_copy (&context_key.collector_ip,
                               &nwif->ipfix.collector_ip);
              context_key.observation_domain_id =
                nwif->ipfix.observation_domain_id;
              context_key.policy = far.ipfix_policy_used;
            }
          if (el->_is_ip4)
            {
              context_key.is_ip4 = true;
              far.ipfix_context4_id = upf_ipfix_ensure_context (&context_key);
            }
          if (el->_is_ip6)
            {
              context_key.is_ip4 = false;
              far.ipfix_context6_id = upf_ipfix_ensure_context (&context_key);
            }
        }
    }

  *result = far;
}

static void
_upf_sxu_stage_3_compile_urr (upf_sxu_t *sxu, u8 xid, sxu_slot_urr_t *slot,
                              upf_time_t now, rules_urr_t *result)
{
  sxu_urr_t *el = &slot->val;

  rules_urr_t urr = (rules_urr_t){};

  urr.pfcp_id = slot->key;
  urr.enabled_triggers = el->reporting_triggers;
  urr.measurement_method_volume = el->measurement_method_volume;
  urr.measurement_method_duration = el->measurement_method_duration;
  urr.measurement_method_event = el->measurement_method_event;
  urr.update_flags = el->update_flags;

  urr.has_quota_ul = el->has_volume_quota_ul;
  urr.has_quota_dl = el->has_volume_quota_dl;
  urr.has_quota_tot = el->has_volume_quota_tot;
  urr.has_quota_time = el->has_time_quota;

  urr.vol.quota_set.ul = el->volume_quota_ul;
  urr.vol.quota_set.dl = el->volume_quota_dl;
  urr.vol.quota_set.tot = el->volume_quota_total;
  urr.vol.threshold_set.ul = el->volume_threshold_ul;
  urr.vol.threshold_set.dl = el->volume_threshold_dl;
  urr.vol.threshold_set.tot = el->volume_threshold_total;

  urr.time.threshold_set = el->time_threshold;
  urr.time.quota_set = el->time_quota;

  urr.measurement_period.period = el->measurement_period;
  urr.quota_holding_time.period = el->quota_holding_time;
  urr.quota_validity_time.period = el->quota_validity_time;
  urr.monitoring_time = el->monitoring_time;

  // LIUSA is done later

  *result = urr;
}

static u32
_pfcp_ie_bit_rate_to_bps (u64 rate)
{
  // Convert kilobits per second to bytes per second with rounding up
  // Limit incoming mbr to 2^31 so it fit in u32
  // This means that maximum representable value is 2 gigabyte per second
  // Incoming value can't be bigger then (((2^31) * 8) / 1000) = 17179869 to
  // not break math
  if (rate > 17179869)
    return 2147483648;
  else
    return ((rate * 1000) + 7) / 8;
}

#define QER_MAXIMUM_BURST_SIZE_BYTES 10000

static void
_upf_sxu_stage_3_compile_qer (upf_sxu_t *sxu, u8 xid, sxu_slot_qer_t *slot,
                              upf_time_t now, rules_qer_t *result)
{
  sxu_qer_t *el = &slot->val;

  rules_qer_t qer = (rules_qer_t){};
  qer.pfcp_id = slot->key;
  qer.gate_closed_ul = el->gate_closed_ul;
  qer.gate_closed_dl = el->gate_closed_dl;
  qer.has_mbr = el->has_maximum_bitrate;
  if (el->has_maximum_bitrate)
    {
      for (upf_dir_t dir = 0; dir < UPF_N_DIR; dir++)
        {
          qer.maximum_bitrate[dir] = el->maximum_bitrate[dir];

          u32 bps = _pfcp_ie_bit_rate_to_bps (el->maximum_bitrate[dir]);
          upf_debug ("rate %d => %d bps", el->maximum_bitrate[dir], bps);
          tokenbucket_init (&qer.policer_bytes[dir], 0, bps,
                            QER_MAXIMUM_BURST_SIZE_BYTES);
          upf_debug ("fill_time: %d/%d = %.6f", QER_MAXIMUM_BURST_SIZE_BYTES,
                     bps, qer.policer_bytes[dir].fill_time);
        }
    }

  *result = qer;
}

static void
_upf_sxu_stage_3_update_pdr_lidsets (
  upf_sxu_t *sxu, upf_rules_t *rules, rules_pdr_t *pdrs_vec,
  rules_urr_t *urrs_vec, rules_tep_t *teps_vec, rules_ep_gtpu_t *gtpu_eps_vec,
  rules_ep_ip_t *ue_ips4_vec, rules_ep_ip_t *ue_ips6_vec)
{
  // Set used PDRs per GTPU/IP endpoint. For faster iteration over needed
  // PDRs
  upf_lidset_foreach (pdr_lid, &sxu->next_slots.pdrs)
    {
      rules_pdr_t *pdr = vec_elt_at_index (pdrs_vec, pdr_lid);

      pdr->has_event_urrs = false;
      bool pdr_has_start_of_traffic_report = false;

      upf_lidset_foreach (urr_lid, &pdr->urr_lids)
        {
          rules_urr_t *urr = vec_elt_at_index (urrs_vec, urr_lid);
          if (urr->measurement_method_event)
            {
              pdr->has_event_urrs = true;
              if (urr->enabled_triggers &
                  PFCP_REPORTING_TRIGGER_START_OF_TRAFFIC)
                pdr_has_start_of_traffic_report = 1;
            }
          if (urr->measurement_method_volume)
            upf_lidset_set (&pdr->volume_urr_lids, urr_lid);
          urr->has_pdr_references = 1;
        }

      if (pdr->is_uplink)
        upf_lidset_set (&rules->pdr_ul_lids, pdr_lid);

      rules_tep_t *tep = vec_elt_at_index (teps_vec, pdr->traffic_ep_lid);

      if (pdr->can_recv_ip4)
        upf_lidset_set (&rules->pdr_ip4_lids, pdr_lid);
      if (pdr->can_recv_ip6)
        upf_lidset_set (&rules->pdr_ip6_lids, pdr_lid);

      if (tep->is_gtpu)
        {
          rules_ep_gtpu_t *gtpu_ep =
            vec_elt_at_index (gtpu_eps_vec, tep->match.gtpu.gtpu_ep_lid);
          upf_lidset_set (&gtpu_ep->pdr_lids, pdr_lid);
        }
      else
        {
          if (is_valid_id (tep->match.ip.traffic_ep4_lid))
            {
              rules_ep_ip_t *ueip4 =
                vec_elt_at_index (ue_ips4_vec, tep->match.ip.traffic_ep4_lid);
              ueip4->traffic_ep_lid = pdr->traffic_ep_lid;
              upf_lidset_set (&rules->pdr_ip4_lids, pdr_lid);
              upf_lidset_set (&ueip4->pdr_lids, pdr_lid);
            }
          if (is_valid_id (tep->match.ip.traffic_ep6_lid))
            {
              rules_ep_ip_t *ueip6 =
                vec_elt_at_index (ue_ips6_vec, tep->match.ip.traffic_ep6_lid);
              ueip6->traffic_ep_lid = pdr->traffic_ep_lid;
              upf_lidset_set (&rules->pdr_ip6_lids, pdr_lid);
              upf_lidset_set (&ueip6->pdr_lids, pdr_lid);
            }
          if (pdr_has_start_of_traffic_report)
            {
              if (ip4_address_is_zero (&tep->ue_addr4) &&
                  ip6_address_is_zero (&tep->ue_addr6))
                pdr->is_tdf_unsolicited = 1;
            }
        }
    }
}

static void
_upf_sxu_stage_3_update_urr_lidsets (upf_sxu_t *sxu, rules_urr_t *urrs_vec)
{
  upf_xid_t xid;
  vec_foreach_index (xid, sxu->urrs)
    {
      sxu_slot_urr_t *slot = vec_elt_at_index (sxu->urrs, xid);

      upf_debug ("will exist %d has_existed %d", slot->state.will_exist,
                 slot->state.has_existed);
      if (slot->state.will_exist != slot->state.has_existed)
        {
          if (slot->state.will_exist)
            upf_lidset_set (&sxu->created_urr_lids, slot->state.lid);
          else
            upf_lidset_set (&sxu->removed_urr_lids, slot->state.lid);
        }

      if (!slot->state.will_exist)
        continue;

      upf_lidset_foreach (main_xid, &slot->val.refs_linked_urr_xids)
        {
          sxu_slot_urr_t *main_slot = vec_elt_at_index (sxu->urrs, main_xid);
          if (!slot->state.will_exist)
            {
              clib_warning ("BUG: URR liusa link reference is removed");
              ASSERT (0);
              continue;
            }

          // reverse reference from linked=>main to main=>linked for faster
          // iteration during report
          rules_urr_t *main_urr =
            vec_elt_at_index (urrs_vec, main_slot->state.lid);
          upf_lidset_set (&main_urr->liusa_urrs_lids, slot->state.lid);
        }
    }
}

// At this point we should have validated all objects and are sure that all
// objects are valid and we should be able to create them.
void
upf_sxu_stage_3_compile_rules (upf_sxu_t *sxu)
{
  upf_main_t *um = &upf_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  uword xid;

  bool took_barrier = false;
  sxu->is_compiled = 1;

  if (sxu->is_session_deletion)
    return;

  upf_rules_t *rules;

  if (pool_get_will_expand (um->rules))
    {
      took_barrier = true;
      vlib_worker_thread_barrier_sync (vlib_get_main ());
    }

  bool flowless_optimization = true;

  pool_get_zero (um->rules, rules);

  sxu->new_rules_id = rules - um->rules;

  rules->nat_binding_id = ~0;
  rules->nat_pool_id = ~0;
  rules->nat_netcap_set_lid = ~0;
  rules->inactivity_timeout = sxu->inactivity_timeout;

  static rules_pdr_t *_pdrs_vec = NULL;
  vec_resize (_pdrs_vec, sxu->next_vec_len.pdrs);
  vec_foreach_index (xid, sxu->pdrs)
    {
      sxu_slot_pdr_t *slot = vec_elt_at_index (sxu->pdrs, xid);

      if (!slot->state.will_exist)
        continue;

      if (!slot->state.has_existed)
        upf_lidset_set (&sxu->created_pdr_lids, slot->state.lid);

      if (is_valid_id (slot->val.pdi.ref_application_xid))
        // may require proxy for DPI
        flowless_optimization = false;

      rules_pdr_t *pdr = vec_elt_at_index (_pdrs_vec, slot->state.lid);
      _upf_sxu_stage_3_compile_pdr (sxu, xid, slot, pdr, &took_barrier);
    }

  static rules_tep_t *_teps_vec = NULL;
  vec_resize (_teps_vec, sxu->next_vec_len.traffic_eps);
  vec_foreach_index (xid, sxu->traffic_eps)
    {
      sxu_slot_traffic_ep_t *slot = vec_elt_at_index (sxu->traffic_eps, xid);

      if (!slot->state.will_exist)
        continue;

      rules_tep_t *tep = vec_elt_at_index (_teps_vec, slot->state.lid);
      _upf_sxu_stage_3_compile_traffic_ep (sxu, xid, slot, tep);
    }

  static rules_f_teid_t *_f_teids_vec = NULL;
  vec_resize (_f_teids_vec, sxu->next_vec_len.f_teid_allocations);
  vec_foreach_index (xid, sxu->f_teid_allocations)
    {
      sxu_slot_f_teid_allocation_t *slot =
        vec_elt_at_index (sxu->f_teid_allocations, xid);
      sxu_f_teid_allocation_t *el = &slot->val;

      if (!slot->state.will_exist)
        continue;

      rules_f_teid_t fteid = {};
      fteid.choose_id = slot->key.choose_id;
      fteid.nwi_id = slot->key.nwi_id;
      fteid.intf = slot->key.intf;
      fteid.gtpu_endpoint_lid = _remap_to_lid (gtpu_eps, el->ref_gtpu_ep_xid);

      *vec_elt_at_index (_f_teids_vec, slot->state.lid) = fteid;
    }

  static rules_ep_gtpu_t *_ep_gtpus_vec = NULL;
  vec_resize (_ep_gtpus_vec, sxu->next_vec_len.gtpu_eps);
  vec_foreach_index (xid, sxu->gtpu_eps)
    {
      sxu_slot_gtpu_ep_t *slot = vec_elt_at_index (sxu->gtpu_eps, xid);

      if (!slot->state.will_exist)
        continue;

      if (!slot->state.has_existed)
        {
          upf_gtpu_endpoint_t *ep =
            pool_elt_at_index (ugm->endpoints, slot->key.gtpu_ep_id);
          upf_gtpu_endpoint_tunnel_create (ep, slot->key.teid, sxu->session_id,
                                           sxu->session_generation,
                                           sxu->thread_id, slot->state.lid);
        }

      rules_ep_gtpu_t gtpu_ep = {};
      gtpu_ep.teid = slot->key.teid;
      gtpu_ep.gtpu_ep_id = slot->key.gtpu_ep_id;
      gtpu_ep.is_uplink = slot->val.intf == UPF_INTERFACE_TYPE_ACCESS;

      *vec_elt_at_index (_ep_gtpus_vec, slot->state.lid) = gtpu_ep;
    }

  static rules_ep_ip_t *_ep_ips4_vec = NULL;
  vec_resize (_ep_ips4_vec, sxu->next_vec_len.ue_ip_eps4);
  vec_foreach_index (xid, sxu->ue_ip_eps4)
    {
      sxu_slot_ue_ip_ep4_t *slot = vec_elt_at_index (sxu->ue_ip_eps4, xid);
      sxu_ue_ip_ep4_t *el = &slot->val;

      if (!slot->state.will_exist)
        continue;

      rules_ep_ip_t ue_ip4 = {};
      ue_ip4.fib_index = slot->key.fib_id;
      ue_ip4.is_ue_side = slot->key.is_source_matching;

      if (!slot->state.has_existed)
        {
          ASSERT (slot->state.references != 0);
          el->dpo_result_id = upf_dpo_result_create (
            sxu->thread_id, sxu->session_id, sxu->session_generation,
            slot->state.lid, slot->key.is_source_matching);

          if (upf_session_match4_dpo_add_del (
                slot->key.fib_id, slot->key.addr, el->dpo_result_id,
                slot->key.is_source_matching, true))
            ASSERT (0);
        }
      ue_ip4.dpo_result_id = el->dpo_result_id;

      *vec_elt_at_index (_ep_ips4_vec, slot->state.lid) = ue_ip4;
    }

  static rules_ep_ip_t *_ep_ips6_vec = NULL;
  vec_resize (_ep_ips6_vec, sxu->next_vec_len.ue_ip_eps6);
  vec_foreach_index (xid, sxu->ue_ip_eps6)
    {
      sxu_slot_ue_ip_ep6_t *slot = vec_elt_at_index (sxu->ue_ip_eps6, xid);
      sxu_ue_ip_ep6_t *el = &slot->val;

      if (!slot->state.will_exist)
        continue;

      rules_ep_ip_t ue_ip6 = {};
      ue_ip6.fib_index = slot->key.fib_id;
      ue_ip6.is_ue_side = slot->key.is_source_matching;

      if (!slot->state.has_existed)
        {
          ASSERT (slot->state.references != 0);
          el->dpo_result_id = upf_dpo_result_create (
            sxu->thread_id, sxu->session_id, sxu->session_generation,
            slot->state.lid, slot->key.is_source_matching);

          if (upf_session_match6_dpo_add_del (
                slot->key.fib_id, slot->key.addr, el->dpo_result_id,
                slot->key.is_source_matching, true))
            ASSERT (0);
        }
      ue_ip6.dpo_result_id = el->dpo_result_id;

      *vec_elt_at_index (_ep_ips6_vec, slot->state.lid) = ue_ip6;
    }

  static rules_far_t *_fars_vec = NULL;
  vec_resize (_fars_vec, sxu->next_vec_len.fars);
  vec_foreach_index (xid, sxu->fars)
    {
      sxu_slot_far_t *slot = vec_elt_at_index (sxu->fars, xid);

      if (!slot->state.will_exist)
        continue;

      rules_far_t *far = vec_elt_at_index (_fars_vec, slot->state.lid);
      _upf_sxu_stage_3_compile_far (sxu, xid, slot, far);

      if (slot->val.fp.has_redirect_information ||
          slot->val.fp.bbf_apply_action_nat ||
          far->ipfix_policy_used != UPF_IPFIX_POLICY_NONE)
        // requires flow for nat, proxy or ipfix
        flowless_optimization = false;
    }

  upf_time_t now = upf_time_now_main ();
  static rules_urr_t *_urrs_vec = NULL;
  vec_resize (_urrs_vec, sxu->next_vec_len.urrs);
  vec_foreach_index (xid, sxu->urrs)
    {
      sxu_slot_urr_t *slot = vec_elt_at_index (sxu->urrs, xid);

      if (!slot->state.will_exist)
        continue;

      rules_urr_t *urr = vec_elt_at_index (_urrs_vec, slot->state.lid);
      _upf_sxu_stage_3_compile_urr (sxu, xid, slot, now, urr);
    }

  static rules_qer_t *_qers_vec = NULL;
  vec_resize (_qers_vec, sxu->next_vec_len.qers);
  vec_foreach_index (xid, sxu->qers)
    {
      sxu_slot_qer_t *slot = vec_elt_at_index (sxu->qers, xid);

      if (!slot->state.will_exist)
        continue;

      rules_qer_t *qer = vec_elt_at_index (_qers_vec, slot->state.lid);
      _upf_sxu_stage_3_compile_qer (sxu, xid, slot, now, qer);
    }

  static rules_netcap_set_t *_cap_set_vec = NULL;
  vec_resize (_cap_set_vec, sxu->next_vec_len.capture_sets);
  vec_foreach_index (xid, sxu->capture_sets)
    {
      sxu_slot_capture_set_t *slot = vec_elt_at_index (sxu->capture_sets, xid);

      if (!slot->state.will_exist)
        continue;

      rules_netcap_set_t *cap_set =
        vec_elt_at_index (_cap_set_vec, slot->state.lid);
      cap_set->intf = slot->key.intf;
      cap_set->nwi_id = slot->key.nwi_id;
      cap_set->streams = NULL; // will be populated in before rpc
    }

  vec_foreach_index (xid, sxu->nat_bindings)
    {
      sxu_slot_nat_binding_t *slot = vec_elt_at_index (sxu->nat_bindings, xid);
      sxu_slot_state_t *state = &slot->state;
      ASSERT (xid == 0); // only single binding allowed

      if (!state->will_exist)
        continue;

      ASSERT (state->references);

      if (!state->has_existed) // need to be created first
        {
          u32 binding_id = upf_nat_binding_create (
            sxu->thread_id, slot->key.pool_id, sxu->session_id);
          ASSERT (is_valid_id (binding_id)); // checked on provision
          slot->val.binding_id = binding_id;
        }

      rules->nat_pool_id = slot->key.pool_id;
      rules->nat_binding_id = slot->val.binding_id;
    }

  _upf_sxu_stage_3_update_pdr_lidsets (sxu, rules, _pdrs_vec, _urrs_vec,
                                       _teps_vec, _ep_gtpus_vec, _ep_ips4_vec,
                                       _ep_ips6_vec);

  _upf_sxu_stage_3_update_urr_lidsets (sxu, _urrs_vec);

  // guestimation that it is easier to test X filters per packet, then
  // to create and manage flow for that packet
  const u32 FLOWLESS_FILTERS_LIMIT = 16;

  if (flowless_optimization)
    {
      upf_lidset_foreach (ep_ip4_lid, &sxu->next_slots.ue_ip_eps4)
        {
          rules_ep_ip4_t *ep4 = vec_elt_at_index (_ep_ips4_vec, ep_ip4_lid);
          u32 count = 0;
          upf_lidset_foreach (pdr_lid, &ep4->pdr_lids)
            count += vec_elt_at_index (_pdrs_vec, pdr_lid)->acls4.len;

          if (count >= FLOWLESS_FILTERS_LIMIT)
            flowless_optimization = false;
        }

      upf_lidset_foreach (ep_ip6_lid, &sxu->next_slots.ue_ip_eps6)
        {
          rules_ep_ip6_t *ep6 = vec_elt_at_index (_ep_ips6_vec, ep_ip6_lid);
          u32 count = 0;
          upf_lidset_foreach (pdr_lid, &ep6->pdr_lids)
            count += vec_elt_at_index (_pdrs_vec, pdr_lid)->acls6.len;

          if (count >= FLOWLESS_FILTERS_LIMIT)
            flowless_optimization = false;
        }

      upf_lidset_foreach (ep_gtpu_lid, &sxu->next_slots.gtpu_eps)
        {
          rules_ep_gtpu_t *ep_gtpu =
            vec_elt_at_index (_ep_gtpus_vec, ep_gtpu_lid);
          u32 count4 = 0, count6 = 0;
          upf_lidset_foreach (pdr_lid, &ep_gtpu->pdr_lids)
            {
              rules_pdr_t *pdr = vec_elt_at_index (_pdrs_vec, pdr_lid);
              count4 += pdr->acls4.len;
              count6 += pdr->acls6.len;
            }
          if (clib_max (count4, count6) >= FLOWLESS_FILTERS_LIMIT)
            flowless_optimization = false;
        }
    }

  rules->slots.urrs = sxu->next_slots.urrs;
  rules->slots.teps = sxu->next_slots.traffic_eps;
  rules->slots.ep_gtpus = sxu->next_slots.gtpu_eps;
  rules->slots.ep_ips4 = sxu->next_slots.ue_ip_eps4;
  rules->slots.ep_ips6 = sxu->next_slots.ue_ip_eps6;

  if (flowless_optimization)
    rules->is_flowless_optimized = 1;

  if (!took_barrier)
    {
      bool wb = false; // want barrier

      // some macro magic to make it more readable
#define vec_we vec_resize_will_expand
      wb |= vec_we (um->heaps.pdrs, sxu->next_vec_len.pdrs);
      wb |= vec_we (um->heaps.fars, sxu->next_vec_len.fars);
      wb |= vec_we (um->heaps.urrs, sxu->next_vec_len.urrs);
      wb |= vec_we (um->heaps.qers, sxu->next_vec_len.qers);
      wb |= vec_we (um->heaps.teps, sxu->next_vec_len.traffic_eps);
      wb |= vec_we (um->heaps.ep_ips4, sxu->next_vec_len.ue_ip_eps4);
      wb |= vec_we (um->heaps.ep_ips6, sxu->next_vec_len.ue_ip_eps6);
      wb |= vec_we (um->heaps.f_teids, sxu->next_vec_len.f_teid_allocations);
      wb |= vec_we (um->heaps.ep_gtpus, sxu->next_vec_len.gtpu_eps);
      wb |= vec_we (um->heaps.netcap_sets, sxu->next_vec_len.capture_sets);
#undef vec_we

      if (wb)
        {
          took_barrier = true;
          vlib_worker_thread_barrier_sync (vlib_get_main ());
        }
    }

  upf_hh_create_from_vec (um->heaps.pdrs, _pdrs_vec, &rules->pdrs);
  upf_hh_create_from_vec (um->heaps.fars, _fars_vec, &rules->fars);
  upf_hh_create_from_vec (um->heaps.urrs, _urrs_vec, &rules->urrs);
  upf_hh_create_from_vec (um->heaps.qers, _qers_vec, &rules->qers);
  upf_hh_create_from_vec (um->heaps.teps, _teps_vec, &rules->teps);
  upf_hh_create_from_vec (um->heaps.ep_ips4, _ep_ips4_vec, &rules->ep_ips4);
  upf_hh_create_from_vec (um->heaps.ep_ips6, _ep_ips6_vec, &rules->ep_ips6);
  upf_hh_create_from_vec (um->heaps.f_teids, _f_teids_vec, &rules->f_teids);
  upf_hh_create_from_vec (um->heaps.ep_gtpus, _ep_gtpus_vec, &rules->ep_gtpus);
  upf_hh_create_from_vec (um->heaps.netcap_sets, _cap_set_vec,
                          &rules->netcap_sets);

  if (took_barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());

  vec_reset_length (_pdrs_vec);
  vec_reset_length (_fars_vec);
  vec_reset_length (_urrs_vec);
  vec_reset_length (_qers_vec);
  vec_reset_length (_teps_vec);
  vec_reset_length (_ep_ips4_vec);
  vec_reset_length (_ep_ips6_vec);
  vec_reset_length (_f_teids_vec);
  vec_reset_length (_ep_gtpus_vec);
  vec_reset_length (_cap_set_vec);
}
