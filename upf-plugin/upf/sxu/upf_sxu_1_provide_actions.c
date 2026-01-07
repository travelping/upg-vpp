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
#include "upf/pfcp/pfcp_proto.h"
#include "upf/rules/upf_ipfilter.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/adf/adf.h"
#include "upf/nat/nat.h"
#include "upf/integrations/upf_ipfix.h"
#include "upf/sxu/upf_session_update.h"
#include "upf/sxu/upf_sxu_inlines.h"

#define UPF_DEBUG_ENABLE 0

static void
_upf_sxu_pdr_xid_ref_ops (upf_sxu_t *sxu, sxu_slot_pdr_t *el,
                          sxu_generic_xid_op_t op)
{
  sxu_op_xid_traffic_ep (sxu, &el->val.pdi.ref_traffic_ep_xid, op);
  sxu_op_xid_adf_application (sxu, &el->val.pdi.ref_application_xid, op);
  sxu_op_xid_far (sxu, &el->val.ref_far_xid, op);
  sxu_op_lidset_urrs (sxu, &el->val.refs_urr_xids, op);
  sxu_op_lidset_qers (sxu, &el->val.refs_qer_xids, op);
}

static void
_upf_sxu_far_xid_ref_ops (upf_sxu_t *sxu, sxu_slot_far_t *el,
                          sxu_generic_xid_op_t op)
{
  sxu_op_xid_nat_binding (sxu, &el->val.nat_binding_xid, op);
}

static void
_upf_sxu_urr_xid_ref_ops (upf_sxu_t *sxu, sxu_slot_urr_t *el,
                          sxu_generic_xid_op_t op)
{
  sxu_op_lidset_urrs (sxu, &el->val.refs_linked_urr_xids, op);
}

static void
_upf_sxu_qer_xid_ref_ops (upf_sxu_t *sxu, sxu_slot_qer_t *el,
                          sxu_generic_xid_op_t op)
{
}

static void
_upf_sxu_traffic_ep_xid_ref_ops (upf_sxu_t *sxu, sxu_slot_traffic_ep_t *el,
                                 sxu_generic_xid_op_t op)
{
  sxu_op_xid_f_teid_allocation (sxu, &el->key.ref_f_teid_allocation_xid, op);
  sxu_op_xid_gtpu_ep (sxu, &el->key.ref_gtpu_ep_xid, op);
  sxu_op_xid_ue_ip_ep4 (sxu, &el->val.ref_ue_ip4_xid, op);
  sxu_op_xid_ue_ip_ep6 (sxu, &el->val.ref_ue_ip6_xid, op);
}

static void
_upf_sxu_f_teid_allocation_xid_ref_ops (upf_sxu_t *sxu,
                                        sxu_slot_f_teid_allocation_t *el,
                                        sxu_generic_xid_op_t op)
{
  sxu_op_xid_gtpu_ep (sxu, &el->val.ref_gtpu_ep_xid, op);
}

// Modify reference count of all objects recursively
static void
_upf_sxu_xid_ref_ops (upf_sxu_t *sxu, sxu_generic_xid_op_t op)
{
  sxu_slot_pdr_t *pdr;
  vec_foreach (pdr, sxu->pdrs)
    _upf_sxu_pdr_xid_ref_ops (sxu, pdr, op);

  sxu_slot_far_t *far;
  vec_foreach (far, sxu->fars)
    _upf_sxu_far_xid_ref_ops (sxu, far, op);

  sxu_slot_urr_t *urr;
  vec_foreach (urr, sxu->urrs)
    _upf_sxu_urr_xid_ref_ops (sxu, urr, op);

  sxu_slot_traffic_ep_t *tep;
  vec_foreach (tep, sxu->traffic_eps)
    _upf_sxu_traffic_ep_xid_ref_ops (sxu, tep, op);

  sxu_slot_f_teid_allocation_t *fta;
  vec_foreach (fta, sxu->f_teid_allocations)
    _upf_sxu_f_teid_allocation_xid_ref_ops (sxu, fta, op);
}

// create object and set default values as needed for provided action
#define _(name, plural)                                                       \
  static __clib_warn_unused_result int _sxu_ensure_op_init_##name##_action (  \
    upf_sxu_t *sxu, sxu_##name##_key_t key, bool has_existed,                 \
    bool will_exist, upf_xid_t *result_xid)                                   \
  {                                                                           \
    if (!has_existed && !will_exist)                                          \
      ASSERT (0);                                                             \
                                                                              \
    upf_xid_t xid = sxu_ensure_##name##_by_key (sxu, key);                    \
    *result_xid = xid;                                                        \
    sxu_slot_state_t *state = &vec_elt_at_index (sxu->plural, xid)->state;    \
                                                                              \
    if (state->is_pfcp_action_taken)                                          \
      /* already in process of creation/deletion/update */                    \
      return upf_sxu_##name##_error_set_by_pfcp_id (                          \
        sxu, key, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE, ~0,          \
        "action on this id already taken");                                   \
                                                                              \
    if (state->has_existed != has_existed)                                    \
      /* unexpected operation */                                              \
      return upf_sxu_##name##_error_set_by_pfcp_id (                          \
        sxu, key, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE, ~0,          \
        "unexpceted operation");                                              \
                                                                              \
    state->will_exist = will_exist;                                           \
    state->is_pfcp_action_taken = 1;                                          \
    return 0;                                                                 \
  }
foreach_sxu_pfcp_type
#undef _

  static __clib_warn_unused_result int
  _upf_sxu_tep_key_with_f_teid (upf_sxu_t *sxu, pfcp_ie_f_teid_t *f_teid,
                                sxu_traffic_ep_key_t *tep_key)
{
  upf_main_t *um = &upf_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  upf_nwi_t *nwi = pool_elt_at_index (um->nwis, tep_key->nwi_id);

  if (!is_valid_id (nwi->gtpu_endpoints_ids[tep_key->intf]))
    return upf_sxu_pdr_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
      PFCP_IE_NETWORK_INSTANCE, "network instance has no GTPU endpoint");

  upf_gtpu_endpoint_t *ep =
    pool_elt_at_index (ugm->endpoints, nwi->gtpu_endpoints_ids[tep_key->intf]);

  tep_key->is_gtpu = 1;
  if (f_teid->flags & PFCP_F_TEID_CH)
    {
      sxu_f_teid_allocation_key_t tak = {
        .nwi_id = tep_key->nwi_id,
        .intf = tep_key->intf,
        .choose_id =
          (f_teid->flags & PFCP_F_TEID_CHID) ? f_teid->choose_id : ~0,
      };

      tep_key->ref_f_teid_allocation_xid =
        sxu_ref_f_teid_allocation_by_key (sxu, tak);
    }
  else
    {
      if (!(f_teid->flags & (PFCP_F_TEID_V4 | PFCP_F_TEID_V6)))
        {
          // From specification:
          // > At least one of the V4 and V6 flags shall be set to "1"
          return upf_sxu_pdr_error_set_by_xid (
            sxu, ~0, PFCP_CAUSE_MANDATORY_IE_INCORRECT, PFCP_IE_F_TEID,
            "at least one of the V4 or V6 flags must be set");
        }

      if (f_teid->teid == 0 || f_teid->teid == (u32) ~0)
        // invalid teid
        return upf_sxu_pdr_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_MANDATORY_IE_INCORRECT, PFCP_IE_F_TEID,
          "invalid TEID value");

      // For simplicity we allow only exact match of (ip4, ip6) pair for gtpu
      // endpoint
      bool ep_has4 = !ip4_address_is_zero (&ep->ip4);
      bool ep_has6 = !ip6_address_is_zero (&ep->ip6);

      if ((f_teid->flags & PFCP_F_TEID_V4) && !ep_has4)
        // no such ipv4 gtpu endpoint
        return upf_sxu_pdr_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_NETWORK_INSTANCE, "no such GTPU IPv4 address");

      if ((f_teid->flags & PFCP_F_TEID_V6) && !ep_has6)
        // no such ipv6 gtpu endpoint
        return upf_sxu_pdr_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_NETWORK_INSTANCE, "no such GTPU IPv6 address");

      sxu_gtpu_ep_key_t epk = {
        .gtpu_ep_id = ep - ugm->endpoints,
        .teid = f_teid->teid,
      };

      tep_key->ref_gtpu_ep_xid = sxu_ref_gtpu_ep_by_key (sxu, epk);
    }

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_tep_key_with_ue_ip (upf_sxu_t *sxu, pfcp_ie_ue_ip_address_t *ueip,
                             sxu_traffic_ep_key_t *tep_key)
{
  if (ueip->flags & PFCP_UE_IP_ADDRESS_CHV4 ||
      ueip->flags & PFCP_UE_IP_ADDRESS_CHV6)
    {
      // TODO: Implement UPF based UE IP allocation
      ASSERT (0);
      return upf_sxu_pdr_error_set_by_xid (sxu, ~0, PFCP_CAUSE_SYSTEM_FAILURE,
                                           PFCP_IE_UE_IP_ADDRESS,
                                           "IP allocation is not implemented");
    }

  tep_key->is_destination_ip = (ueip->flags & PFCP_UE_IP_ADDRESS_SD) ? 1 : 0;
  if (ueip->flags & PFCP_UE_IP_ADDRESS_V4)
    {
      tep_key->ue_addr4 = ueip->ip4;
      tep_key->is_ip4 = 1;
    }

  if (ueip->flags & PFCP_UE_IP_ADDRESS_V6)
    {
      tep_key->ue_addr6 = ueip->ip6;
      tep_key->is_ip6 = 1;
    }

  if (!tep_key->is_ip4 && !tep_key->is_ip6)
    {
      // Match any case:
      // > CP function may provision a PDR with all match fields wildcarded
      // > (i.e. all match fields omitted in the PDI) in a separate PFCP
      // > session,
      tep_key->is_ip4 = 1;
      tep_key->is_ip6 = 1;

      ip4_address_set_zero (&tep_key->ue_addr4);
      ip6_address_set_zero (&tep_key->ue_addr6);
    }

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_handle_pdi (upf_sxu_t *sxu, sxu_pdr_t *el, pfcp_ie_pdi_t *cpdi,
                     bool is_update)
{
  upf_main_t *um = &upf_main;

  if (is_update)
    {
      // > When present, this IE shall replace the PDI previously stored in the
      // > UP function for this PDR
      sxu_unref_traffic_ep (sxu, &el->pdi.ref_traffic_ep_xid);
      vec_free (el->pdi.sdf_filters_new);
      el->do_reuse_acls = false;
      sxu_unref_adf_application (sxu, &el->pdi.ref_application_xid);
    }

  el->pdi.source_interface = upf_interface_type_from_pfcp_source_interface_ie (
    cpdi->source_interface); // mandatory

  if (!is_valid_id (el->pdi.source_interface))
    return upf_sxu_pdr_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_MANDATORY_IE_INCORRECT, PFCP_IE_SOURCE_INTERFACE,
      "invalid source interface");

  upf_nwi_t *nwi;
  if (BIT_ISSET (cpdi->grp.fields, PDI_NETWORK_INSTANCE))
    {
      if ((nwi = upf_nwi_get_by_name (cpdi->network_instance)) == NULL)
        return upf_sxu_pdr_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_NETWORK_INSTANCE, "no such NWI is configured");
    }
  else
    nwi = upf_nwi_get_by_name (NULL); // Use default NWI

  el->pdi.nwi_id = nwi - um->nwis;

  sxu_traffic_ep_key_t tep_key = {
    .nwi_id = el->pdi.nwi_id,
    .intf = el->pdi.source_interface,
    .ref_f_teid_allocation_xid = ~0,
    .ref_gtpu_ep_xid = ~0,
  };

  if (BIT_ISSET (cpdi->grp.fields, PDI_F_TEID))
    if (_upf_sxu_tep_key_with_f_teid (sxu, &cpdi->f_teid, &tep_key))
      return upf_sxu_pdr_error_wrap (sxu, ~0, "f-teid");

  if (BIT_ISSET (cpdi->grp.fields, PDI_UE_IP_ADDRESS))
    {
      if (_upf_sxu_tep_key_with_ue_ip (sxu, &cpdi->ue_ip_address, &tep_key))
        return upf_sxu_pdr_error_wrap (sxu, ~0, "ue ip");

      bool is_uplink = el->pdi.source_interface == UPF_INTERFACE_TYPE_ACCESS;

      // TODO: should we return error instead of assert?
      // (ueip.flags & PFCP_UE_IP_ADDRESS_SD) do not match pdi.source_interface
      ASSERT (tep_key.is_destination_ip != is_uplink);
    }

  el->pdi.ref_traffic_ep_xid = sxu_ref_traffic_ep_by_key (sxu, tep_key);

  if (BIT_ISSET (cpdi->grp.fields, PDI_SDF_FILTER))
    {
      ASSERT (el->pdi.sdf_filters_new == NULL);
      vec_resize (el->pdi.sdf_filters_new, vec_len (cpdi->sdf_filter));

      u32 sdf_idx;
      vec_foreach_index (sdf_idx, cpdi->sdf_filter)
        {
          pfcp_ie_sdf_filter_t *sdf =
            vec_elt_at_index (cpdi->sdf_filter, sdf_idx);
          ipfilter_rule_t *acl =
            vec_elt_at_index (el->pdi.sdf_filters_new, sdf_idx);

          if (sdf->flags != PFCP_F_SDF_FD)
            return upf_sxu_pdr_error_set_by_xid (
              sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
              PFCP_IE_SDF_FILTER, "unsupported flag");

          unformat_input_t input;
          unformat_init_string (&input, (char *) sdf->flow,
                                vec_len (sdf->flow));
          int rv = unformat_user (&input, unformat_upf_ipfilter, acl);
          unformat_free (&input);

          if (!rv)
            return upf_sxu_pdr_error_set_by_xid (
              sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
              PFCP_IE_SDF_FILTER, "incorrect filter");
        }
    }

  if (BIT_ISSET (cpdi->grp.fields, PDI_APPLICATION_ID))
    {
      upf_adf_app_t *app = upf_adf_app_get_by_name (cpdi->application_id);
      if (!app)
        return upf_sxu_pdr_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_APPLICATION_ID, "unknown application name");

      sxu_adf_application_key_t application_key = {
        .application_id = app - um->adf_main.apps,
      };
      el->pdi.ref_application_xid =
        sxu_ref_adf_application_by_key (sxu, application_key);
    }

  return 0;
}

static void
_upf_sxu_pdr_with_urrs (upf_sxu_t *sxu, sxu_pdr_t *pdr,
                        pfcp_ie_urr_id_t *pfcp_urr_ids_vec)
{
  sxu_op_lidset_urrs (sxu, &pdr->refs_urr_xids, SXU_REF_GENERIC_OP__UNREF);

  pfcp_ie_urr_id_t *p_urr_id;
  vec_foreach (p_urr_id, pfcp_urr_ids_vec)
    {
      upf_xid_t xid = sxu_ensure_urr_by_key (sxu, *p_urr_id);
      if (upf_lidset_get (&pdr->refs_urr_xids, xid))
        continue;
      upf_lidset_set (&pdr->refs_urr_xids, sxu_ref_urr_by_xid (sxu, xid));
    }
}

static void
_upf_sxu_pdr_with_qers (upf_sxu_t *sxu, sxu_pdr_t *pdr,
                        pfcp_ie_qer_id_t *pfcp_qer_ids_vec)
{
  sxu_op_lidset_qers (sxu, &pdr->refs_qer_xids, SXU_REF_GENERIC_OP__UNREF);

  pfcp_ie_qer_id_t *p_qer_id;
  vec_foreach (p_qer_id, pfcp_qer_ids_vec)
    {
      upf_xid_t xid = sxu_ensure_qer_by_key (sxu, *p_qer_id);
      if (upf_lidset_get (&pdr->refs_qer_xids, xid))
        continue;
      upf_lidset_set (&pdr->refs_qer_xids, sxu_ref_qer_by_xid (sxu, xid));
    }
}

// check supported configurations
static __clib_warn_unused_result int
_upf_sxu_pdr_check (upf_sxu_t *sxu, sxu_pdr_t *pdr)
{
  sxu_slot_traffic_ep_t *tep =
    vec_elt_at_index (sxu->traffic_eps, pdr->pdi.ref_traffic_ep_xid);

  // For simplicity require gtpu FTEID for Outher Header Removal.
  if (pdr->gtpu_outer_header_removal && !tep->key.is_gtpu)
    return upf_sxu_pdr_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
      PFCP_IE_OUTER_HEADER_REMOVAL,
      "Outer Header Removal without F-TEID is not supported");

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_pdr_with_ohr (upf_sxu_t *sxu, sxu_pdr_t *pdr,
                       pfcp_ie_outer_header_removal_t ohr)
{
  switch (ohr)
    {
    case PFCP_OUTER_HEADER_REMOVAL_GTP:
    case PFCP_OUTER_HEADER_REMOVAL_GTP_IP4:
    case PFCP_OUTER_HEADER_REMOVAL_GTP_IP6:
      pdr->gtpu_outer_header_removal = 1;
      return 0;
    default:
      return upf_sxu_pdr_error_set_by_xid (
        sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
        PFCP_IE_OUTER_HEADER_REMOVAL, "unsupported outer header removal type");
    }
}

static __clib_warn_unused_result int
_upf_sxu_handle_create_pdr (upf_sxu_t *sxu, pfcp_ie_create_pdr_t *cpdr)
{
  sxu_slot_pdr_t *slot = vec_elt_at_index (sxu->pdrs, cpdr->upf_update_xid);
  sxu_pdr_t *el = &slot->val;

  *el = (sxu_pdr_t){
    .pdi.ref_traffic_ep_xid = ~0,
    .pdi.ref_application_xid = ~0,
    .ref_far_xid = ~0,
    ._old_acl_cached_id = ~0,
  };

  el->precedence = cpdr->precedence; // mandatory

  if (_upf_sxu_handle_pdi (sxu, el, &cpdr->pdi, false)) // mandatory
    return upf_sxu_pdr_error_wrap (sxu, ~0, "pdi");

  if (BIT_ISSET (cpdr->grp.fields, CREATE_PDR_OUTER_HEADER_REMOVAL))
    if (_upf_sxu_pdr_with_ohr (sxu, el, cpdr->outer_header_removal))
      return upf_sxu_pdr_error_wrap (sxu, ~0, "ohr");

  if (BIT_ISSET (cpdr->grp.fields, CREATE_PDR_FAR_ID))
    el->ref_far_xid = sxu_ref_far_by_key (sxu, cpdr->far_id);

  if (BIT_ISSET (cpdr->grp.fields, CREATE_PDR_URR_ID))
    _upf_sxu_pdr_with_urrs (sxu, el, cpdr->urr_id);

  if (BIT_ISSET (cpdr->grp.fields, CREATE_PDR_QER_ID))
    _upf_sxu_pdr_with_qers (sxu, el, cpdr->qer_id);

  if (_upf_sxu_pdr_check (sxu, el))
    return upf_sxu_pdr_error_wrap (sxu, ~0, "pdr check");

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_handle_update_pdr (upf_sxu_t *sxu, pfcp_ie_update_pdr_t *updr)
{
  sxu_slot_pdr_t *slot = vec_elt_at_index (sxu->pdrs, updr->upf_update_xid);
  sxu_pdr_t *el = &slot->val;

  if (BIT_ISSET (updr->grp.fields, UPDATE_PDR_PRECEDENCE))
    el->precedence = updr->precedence;

  if (BIT_ISSET (updr->grp.fields, UPDATE_PDR_PDI))
    if (_upf_sxu_handle_pdi (sxu, el, &updr->pdi, true))
      return upf_sxu_pdr_error_wrap (sxu, ~0, "pdi");

  if (BIT_ISSET (updr->grp.fields, UPDATE_PDR_OUTER_HEADER_REMOVAL))
    if (_upf_sxu_pdr_with_ohr (sxu, el, updr->outer_header_removal))
      return upf_sxu_pdr_error_wrap (sxu, ~0, "ohr");

  if (BIT_ISSET (updr->grp.fields, UPDATE_PDR_FAR_ID))
    {
      sxu_unref_far (sxu, &el->ref_far_xid);
      el->ref_far_xid = sxu_ref_far_by_key (sxu, updr->far_id);
    }

  if (BIT_ISSET (updr->grp.fields, UPDATE_PDR_URR_ID))
    _upf_sxu_pdr_with_urrs (sxu, el, updr->urr_id);

  if (BIT_ISSET (updr->grp.fields, UPDATE_PDR_QER_ID))
    _upf_sxu_pdr_with_qers (sxu, el, updr->qer_id);

  if (_upf_sxu_pdr_check (sxu, el))
    return upf_sxu_pdr_error_wrap (sxu, ~0, "pdr check");

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_far_with_outer_header_creation (upf_sxu_t *sxu, sxu_far_t *far,
                                         pfcp_ie_outer_header_creation_t *ohc)
{
  upf_main_t *um = &upf_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  if (ohc->description & PFCP_OUTER_HEADER_CREATION_GTP_ANY)
    far->fp.ohc.teid = ohc->teid;
  else
    return upf_sxu_far_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
      PFCP_IE_OUTER_HEADER_CREATION, "unsupported outer header creation type");

  if (ohc->description & PFCP_OUTER_HEADER_CREATION_ANY_IP4)
    far->fp.ohc.addr4 = ohc->ip4;

  if (ohc->description & PFCP_OUTER_HEADER_CREATION_ANY_IP6)
    far->fp.ohc.addr6 = ohc->ip6;

  bool want_ip4 = !ip4_address_is_zero (&far->fp.ohc.addr4);
  bool want_ip6 = !ip6_address_is_zero (&far->fp.ohc.addr6);

  if (!want_ip4 && !want_ip6)
    // require at least some address
    return upf_sxu_far_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_MANDATORY_IE_INCORRECT,
      PFCP_IE_OUTER_HEADER_CREATION, "no outer address is provided");

  // very that we have source gtpu endpoint
  upf_nwi_t *nwi = pool_elt_at_index (um->nwis, far->fp.nwi_id);
  u16 gep_id = nwi->gtpu_endpoints_ids[far->fp.destination_interface];
  if (!is_valid_id (gep_id))
    return upf_sxu_far_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
      PFCP_IE_OUTER_HEADER_CREATION, "NWI has no required GTPU endpoint");

  upf_gtpu_endpoint_t *gep = pool_elt_at_index (ugm->endpoints, gep_id);

  if (want_ip4 && !gep->has_ip4)
    return upf_sxu_far_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
      PFCP_IE_OUTER_HEADER_CREATION, "NWI GTPU endpoint is not ipv4");
  if (want_ip6 && !gep->has_ip6)
    return upf_sxu_far_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
      PFCP_IE_OUTER_HEADER_CREATION, "NWI GTPU endpoint is not ipv6");

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_create_forwarding_parameters (upf_sxu_t *sxu, sxu_far_t *el,
                                       pfcp_ie_forwarding_parameters_t *cfp)
{
  upf_main_t *um = &upf_main;

  el->fp.destination_interface =
    upf_interface_type_from_pfcp_destination_interface_ie (
      cfp->destination_interface);
  if (!is_valid_id (el->fp.destination_interface))
    return upf_sxu_far_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_MANDATORY_IE_INCORRECT,
      PFCP_IE_DESTINATION_INTERFACE, "invalid destination interface");

  upf_nwi_t *nwi;
  if (BIT_ISSET (cfp->grp.fields, FORWARDING_PARAMETERS_NETWORK_INSTANCE))
    {
      if ((nwi = upf_nwi_get_by_name (cfp->network_instance)) == NULL)
        return upf_sxu_far_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_NETWORK_INSTANCE, "no such NWI is configured");
    }
  else
    nwi = upf_nwi_get_by_name (NULL); // Use default NWI

  el->fp.nwi_id = nwi - um->nwis;

  if (BIT_ISSET (cfp->grp.fields, FORWARDING_PARAMETERS_REDIRECT_INFORMATION))
    {
      if (cfp->redirect_information.type != PFCP_REDIRECT_INFORMATION_HTTP)
        return upf_sxu_far_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_REDIRECT_INFORMATION, "only http redirect is supported");

      el->fp.has_redirect_information = 1;
      copy_pfcp_ie_redirect_information (&el->fp.redirect_information,
                                         &cfp->redirect_information);
    }

  if (BIT_ISSET (cfp->grp.fields, FORWARDING_PARAMETERS_OUTER_HEADER_CREATION))
    {
      el->fp.has_outer_header_creation = 1;
      if (_upf_sxu_far_with_outer_header_creation (
            sxu, el, &cfp->outer_header_creation))
        return upf_sxu_far_error_wrap (sxu, ~0, "ohc");
    }

  if (BIT_ISSET (cfp->grp.fields, FORWARDING_PARAMETERS_FORWARDING_POLICY))
    {
      upf_forwarding_policy_t *fp =
        upf_forwarding_policy_get_by_name (cfp->forwarding_policy.identifier);
      if (!fp)
        return upf_sxu_far_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_INVALID_FORWARDING_POLICY,
          PFCP_IE_FORWARDING_POLICY, "unknown forwarding policy");
      el->fp.policy_id = fp - um->forwarding_policies;
    }

  if (BIT_ISSET (cfp->grp.fields, FORWARDING_PARAMETERS_BBF_APPLY_ACTION))
    {
      if (cfp->bbf_apply_action != PFCP_BBF_APPLY_ACTION_NAT)
        return upf_sxu_far_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_BBF_APPLY_ACTION, "unknown bpf action");

      el->fp.bbf_apply_action_nat = 1;
    }

  if (BIT_ISSET (cfp->grp.fields, FORWARDING_PARAMETERS_BBF_NAT_PORT_BLOCK))
    {
      upf_nat_main_t *unm = &upf_nat_main;
      if (!unm->initialized)
        return upf_sxu_far_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_BBF_NAT_PORT_BLOCK, "nat is not configured");

      upf_nat_pool_t *nat_pool =
        upf_nat_pool_get_by_name (cfp->nat_port_block);
      if (!nat_pool)
        return upf_sxu_far_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_BBF_NAT_PORT_BLOCK, "unknown nat pool name");

      sxu_nat_binding_key_t key = {
        .pool_id = nat_pool - unm->nat_pools,
      };
      el->nat_binding_xid = sxu_ref_nat_binding_by_key (sxu, key);
    }

  if (el->fp.bbf_apply_action_nat && !is_valid_id (el->nat_binding_xid))
    // Can't do nat without pool.
    // If needed in future, then default NAT pool per NWI configuration can be
    // implemented.
    return upf_sxu_far_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_CONDITIONAL_IE_MISSING, PFCP_IE_BBF_NAT_PORT_BLOCK,
      "nat block required");

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_update_forwarding_parameters (
  upf_sxu_t *sxu, sxu_far_t *el, pfcp_ie_update_forwarding_parameters_t *ufp)
{
  upf_main_t *um = &upf_main;

  if (BIT_ISSET (ufp->grp.fields,
                 UPDATE_FORWARDING_PARAMETERS_DESTINATION_INTERFACE))
    {
      el->fp.destination_interface =
        upf_interface_type_from_pfcp_destination_interface_ie (
          ufp->destination_interface);
      if (!is_valid_id (el->fp.destination_interface))
        return upf_sxu_far_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_MANDATORY_IE_INCORRECT,
          PFCP_IE_DESTINATION_INTERFACE, "invalid destination interface");
    }

  if (BIT_ISSET (ufp->grp.fields,
                 UPDATE_FORWARDING_PARAMETERS_NETWORK_INSTANCE))
    {
      upf_nwi_t *nwi = upf_nwi_get_by_name (ufp->network_instance);
      if (nwi == NULL)
        return upf_sxu_far_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_NETWORK_INSTANCE, "no such NWI is configured");
      el->fp.nwi_id = nwi - um->nwis;
    }

  if (BIT_ISSET (ufp->grp.fields,
                 UPDATE_FORWARDING_PARAMETERS_REDIRECT_INFORMATION))
    {
      if (el->fp.has_redirect_information)
        free_pfcp_ie_redirect_information (&el->fp.redirect_information);

      if (ufp->redirect_information.type != PFCP_REDIRECT_INFORMATION_HTTP)
        return upf_sxu_far_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
          PFCP_IE_REDIRECT_INFORMATION, "only http redirect is supported");

      el->fp.has_redirect_information = 1;
      copy_pfcp_ie_redirect_information (&el->fp.redirect_information,
                                         &ufp->redirect_information);
    }

  if (BIT_ISSET (ufp->grp.fields,
                 UPDATE_FORWARDING_PARAMETERS_PFCPSMREQ_FLAGS))
    if (ufp->pfcpsmreq_flags & PFCP_PFCPSMREQ_SNDEM)
      el->fp.do_send_end_marker = 1;

  if (BIT_ISSET (ufp->grp.fields,
                 UPDATE_FORWARDING_PARAMETERS_OUTER_HEADER_CREATION))
    {
      if (el->fp.has_outer_header_creation)
        memset (&el->fp.ohc, 0, sizeof (el->fp.ohc));

      el->fp.has_outer_header_creation = 1;
      if (_upf_sxu_far_with_outer_header_creation (
            sxu, el, &ufp->outer_header_creation))
        return upf_sxu_far_error_wrap (sxu, ~0, "ohc");
    }

  if (BIT_ISSET (ufp->grp.fields,
                 UPDATE_FORWARDING_PARAMETERS_FORWARDING_POLICY))
    {
      upf_forwarding_policy_t *fp =
        upf_forwarding_policy_get_by_name (ufp->forwarding_policy.identifier);
      if (!fp)
        return upf_sxu_far_error_set_by_xid (
          sxu, ~0, PFCP_CAUSE_INVALID_FORWARDING_POLICY,
          PFCP_IE_FORWARDING_POLICY, "unknown forwarding policy");
      el->fp.policy_id = fp - um->forwarding_policies;
    }

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_with_apply_action (upf_sxu_t *sxu, sxu_far_t *far,
                            pfcp_ie_apply_action_t apply_action)
{
  switch (apply_action)
    {
    case PFCP_F_APPLY_FORW:
      far->apply_action = UPF_FAR_ACTION_FORWARD;
      break;
    case PFCP_F_APPLY_DROP:
      far->apply_action = UPF_FAR_ACTION_DROP;
      break;
    default:
      // unsupported apply action
      return upf_sxu_far_error_set_by_xid (
        sxu, ~0, PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE,
        PFCP_IE_APPLY_ACTION, "unsupported apply action");
    }
  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_handle_create_far (upf_sxu_t *sxu, pfcp_ie_create_far_t *cfar)
{
  sxu_slot_far_t *slot = vec_elt_at_index (sxu->fars, cfar->upf_update_xid);
  sxu_far_t *el = &slot->val;

  *el = (sxu_far_t){
    .fp.nwi_id = ~0,
    .fp.policy_id = ~0,
    .ipfix_policy = UPF_IPFIX_POLICY_UNSPECIFIED,
    .nat_binding_xid = ~0,
  };

  // mandatory
  if (_upf_sxu_with_apply_action (sxu, el, cfar->apply_action))
    return upf_sxu_far_error_wrap (sxu, ~0, "apply action");

  if (BIT_ISSET (cfar->grp.fields, CREATE_FAR_FORWARDING_PARAMETERS))
    if (_upf_sxu_create_forwarding_parameters (sxu, el,
                                               &cfar->forwarding_parameters))
      return upf_sxu_far_error_wrap (sxu, ~0, "fp");

  if (BIT_ISSET (cfar->grp.fields, CREATE_FAR_TP_IPFIX_POLICY))
    el->ipfix_policy = upf_ipfix_lookup_policy (cfar->ipfix_policy, 0);

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_handle_update_far (upf_sxu_t *sxu, pfcp_ie_update_far_t *ufar)
{
  sxu_slot_far_t *slot = vec_elt_at_index (sxu->fars, ufar->upf_update_xid);
  sxu_far_t *el = &slot->val;

  if (BIT_ISSET (ufar->grp.fields, UPDATE_FAR_APPLY_ACTION))
    if (_upf_sxu_with_apply_action (sxu, el, ufar->apply_action))
      return upf_sxu_far_error_wrap (sxu, ~0, "apply action");

  if (BIT_ISSET (ufar->grp.fields, UPDATE_FAR_UPDATE_FORWARDING_PARAMETERS))
    if (_upf_sxu_update_forwarding_parameters (
          sxu, el, &ufar->update_forwarding_parameters))
      return upf_sxu_far_error_wrap (sxu, ~0, "fp");

  if (BIT_ISSET (ufar->grp.fields, UPDATE_FAR_TP_IPFIX_POLICY))
    el->ipfix_policy = upf_ipfix_lookup_policy (ufar->ipfix_policy, 0);

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_with_measurement_method (upf_sxu_t *sxu, sxu_urr_t *urr,
                                  pfcp_ie_measurement_method_t methods)
{
  if ((methods &
       (PFCP_MEASUREMENT_METHOD_VOLUME | PFCP_MEASUREMENT_METHOD_DURATION |
        PFCP_MEASUREMENT_METHOD_EVENT)) == 0)
    // > At least one bit shall be set to "1"
    return upf_sxu_urr_error_set_by_xid (
      sxu, ~0, PFCP_CAUSE_MANDATORY_IE_INCORRECT, PFCP_IE_MEASUREMENT_METHOD,
      "no measurement method provided");

  urr->measurement_method_volume =
    (methods & PFCP_MEASUREMENT_METHOD_VOLUME) != 0;
  urr->measurement_method_duration =
    (methods & PFCP_MEASUREMENT_METHOD_DURATION) != 0;
  urr->measurement_method_event =
    (methods & PFCP_MEASUREMENT_METHOD_EVENT) != 0;

  if (urr->measurement_method_event &&
      (urr->measurement_method_duration || urr->measurement_method_volume))
    {
      // Event method shouldn't be combined with duration or volume methods
      return upf_sxu_urr_error_set_by_xid (
        sxu, ~0, PFCP_CAUSE_MANDATORY_IE_INCORRECT, PFCP_IE_MEASUREMENT_METHOD,
        "event method shouldn't be combined with volume or duration");
    }
  return 0;
}

static void
_upf_sxu_urr_with_linked_urrs (upf_sxu_t *sxu, sxu_urr_t *urr,
                               pfcp_ie_urr_id_t *pfcp_urr_ids_vec)
{
  sxu_op_lidset_urrs (sxu, &urr->refs_linked_urr_xids,
                      SXU_REF_GENERIC_OP__UNREF);

  pfcp_ie_urr_id_t *p_urr_id;
  vec_foreach (p_urr_id, pfcp_urr_ids_vec)
    {
      upf_xid_t xid = sxu_ensure_urr_by_key (sxu, *p_urr_id);
      if (upf_lidset_get (&urr->refs_linked_urr_xids, xid))
        continue;
      upf_lidset_set (&urr->refs_linked_urr_xids,
                      sxu_ref_urr_by_xid (sxu, xid));
    }
}

static __clib_warn_unused_result int
_upf_sxu_handle_create_urr (upf_sxu_t *sxu, pfcp_ie_create_urr_t *curr)
{
  sxu_slot_urr_t *slot = vec_elt_at_index (sxu->urrs, curr->upf_update_xid);
  sxu_urr_t *el = &slot->val;

  *el = (sxu_urr_t){};

  // mandatory
  if (_upf_sxu_with_measurement_method (sxu, el, curr->measurement_method))
    return upf_sxu_urr_error_wrap (sxu, ~0, "mm");

  if (BIT_ISSET (curr->grp.fields, CREATE_URR_REPORTING_TRIGGERS))
    el->reporting_triggers = curr->reporting_triggers;

  if (BIT_ISSET (curr->grp.fields, CREATE_URR_MEASUREMENT_PERIOD))
    {
      el->update_flags |= URR_UPDATE_F_MEASUREMENT_PERIOD;
      el->measurement_period = curr->measurement_period;
    }
  if (BIT_ISSET (curr->grp.fields, CREATE_URR_VOLUME_THRESHOLD))
    {
      el->update_flags |= URR_UPDATE_F_VOLUME_THRESHOLD;
      el->volume_threshold_ul = curr->volume_threshold.ul;
      el->volume_threshold_dl = curr->volume_threshold.dl;
      el->volume_threshold_total = curr->volume_threshold.total;
    }
  if (BIT_ISSET (curr->grp.fields, CREATE_URR_VOLUME_QUOTA))
    {
      if (!(curr->volume_quota.fields & PFCP_VOLUME_VOLUME))
        // > At least one bit shall be set to "1".
        return upf_sxu_urr_error_set_by_xid (
          sxu, curr->upf_update_xid, PFCP_CAUSE_MANDATORY_IE_INCORRECT,
          PFCP_IE_VOLUME_QUOTA, "no fields provided");

      el->update_flags |= URR_UPDATE_F_VOLUME_QUOTA;
      el->has_volume_quota_tot =
        (curr->volume_quota.fields & PFCP_VOLUME_TOVOL) != 0;
      el->has_volume_quota_ul =
        (curr->volume_quota.fields & PFCP_VOLUME_ULVOL) != 0;
      el->has_volume_quota_dl =
        (curr->volume_quota.fields & PFCP_VOLUME_DLVOL) != 0;

      el->volume_quota_total = curr->volume_quota.total;
      el->volume_quota_ul = curr->volume_quota.ul;
      el->volume_quota_dl = curr->volume_quota.dl;
    }
  if (BIT_ISSET (curr->grp.fields, CREATE_URR_TIME_THRESHOLD))
    {
      el->update_flags |= URR_UPDATE_F_TIME_THRESHOLD;
      el->time_threshold = curr->time_threshold;
    }
  if (BIT_ISSET (curr->grp.fields, CREATE_URR_TIME_QUOTA))
    {
      el->update_flags |= URR_UPDATE_F_TIME_QUOTA;
      el->has_time_quota = 1;
      el->time_quota = curr->time_quota;
    }
  if (BIT_ISSET (curr->grp.fields, CREATE_URR_QUOTA_VALIDITY_TIME))
    {
      el->update_flags |= URR_UPDATE_F_QUOTA_VALIDITY_TIME;
      el->quota_validity_time = curr->quota_validity_time;
    }
  if (BIT_ISSET (curr->grp.fields, CREATE_URR_QUOTA_HOLDING_TIME))
    {
      el->update_flags |= URR_UPDATE_F_QUOTA_HOLDING_TIME;
      el->quota_holding_time = curr->quota_holding_time;
    }
  if (BIT_ISSET (curr->grp.fields, CREATE_URR_MONITORING_TIME))
    {
      el->update_flags |= URR_UPDATE_F_MONITORING_TIME;
      el->monitoring_time = curr->monitoring_time;
    }

  if (BIT_ISSET (curr->grp.fields, CREATE_URR_LINKED_URR_ID))
    _upf_sxu_urr_with_linked_urrs (sxu, el, curr->linked_urr_id);

  return 0;
}

static __clib_warn_unused_result int
_upf_sxu_handle_update_urr (upf_sxu_t *sxu, pfcp_ie_update_urr_t *uurr)
{
  sxu_slot_urr_t *slot = vec_elt_at_index (sxu->urrs, uurr->upf_update_xid);
  sxu_urr_t *el = &slot->val;

  el->update_flags = 0;

  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_MEASUREMENT_METHOD))
    if (_upf_sxu_with_measurement_method (sxu, el, uurr->measurement_method))
      return upf_sxu_urr_error_wrap (sxu, ~0, "mm");

  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_REPORTING_TRIGGERS))
    el->reporting_triggers = uurr->reporting_triggers;

  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_MEASUREMENT_PERIOD))
    {
      el->update_flags |= URR_UPDATE_F_MEASUREMENT_PERIOD;
      el->measurement_period = uurr->measurement_period;
    }
  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_VOLUME_THRESHOLD))
    {
      el->update_flags |= URR_UPDATE_F_VOLUME_THRESHOLD;
      el->volume_threshold_ul = uurr->volume_threshold.ul;
      el->volume_threshold_dl = uurr->volume_threshold.dl;
      el->volume_threshold_total = uurr->volume_threshold.total;
    }
  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_VOLUME_QUOTA))
    {
      if (!(uurr->volume_quota.fields & PFCP_VOLUME_VOLUME))
        // At least single quota value should be provided
        return upf_sxu_urr_error_set_by_xid (
          sxu, uurr->upf_update_xid, PFCP_CAUSE_MANDATORY_IE_INCORRECT,
          PFCP_IE_VOLUME_QUOTA, "no fields provided");

      el->update_flags |= URR_UPDATE_F_VOLUME_QUOTA;
      el->has_volume_quota_tot =
        (uurr->volume_quota.fields & PFCP_VOLUME_TOVOL) != 0;
      el->has_volume_quota_ul =
        (uurr->volume_quota.fields & PFCP_VOLUME_ULVOL) != 0;
      el->has_volume_quota_dl =
        (uurr->volume_quota.fields & PFCP_VOLUME_DLVOL) != 0;

      el->volume_quota_total = uurr->volume_quota.total;
      el->volume_quota_ul = uurr->volume_quota.ul;
      el->volume_quota_dl = uurr->volume_quota.dl;
    }
  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_TIME_THRESHOLD))
    {
      el->update_flags |= URR_UPDATE_F_TIME_THRESHOLD;
      el->time_threshold = uurr->time_threshold;
    }
  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_TIME_QUOTA))
    {
      el->update_flags |= URR_UPDATE_F_TIME_QUOTA;
      el->has_time_quota = 1;
      el->time_quota = uurr->time_quota;
    }
  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_QUOTA_VALIDITY_TIME))
    {
      el->update_flags |= URR_UPDATE_F_QUOTA_VALIDITY_TIME;
      el->quota_validity_time = uurr->quota_validity_time;
    }
  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_QUOTA_HOLDING_TIME))
    {
      el->update_flags |= URR_UPDATE_F_QUOTA_HOLDING_TIME;
      el->quota_holding_time = uurr->quota_holding_time;
    }
  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_MONITORING_TIME))
    {
      el->update_flags |= URR_UPDATE_F_MONITORING_TIME;
      el->monitoring_time = uurr->monitoring_time;
    }
  if (BIT_ISSET (uurr->grp.fields, UPDATE_URR_LINKED_URR_ID))
    _upf_sxu_urr_with_linked_urrs (sxu, el, uurr->linked_urr_id);

  return 0;
}

static void
_upf_sxu_handle_create_qer (upf_sxu_t *sxu, pfcp_ie_create_qer_t *cqer)
{
  sxu_slot_qer_t *slot = vec_elt_at_index (sxu->qers, cqer->upf_update_xid);
  sxu_qer_t *el = &slot->val;

  *el = (sxu_qer_t){};

  // mandatory
  el->gate_closed_ul = cqer->gate_status.ul != 0;
  el->gate_closed_dl = cqer->gate_status.dl != 0;

  if (BIT_ISSET (cqer->grp.fields, CREATE_QER_MBR))
    {
      el->has_maximum_bitrate = 1;
      el->maximum_bitrate[UPF_DIR_UL] = cqer->mbr.ul;
      el->maximum_bitrate[UPF_DIR_DL] = cqer->mbr.dl;
    }
}

static void
_upf_sxu_handle_update_qer (upf_sxu_t *sxu, pfcp_ie_update_qer_t *uqer)
{
  sxu_slot_qer_t *slot = vec_elt_at_index (sxu->qers, uqer->upf_update_xid);
  sxu_qer_t *el = &slot->val;

  if (BIT_ISSET (uqer->grp.fields, UPDATE_QER_GATE_STATUS))
    {
      el->gate_closed_ul = uqer->gate_status.ul != 0;
      el->gate_closed_dl = uqer->gate_status.dl != 0;
    }

  if (BIT_ISSET (uqer->grp.fields, UPDATE_QER_MBR))
    {
      el->has_maximum_bitrate = 1;
      el->maximum_bitrate[UPF_DIR_UL] = uqer->mbr.ul;
      el->maximum_bitrate[UPF_DIR_DL] = uqer->mbr.dl;
    }
}

int
upf_sxu_stage_1_provide_pfcp_actions (upf_sxu_t *sxu,
                                      upf_sxu_pfcp_actions_t *actions)
{
  pfcp_ie_create_pdr_t *cpdr = NULL;
  pfcp_ie_update_pdr_t *updr = NULL;
  pfcp_ie_remove_pdr_t *rpdr = NULL;
  pfcp_ie_create_far_t *cfar = NULL;
  pfcp_ie_update_far_t *ufar = NULL;
  pfcp_ie_remove_far_t *rfar = NULL;
  pfcp_ie_create_urr_t *curr = NULL;
  pfcp_ie_update_urr_t *uurr = NULL;
  pfcp_ie_remove_urr_t *rurr = NULL;
  pfcp_ie_create_qer_t *cqer = NULL;
  pfcp_ie_update_qer_t *uqer = NULL;
  pfcp_ie_remove_qer_t *rqer = NULL;

  vec_foreach (cpdr, actions->create_pdrs)
    {
      if (_sxu_ensure_op_init_pdr_action (sxu, cpdr->pdr_id, false, true,
                                          &cpdr->upf_update_xid))
        return upf_sxu_pdr_error_wrap (sxu, ~0, "cpdr a");
      if (_upf_sxu_handle_create_pdr (sxu, cpdr))
        return upf_sxu_pdr_error_wrap (sxu, cpdr->upf_update_xid, "cpdr");
    }
  vec_foreach (cfar, actions->create_fars)
    {
      if (_sxu_ensure_op_init_far_action (sxu, cfar->far_id, false, true,
                                          &cfar->upf_update_xid))
        return upf_sxu_far_error_wrap (sxu, ~0, "cfar a");
      upf_debug ("creating FAR %d => %d", cfar->upf_update_xid, cfar->far_id);
      if (_upf_sxu_handle_create_far (sxu, cfar))
        return upf_sxu_far_error_wrap (sxu, cfar->upf_update_xid, "cfar");
    }
  vec_foreach (curr, actions->create_urrs)
    {
      if (_sxu_ensure_op_init_urr_action (sxu, curr->urr_id, false, true,
                                          &curr->upf_update_xid))
        return upf_sxu_urr_error_wrap (sxu, ~0, "curr a");
      if (_upf_sxu_handle_create_urr (sxu, curr))
        return upf_sxu_urr_error_wrap (sxu, curr->upf_update_xid, "curr");
    }
  vec_foreach (cqer, actions->create_qers)
    {
      if (_sxu_ensure_op_init_qer_action (sxu, cqer->qer_id, false, true,
                                          &cqer->upf_update_xid))
        return upf_sxu_urr_error_wrap (sxu, ~0, "cqer a");

      _upf_sxu_handle_create_qer (sxu, cqer);
    }

  vec_foreach (updr, actions->update_pdrs)
    {
      if (_sxu_ensure_op_init_pdr_action (sxu, updr->pdr_id, true, true,
                                          &updr->upf_update_xid))
        return upf_sxu_pdr_error_wrap (sxu, ~0, "updr a");
      if (_upf_sxu_handle_update_pdr (sxu, updr))
        return upf_sxu_pdr_error_wrap (sxu, updr->upf_update_xid, "updr");
    }
  vec_foreach (ufar, actions->update_fars)
    {
      if (_sxu_ensure_op_init_far_action (sxu, ufar->far_id, true, true,
                                          &ufar->upf_update_xid))
        return upf_sxu_far_error_wrap (sxu, ~0, "ufar a");
      if (_upf_sxu_handle_update_far (sxu, ufar))
        return upf_sxu_far_error_wrap (sxu, ufar->upf_update_xid, "ufar");
    }
  vec_foreach (uurr, actions->update_urrs)
    {
      if (_sxu_ensure_op_init_urr_action (sxu, uurr->urr_id, true, true,
                                          &uurr->upf_update_xid))
        return upf_sxu_urr_error_wrap (sxu, ~0, "uurr a");
      if (_upf_sxu_handle_update_urr (sxu, uurr))
        return upf_sxu_urr_error_wrap (sxu, uurr->upf_update_xid, "uurr");
    }
  vec_foreach (uqer, actions->update_qers)
    {
      if (_sxu_ensure_op_init_qer_action (sxu, uqer->qer_id, true, true,
                                          &uqer->upf_update_xid))
        return upf_sxu_qer_error_wrap (sxu, ~0, "uqer a");
      _upf_sxu_handle_update_qer (sxu, uqer);
    }

  vec_foreach (rpdr, actions->remove_pdrs)
    {
      if (_sxu_ensure_op_init_pdr_action (sxu, rpdr->pdr_id, true, false,
                                          &rpdr->upf_update_xid))
        return upf_sxu_pdr_error_wrap (sxu, ~0, "rpdr a");
      _upf_sxu_pdr_xid_ref_ops (
        sxu, vec_elt_at_index (sxu->pdrs, rpdr->upf_update_xid),
        SXU_REF_GENERIC_OP__UNREF);
    }
  vec_foreach (rfar, actions->remove_fars)
    {
      if (_sxu_ensure_op_init_far_action (sxu, rfar->far_id, true, false,
                                          &rfar->upf_update_xid))
        return upf_sxu_far_error_wrap (sxu, ~0, "rfar a");
      _upf_sxu_far_xid_ref_ops (
        sxu, vec_elt_at_index (sxu->fars, rfar->upf_update_xid),
        SXU_REF_GENERIC_OP__UNREF);
    }
  vec_foreach (rurr, actions->remove_urrs)
    {
      if (_sxu_ensure_op_init_urr_action (sxu, rurr->urr_id, true, false,
                                          &rurr->upf_update_xid))
        return upf_sxu_urr_error_wrap (sxu, ~0, "rurr a");
      _upf_sxu_urr_xid_ref_ops (
        sxu, vec_elt_at_index (sxu->urrs, rurr->upf_update_xid),
        SXU_REF_GENERIC_OP__UNREF);
    }
  vec_foreach (rqer, actions->remove_qers)
    {
      if (_sxu_ensure_op_init_qer_action (sxu, rqer->qer_id, true, false,
                                          &rqer->upf_update_xid))
        return upf_sxu_qer_error_wrap (sxu, ~0, "rqer a");
      _upf_sxu_qer_xid_ref_ops (
        sxu, vec_elt_at_index (sxu->qers, rqer->upf_update_xid),
        SXU_REF_GENERIC_OP__UNREF);
    }

  return 0;
}

void
upf_sxu_stage_1_provide_delete_actions (upf_sxu_t *sxu)
{
  sxu->is_session_deletion = 1;

#define _(name, plural)                                                       \
  sxu_slot_##name##_t *name;                                                  \
  vec_foreach (name, sxu->plural)                                             \
    {                                                                         \
      name->state.will_exist = 0;                                             \
      _upf_sxu_##name##_xid_ref_ops (sxu, name, SXU_REF_GENERIC_OP__UNREF);   \
    }
  foreach_sxu_pfcp_type
#undef _
}

typedef struct
{
#define _(name, plural) upf_xid_t name##_lid_to_xid[UPF_LID_MAX];
  foreach_sxu_nontemporary_type
#undef _
} sxu_init_remap_t;

#define _(name, plural)                                                       \
  static void _sxu_vecs_create_##plural##_slots (                             \
    upf_sxu_t *sxu, upf_lidset_t *used, sxu_init_remap_t *remap)              \
  {                                                                           \
    u8 count = upf_lidset_count (used);                                       \
    if (count == 0)                                                           \
      return;                                                                 \
                                                                              \
    vec_validate (sxu->plural, count - 1);                                    \
    upf_lid_t lid_zero_start = 0;                                             \
    upf_xid_t xid = 0;                                                        \
    upf_lidset_foreach (lid, used)                                            \
      {                                                                       \
        int zero_lids = lid - lid_zero_start;                                 \
        ASSERT (zero_lids >= 0 && zero_lids < UPF_LIDSET_MAX);                \
        if (zero_lids != 0)                                                   \
          /* invalidate empty lid slots xid mapping */                        \
          memset (remap->name##_lid_to_xid + lid_zero_start, 0xff,            \
                  sizeof (upf_lid_t) * zero_lids);                            \
        lid_zero_start = lid + 1;                                             \
                                                                              \
        sxu_slot_##name##_t *p = vec_elt_at_index (sxu->plural, xid);         \
        p->state = (sxu_slot_state_t){                                        \
          .references = 0,                                                    \
          .has_existed = 1,                                                   \
          .will_exist = 1,                                                    \
          .lid = lid,                                                         \
        };                                                                    \
        remap->name##_lid_to_xid[lid] = xid;                                  \
                                                                              \
        xid += 1;                                                             \
      }                                                                       \
  }
foreach_sxu_nontemporary_type
#undef _

#define _(name, plural)                                                       \
  static void _sxu_vecs_create_##plural##_linear (upf_sxu_t *sxu, u8 count,   \
                                                  sxu_init_remap_t *remap)    \
  {                                                                           \
    if (count == 0)                                                           \
      return;                                                                 \
                                                                              \
    vec_validate (sxu->plural, count - 1);                                    \
                                                                              \
    /* here lid == xid */                                                     \
    for (u8 xlid = 0; xlid < count; xlid++)                                   \
      {                                                                       \
        sxu_slot_##name##_t *p = vec_elt_at_index (sxu->plural, xlid);        \
                                                                              \
        p->state = (sxu_slot_state_t){                                        \
          .references = 0,                                                    \
          .has_existed = 1,                                                   \
          .will_exist = 1,                                                    \
          .lid = xlid,                                                        \
        };                                                                    \
        remap->name##_lid_to_xid[xlid] = xlid;                                \
      }                                                                       \
  }
  foreach_sxu_nontemporary_type
#undef _

#define _(name, plural)                                                       \
  static __clib_warn_unused_result __clib_unused upf_xid_t                    \
    _sxu_init_remap_##name (sxu_init_remap_t *remap, upf_lid_t lid)           \
  {                                                                           \
    if (is_valid_id (lid))                                                    \
      return remap->name##_lid_to_xid[lid];                                   \
    else                                                                      \
      return -1;                                                              \
  }
    foreach_sxu_nontemporary_type
#undef _

  static void
  _upf_sxu_1_init_pdr_from_rules (upf_sxu_t *sxu, upf_rules_t *rules, u8 xlid,
                                  sxu_init_remap_t *remap)
{
  rules_pdr_t *from = upf_rules_get_pdr (rules, xlid);
  sxu_slot_pdr_t *slot = vec_elt_at_index (sxu->pdrs, xlid);
  sxu_pdr_t *to = &slot->val;

  slot->key = from->pfcp_id;

  *to = (sxu_pdr_t){
    .gtpu_outer_header_removal = from->gtpu_outer_header_removal,
    .precedence = from->precedence,
    .pdi.source_interface = from->src_intf,
    .pdi.nwi_id = from->nwi_id,

    ._old_acl_cached_id = from->acl_cached_id,

    .pdi.sdf_filters_new = NULL,
    .do_reuse_acls = true,
  };

  to->pdi.ref_traffic_ep_xid =
    _sxu_init_remap_traffic_ep (remap, from->traffic_ep_lid);

  to->pdi.ref_application_xid = ~0;

  if (is_valid_id (from->application_id))
    {
      sxu_adf_application_key_t key = {
        .application_id = from->application_id,
      };
      to->pdi.ref_application_xid =
        sxu_ensure_adf_application_by_key (sxu, key);
    }

  to->ref_far_xid = _sxu_init_remap_far (remap, from->far_lid);

  upf_lidset_foreach (urr_lid, &from->urr_lids)
    upf_lidset_set (&to->refs_urr_xids, remap->urr_lid_to_xid[urr_lid]);
  upf_lidset_foreach (qer_lid, &from->qer_lids)
    upf_lidset_set (&to->refs_qer_xids, remap->qer_lid_to_xid[qer_lid]);
}

static void
_upf_sxu_1_init_far_from_rules (upf_sxu_t *sxu, upf_rules_t *rules, u8 xlid,
                                sxu_init_remap_t *remap)
{
  rules_far_t *from = upf_rules_get_far (rules, xlid);
  sxu_slot_far_t *slot = vec_elt_at_index (sxu->fars, xlid);
  sxu_far_t *to = &slot->val;

  slot->key = from->pfcp_id;
  *to = (sxu_far_t){
    .apply_action = from->apply_action,
    .ipfix_policy = from->ipfix_policy_set,
    .fp.policy_id = ~0,
  };

  to->nat_binding_xid = ~0;
  // there can be only single nat binding
  if (from->apply_action == UPF_FAR_ACTION_FORWARD && from->forward.do_nat)
    to->nat_binding_xid = 0;

  rules_far_forward_t *ff = &from->forward;
  to->fp.destination_interface = ff->dst_intf;
  to->fp.nwi_id = ff->nwi_id;
  to->fp.has_redirect_information = ff->has_redirect_information;
  to->fp.has_outer_header_creation = ff->has_outer_header_creation;
  to->fp.bbf_apply_action_nat = is_valid_id (to->nat_binding_xid);

  if (ff->has_forwarding_policy)
    {
      sxu_policy_ref_key_t fp_ref_key = { .policy_id =
                                            ff->forwarding_policy_id };
      (void) sxu_ensure_policy_ref_by_key (sxu, fp_ref_key);
      to->fp.policy_id = ff->forwarding_policy_id;
    }

  if (ff->has_redirect_information)
    {
      to->fp.redirect_information.uri = vec_dup (ff->redirect_uri);
      to->fp.redirect_information.type = PFCP_REDIRECT_INFORMATION_HTTP;
    }

  if (ff->has_outer_header_creation)
    {
      to->fp.ohc.addr4 = ff->ohc.addr4;
      to->fp.ohc.addr6 = ff->ohc.addr6;
      to->fp.ohc.teid = ff->ohc.teid;
    }

  if (is_valid_id (ff->nwi_id))
    {
      sxu_nwi_stat_key_t nwi_stat_key = { .nwi_id = ff->nwi_id };
      (void) sxu_ensure_nwi_stat_by_key (sxu, nwi_stat_key);
    }
  if (ff->has_outer_header_creation &&
      is_valid_id (ff->ohc.src_gtpu_endpoint_id))
    {
      sxu_gtpu_ep_stat_key_t gtpu_stat_key = {
        .gtpu_ep_id = ff->ohc.src_gtpu_endpoint_id
      };
      (void) sxu_ensure_gtpu_ep_stat_by_key (sxu, gtpu_stat_key);
    }
}

static void
_upf_sxu_1_init_urr_from_rules (upf_sxu_t *sxu, upf_rules_t *rules,
                                upf_lid_t lid, sxu_init_remap_t *remap)
{
  rules_urr_t *from = upf_rules_get_urr (rules, lid);
  sxu_slot_urr_t *slot =
    vec_elt_at_index (sxu->urrs, remap->urr_lid_to_xid[lid]);
  sxu_urr_t *to = &slot->val;

  slot->key = from->pfcp_id;

  *to = (sxu_urr_t){
    .reporting_triggers = from->enabled_triggers,
    .update_flags = 0,
    .measurement_method_volume = from->measurement_method_volume,
    .measurement_method_duration = from->measurement_method_duration,
    .measurement_method_event = from->measurement_method_event,
    .has_volume_quota_ul = from->has_quota_ul,
    .has_volume_quota_dl = from->has_quota_dl,
    .has_volume_quota_tot = from->has_quota_tot,
    .has_time_quota = from->has_quota_time,
    .measurement_period = from->measurement_period.period,
    .time_threshold = from->time.threshold_set,
    .time_quota = from->time.quota_set,
    .quota_holding_time = from->quota_holding_time.period,
    .quota_validity_time = from->quota_validity_time.period,
    .monitoring_time = from->monitoring_time,
    .volume_threshold_total = from->vol.threshold_set.tot,
    .volume_threshold_ul = from->vol.threshold_set.ul,
    .volume_threshold_dl = from->vol.threshold_set.dl,
    .volume_quota_total = from->vol.quota_set.tot,
    .volume_quota_ul = from->vol.quota_set.ul,
    .volume_quota_dl = from->vol.quota_set.dl,
  };
}

// should be called after all sxu_urr_t are initialized, because here we have
// references between same object
static void
_upf_sxu_1_init_urr_liusa_from_rules (upf_sxu_t *sxu, upf_rules_t *rules,
                                      sxu_init_remap_t *remap)
{
  // reverse references, because in rules references are from Main to Linked,
  // but during update we want from Linked to Main
  upf_lidset_foreach (main_lid, &rules->slots.urrs)
    {
      rules_urr_t *from_main = upf_rules_get_urr (rules, main_lid);

      upf_lidset_foreach (linked_lid, &from_main->liusa_urrs_lids)
        {
          sxu_slot_urr_t *linked_slot =
            vec_elt_at_index (sxu->urrs, remap->urr_lid_to_xid[linked_lid]);
          sxu_urr_t *linked_to = &linked_slot->val;
          // reference will happen after
          upf_lidset_set (&linked_to->refs_linked_urr_xids,
                          remap->urr_lid_to_xid[main_lid]);
        }
    }
}

static void
_upf_sxu_1_init_qer_from_rules (upf_sxu_t *sxu, upf_rules_t *rules, u8 xlid,
                                sxu_init_remap_t *remap)
{
  rules_qer_t *from = upf_rules_get_qer (rules, xlid);
  sxu_slot_qer_t *slot = vec_elt_at_index (sxu->qers, xlid);
  sxu_qer_t *to = &slot->val;

  slot->key = from->pfcp_id;

  *to = (sxu_qer_t){
    .gate_closed_dl = from->gate_closed_dl,
    .gate_closed_ul = from->gate_closed_ul,
    .has_maximum_bitrate = from->has_mbr,
    .maximum_bitrate[UPF_DIR_UL] = from->maximum_bitrate[UPF_DIR_UL],
    .maximum_bitrate[UPF_DIR_DL] = from->maximum_bitrate[UPF_DIR_DL],
  };
}

static void
_upf_sxu_1_init_tep_from_rules (upf_sxu_t *sxu, upf_rules_t *rules,
                                upf_lid_t lid, sxu_init_remap_t *remap)
{
  rules_tep_t *from = upf_rules_get_tep (rules, lid);
  sxu_slot_traffic_ep_t *slot =
    vec_elt_at_index (sxu->traffic_eps, remap->traffic_ep_lid_to_xid[lid]);
  sxu_traffic_ep_key_t *key = &slot->key;
  sxu_traffic_ep_t *to = &slot->val;

  *key = (sxu_traffic_ep_key_t){
    .is_destination_ip = from->is_destination_ip,
    .is_gtpu = from->is_gtpu,
    .is_ip4 = from->is_ue_ip4,
    .is_ip6 = from->is_ue_ip6,
    .intf = from->intf,
    .nwi_id = from->nwi_id,
    .ue_addr4 = from->ue_addr4,
    .ue_addr6 = from->ue_addr6,
    .ref_f_teid_allocation_xid = ~0,
    .ref_gtpu_ep_xid = ~0,
  };
  *to = (sxu_traffic_ep_t){
    .ref_ue_ip4_xid = ~0,
    .ref_ue_ip6_xid = ~0,
  };

  if (from->is_gtpu)
    {
      key->ref_f_teid_allocation_xid = _sxu_init_remap_f_teid_allocation (
        remap, from->match.gtpu.fteid_allocation_lid);

      if (is_valid_id (from->match.gtpu.fteid_allocation_lid))
        // then it is not owned by teid, but by f_teid_allocation
        key->ref_gtpu_ep_xid = ~0;
      else
        key->ref_gtpu_ep_xid =
          remap->traffic_ep_lid_to_xid[from->match.gtpu.gtpu_ep_lid];
    }
  else
    {
      to->ref_ue_ip4_xid =
        _sxu_init_remap_ue_ip_ep4 (remap, from->match.ip.traffic_ep4_lid);
      to->ref_ue_ip6_xid =
        _sxu_init_remap_ue_ip_ep6 (remap, from->match.ip.traffic_ep6_lid);
    }

  to->capture_set_xid =
    _sxu_init_remap_capture_set (remap, from->capture_set_lid);

  sxu_nwi_stat_key_t nwi_stat_key = { .nwi_id = from->nwi_id };
  (void) sxu_ensure_nwi_stat_by_key (sxu, nwi_stat_key);
}

static void
_upf_sxu_1_init_f_teid_from_rules (upf_sxu_t *sxu, upf_rules_t *rules, u8 xlid,
                                   sxu_init_remap_t *remap)
{
  rules_f_teid_t *from = upf_rules_get_f_teid (rules, xlid);
  sxu_slot_f_teid_allocation_t *slot =
    vec_elt_at_index (sxu->f_teid_allocations, xlid);
  sxu_f_teid_allocation_key_t *key = &slot->key;
  sxu_f_teid_allocation_t *to = &slot->val;

  *key = (sxu_f_teid_allocation_key_t){
    .intf = from->intf,
    .nwi_id = from->nwi_id,
    .choose_id = from->choose_id,
  };
  *to = (sxu_f_teid_allocation_t){
    .ref_gtpu_ep_xid =
      _sxu_init_remap_gtpu_ep (remap, from->gtpu_endpoint_lid),
  };
}

static void
_upf_sxu_1_init_gtpu_ep_from_rules (upf_sxu_t *sxu, upf_rules_t *rules,
                                    upf_lid_t lid, sxu_init_remap_t *remap)
{
  rules_ep_gtpu_t *from = upf_rules_get_ep_gtpu (rules, lid);
  sxu_slot_gtpu_ep_t *slot =
    vec_elt_at_index (sxu->gtpu_eps, remap->gtpu_ep_lid_to_xid[lid]);
  sxu_gtpu_ep_key_t *key = &slot->key;
  sxu_gtpu_ep_t *to = &slot->val;

  *key = (sxu_gtpu_ep_key_t){
    .gtpu_ep_id = from->gtpu_ep_id,
    .teid = from->teid,
  };
  *to = (sxu_gtpu_ep_t){
    // will be set later from teps
    .intf = ~0,
    .nwi_id = ~0,
  };

  sxu_gtpu_ep_stat_key_t gtpu_stat_key = { .gtpu_ep_id = key->gtpu_ep_id };
  (void) sxu_ensure_gtpu_ep_stat_by_key (sxu, gtpu_stat_key);
}

static void
_upf_sxu_1_init_ue_ip4_from_rules (upf_sxu_t *sxu, upf_rules_t *rules,
                                   upf_lid_t lid, sxu_init_remap_t *remap)
{
  rules_ep_ip_t *from = upf_rules_get_ep_ip4 (rules, lid);
  sxu_slot_ue_ip_ep4_t *slot =
    vec_elt_at_index (sxu->ue_ip_eps4, remap->ue_ip_ep4_lid_to_xid[lid]);
  sxu_ue_ip_ep4_key_t *key = &slot->key;
  sxu_ue_ip_ep4_t *to = &slot->val;

  rules_tep_t *from_tep = upf_rules_get_tep (rules, from->traffic_ep_lid);

  *key = (sxu_ue_ip_ep4_key_t){
    .addr = from_tep->ue_addr4,
    .fib_id = from->fib_index,
    .is_source_matching = from->is_ue_side,
  };
  *to = (sxu_ue_ip_ep4_t){
    .dpo_result_id = from->dpo_result_id,
  };
}

static void
_upf_sxu_1_init_ue_ip6_from_rules (upf_sxu_t *sxu, upf_rules_t *rules,
                                   upf_lid_t lid, sxu_init_remap_t *remap)
{
  rules_ep_ip_t *from = upf_rules_get_ep_ip6 (rules, lid);
  sxu_slot_ue_ip_ep6_t *slot =
    vec_elt_at_index (sxu->ue_ip_eps6, remap->ue_ip_ep6_lid_to_xid[lid]);
  sxu_ue_ip_ep6_key_t *key = &slot->key;
  sxu_ue_ip_ep6_t *to = &slot->val;

  rules_tep_t *from_tep = upf_rules_get_tep (rules, from->traffic_ep_lid);

  *key = (sxu_ue_ip_ep6_key_t){
    .addr = from_tep->ue_addr6,
    .fib_id = from->fib_index,
    .is_source_matching = from->is_ue_side,
  };
  *to = (sxu_ue_ip_ep6_t){
    .dpo_result_id = from->dpo_result_id,
  };
}

static void
_upf_sxu_1_init_capture_set_from_rules (upf_sxu_t *sxu, upf_rules_t *rules,
                                        u8 cap_set_xlid,
                                        sxu_init_remap_t *remap)
{
  rules_netcap_set_t *from = upf_rules_get_netcap_set (rules, cap_set_xlid);
  sxu_slot_capture_set_t *to_slot =
    vec_elt_at_index (sxu->capture_sets, cap_set_xlid);

  to_slot->key = (sxu_capture_set_key_t){
    .nwi_id = from->nwi_id,
    .intf = from->intf,
  };
  to_slot->val = (sxu_capture_set_t){
    .capture_streams = NULL,
  };

  rules_netcap_stream_t *from_cap_stream;
  vec_foreach (from_cap_stream, from->streams)
    {
      sxu_imsi_capture_key_t imsi_cap_key = {
        .imsi_capture_id = from_cap_stream->imsi_capture_id,
      };
      u8 imsi_cap_xid = sxu_ensure_imsi_capture_by_key (sxu, imsi_cap_key);

      vec_validate_init_empty (to_slot->val.capture_streams, imsi_cap_xid, ~0);
      *vec_elt_at_index (to_slot->val.capture_streams, imsi_cap_xid) =
        from_cap_stream->netcap_stream_id;
    }
}

void
upf_sxu_1_init_from_rules (upf_sxu_t *sxu, upf_rules_t *rules)
{
  sxu_init_remap_t remap;
  u8 xlid; // when lid == xid (linear storage in rules)

  _sxu_vecs_create_pdrs_linear (sxu, rules->pdrs.len, &remap);
  _sxu_vecs_create_fars_linear (sxu, rules->fars.len, &remap);
  _sxu_vecs_create_urrs_slots (sxu, &rules->slots.urrs, &remap);
  _sxu_vecs_create_qers_linear (sxu, rules->qers.len, &remap);
  _sxu_vecs_create_traffic_eps_slots (sxu, &rules->slots.teps, &remap);
  _sxu_vecs_create_f_teid_allocations_linear (sxu, rules->f_teids.len, &remap);
  _sxu_vecs_create_gtpu_eps_slots (sxu, &rules->slots.ep_gtpus, &remap);
  _sxu_vecs_create_ue_ip_eps4_slots (sxu, &rules->slots.ep_ips4, &remap);
  _sxu_vecs_create_ue_ip_eps6_slots (sxu, &rules->slots.ep_ips6, &remap);
  _sxu_vecs_create_capture_sets_linear (sxu, rules->netcap_sets.len, &remap);

  vec_foreach_index (xlid, sxu->pdrs)
    _upf_sxu_1_init_pdr_from_rules (sxu, rules, xlid, &remap);

  vec_foreach_index (xlid, sxu->fars)
    _upf_sxu_1_init_far_from_rules (sxu, rules, xlid, &remap);

  upf_lidset_foreach (lid, &rules->slots.urrs)
    _upf_sxu_1_init_urr_from_rules (sxu, rules, lid, &remap);

  _upf_sxu_1_init_urr_liusa_from_rules (sxu, rules, &remap);

  vec_foreach_index (xlid, sxu->qers)
    _upf_sxu_1_init_qer_from_rules (sxu, rules, xlid, &remap);

  upf_lidset_foreach (lid, &rules->slots.teps)
    _upf_sxu_1_init_tep_from_rules (sxu, rules, lid, &remap);

  vec_foreach_index (xlid, sxu->f_teid_allocations)
    _upf_sxu_1_init_f_teid_from_rules (sxu, rules, xlid, &remap);

  upf_lidset_foreach (lid, &rules->slots.ep_gtpus)
    _upf_sxu_1_init_gtpu_ep_from_rules (sxu, rules, lid, &remap);

  upf_lidset_foreach (lid, &rules->slots.ep_ips4)
    _upf_sxu_1_init_ue_ip4_from_rules (sxu, rules, lid, &remap);

  upf_lidset_foreach (lid, &rules->slots.ep_ips6)
    _upf_sxu_1_init_ue_ip6_from_rules (sxu, rules, lid, &remap);

  vec_foreach_index (xlid, sxu->capture_sets)
    _upf_sxu_1_init_capture_set_from_rules (sxu, rules, xlid, &remap);

  if (is_valid_id (rules->nat_pool_id))
    {
      sxu_nat_binding_key_t key = { rules->nat_pool_id };
      upf_xid_t xid = sxu_ensure_nat_binding_by_key (sxu, key);
      ASSERT (xid == 0); // single nat binding per session only

      sxu_slot_nat_binding_t *slot = vec_elt_at_index (sxu->nat_bindings, xid);
      slot->val.binding_id = rules->nat_binding_id;
      slot->state.has_existed = 1;
      slot->state.will_exist = 1;

      slot->val.capture_set_xid =
        _sxu_init_remap_capture_set (&remap, rules->nat_netcap_set_lid);
    }

  // Init temporary objects state
  sxu_slot_adf_application_t *adf_app;
  vec_foreach (adf_app, sxu->adf_applications)
    {
      adf_app->state.has_existed = 1;
      adf_app->state.will_exist = 1;
    }
  sxu_slot_imsi_capture_t *imsi_cap;
  vec_foreach (imsi_cap, sxu->imsi_captures)
    {
      imsi_cap->state.has_existed = 1;
      imsi_cap->state.will_exist = 1;
    }
  sxu_slot_nwi_stat_t *nwi_stat;
  vec_foreach (nwi_stat, sxu->nwi_stats)
    {
      nwi_stat->state.has_existed = 1;
      nwi_stat->state.will_exist = 1;
    }
  sxu_slot_policy_ref_t *fp_ref;
  vec_foreach (fp_ref, sxu->policy_refs)
    {
      fp_ref->state.has_existed = 1;
      fp_ref->state.will_exist = 1;
    }
  sxu_slot_gtpu_ep_stat_t *gtpu_stat;
  vec_foreach (gtpu_stat, sxu->gtpu_ep_stats)
    {
      gtpu_stat->state.has_existed = 1;
      gtpu_stat->state.will_exist = 1;
    }

  _upf_sxu_xid_ref_ops (sxu, SXU_REF_GENERIC_OP__REF);
  sxu->inactivity_timeout = rules->inactivity_timeout;
}
