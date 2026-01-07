/*
 * Copyright (c) 2018-2025 Travelping GmbH
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

#include <vlib/unix/plugin.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/random.h>

#include "upf/upf.h"
#include "upf/utils/ip_helpers.h"
#include "upf/upf_stats.h"
#include "upf/utils/upf_mt.h"
#include "upf/pfcp/pfcp_proto.h"
#include "upf/pfcp/upf_pfcp_handlers.h"
#include "upf/pfcp/upf_pfcp_server.h"
#include "upf/pfcp/upf_pfcp_assoc.h"
#include "upf/sxu/upf_session_update.h"
#include "upf/nat/nat.h"
#include "upf/rules/upf_gtpu.h"

#define UPF_DEBUG_ENABLE 0

extern char *vpe_version_string;

static void
_start_procedure_with_pfcp_request (upf_session_t *sx,
                                    upf_pfcp_message_t *in_req,
                                    upf_mt_session_req_kind_t req_kind,
                                    upf_sxu_t *sxu,
                                    upf_lidset_t *p_immediate_report_urrs)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  // create response promise
  upf_pfcp_response_t *pfcp_resp = upf_pfcp_response_create (in_req);

  upf_session_procedure_t *procedure = upf_session_enqueue_procedure (
    sx, req_kind, sxu, p_immediate_report_urrs, false);

  procedure->response_id = pfcp_resp - psm->responses;
}

/*************************************************************************/

/* message helpers */

static void
_build_ue_ip_address_information (
  pfcp_ie_ue_ip_address_pool_information_t **ue_pool_info)
{
  upf_main_t *um = &upf_main;
  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_pool_t *np;
  upf_ue_ip_pool_info_t *ue_p;

  vec_alloc (*ue_pool_info, pool_elts (um->ueip_pools));

  pool_foreach (ue_p, um->ueip_pools)
    {
      pfcp_ie_ue_ip_address_pool_information_t *ueif;

      vec_add2 (*ue_pool_info, ueif, 1);
      ueif->ue_ip_address_pool_identity = vec_dup (ue_p->identity);
      BIT_SET (ueif->grp.fields, UE_IP_ADDRESS_POOL_INFORMATION_POOL_IDENTIFY);

      ueif->network_instance = vec_dup (ue_p->nwi_name);
      BIT_SET (ueif->grp.fields,
               UE_IP_ADDRESS_POOL_INFORMATION_NETWORK_INSTANCE);

      upf_nwi_t *ue_p_nwi = upf_nwi_get_by_name (ue_p->nwi_name);
      u32 ue_p_nwi_id = ue_p_nwi - um->nwis;

      pool_foreach (np, unm->nat_pools)
        {
          upf_interface_t *nwif =
            pool_elt_at_index (um->nwi_interfaces, np->nwif_id);
          if (ue_p_nwi_id != nwif->nwi_id)
            continue;

          pfcp_ie_bbf_nat_port_block_t *block;

          vec_add2 (ueif->port_blocks, block, 1);
          *block = vec_dup (np->name);
          BIT_SET (ueif->grp.fields,
                   UE_IP_ADDRESS_POOL_INFORMATION_BBF_NAT_PORT_BLOCK);
        }
    }
}

static void
_build_user_plane_ip_resource_information (
  pfcp_ie_user_plane_ip_resource_information_t **upip)
{
  upf_main_t *um = &upf_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  upf_gtpu_endpoint_t *endp;

  vec_alloc (*upip, pool_elts (ugm->endpoints));

  pool_foreach (endp, ugm->endpoints)
    {
      pfcp_ie_user_plane_ip_resource_information_t *r;

      vec_add2 (*upip, r, 1);

      upf_nwi_t *nwi = pool_elt_at_index (um->nwis, endp->nwi_id);

      if (vec_len (nwi->name)) // if not default NWI
        {
          r->flags |= PFCP_USER_PLANE_IP_RESOURCE_INFORMATION_ASSONI;
          r->network_instance = vec_dup (nwi->name);
        }

      bool invalid_src_if = false;
      switch (endp->intf)
        {
        case UPF_INTERFACE_TYPE_ACCESS:
          r->source_intf = PFCP_SRC_INTF_ACCESS;
          break;
        case UPF_INTERFACE_TYPE_CORE:
          r->source_intf = PFCP_SRC_INTF_CORE;
          break;
        case UPF_INTERFACE_TYPE_SGI_LAN:
          r->source_intf = PFCP_SRC_INTF_SGI_LAN;
          break;
        case UPF_INTERFACE_TYPE_CP:
          r->source_intf = PFCP_SRC_INTF_CP;
          break;
        default:
          invalid_src_if = true;
          ASSERT (0 && "Invalid src if value");
        }
      if (!invalid_src_if)
        r->flags |= PFCP_USER_PLANE_IP_RESOURCE_INFORMATION_ASSOSI;

      // TODO: restore functionality
      // if (endp->mask != 0)
      //   {
      //     r->teid_range_indication = __builtin_popcount (endp->mask);
      //     r->teid_range = (endp->teid >> 24);
      //   }

      if (!ip4_address_is_zero (&endp->ip4))
        {
          r->flags |= PFCP_USER_PLANE_IP_RESOURCE_INFORMATION_V4;
          r->ip4 = endp->ip4;
        }

      if (!ip6_address_is_zero (&endp->ip6))
        {
          r->flags |= PFCP_USER_PLANE_IP_RESOURCE_INFORMATION_V6;
          r->ip6 = endp->ip6;
        }
    }
}

/* message handlers */
static upf_pfcp_message_rv_t
_handle_heartbeat_request (upf_pfcp_message_t *msg, pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_decoded_msg_t resp_dmsg = {
    .type = PFCP_MSG_HEARTBEAT_RESPONSE,
    .simple_response = {},
  };
  pfcp_simple_response_t *resp = &resp_dmsg.simple_response;

  memset (resp, 0, sizeof (*resp));
  BIT_SET (resp->grp.fields, PFCP_RESPONSE_RECOVERY_TIME_STAMP);
  resp->response.recovery_time_stamp = psm->recovery;

  upf_debug ("recovery: %d, %x", psm->recovery, psm->recovery);

  upf_pfcp_server_send_response (msg, &resp_dmsg);

  return UPF_PFCP_MESSAGE_RV_SUCCESS;
}

static upf_pfcp_response_rv_t
_handle_heartbeat_request_response (upf_pfcp_message_t *msg,
                                    upf_pfcp_request_t *our_req,
                                    pfcp_decoded_msg_t *dmsg)
{
  upf_main_t *um = &upf_main;
  pfcp_server_main_t *psm = &pfcp_server_main;

  if (dmsg->type != PFCP_MSG_HEARTBEAT_RESPONSE)
    return UPF_PFCP_RESPONSE_RV_IGNORE;

  pfcp_ie_recovery_time_stamp_t ts =
    dmsg->simple_response.response.recovery_time_stamp;

  upf_assoc_t *assoc = pool_elt_at_index (um->assocs, our_req->assoc.id);
  ASSERT (!assoc->is_released);

  if (ts > assoc->recovery_time_stamp)
    {
      upf_assoc_delete (assoc, "remote peer restarted");
      return UPF_PFCP_RESPONSE_RV_ACCEPT;
    }
  else if (ts < assoc->recovery_time_stamp)
    {
      /* 3GPP TS 23.007, Sect. 19A:
       *
       * If the value of a Recovery Time Stamp previously stored for a peer is
       * larger than the Recovery Time Stamp value received in the Heartbeat
       * Response message or the PFCP message, this indicates a possible race
       * condition (newer message arriving before the older one). The received
       * PFCP node related message and the received new Recovery Time Stamp
       * value shall be discarded and an error may be logged.
       */
      return UPF_PFCP_RESPONSE_RV_IGNORE;
    }
  else
    {
      upf_debug ("restarting HB timer\n");
      upf_timer_stop_safe (0, &assoc->heartbeat_timer);
      assoc->heartbeat_timer = upf_timer_start_secs (
        0, psm->heartbeat_cfg.timeout, UPF_TIMER_KIND_PFCP_HEARTBEAT,
        assoc - um->assocs, 0);
      return UPF_PFCP_RESPONSE_RV_ACCEPT;
    }
}

static void
_handle_heartbeat_request_timeout (upf_pfcp_request_t *req)
{
  upf_main_t *um = &upf_main;

  if (pool_is_free_index (um->assocs, req->assoc.id))
    {
      ASSERT (0 && "Invalid assoc id");
      clib_warning ("invalid assoc_id %d", req->assoc.id);
      return;
    }

  upf_assoc_t *a = pool_elt_at_index (um->assocs, req->assoc.id);

  ASSERT (!a->is_released); // shouldn't happen
  if (a->is_released)
    return;

  vlib_log_info (um->log_class,
                 "PFCP Association lost: node %U, local IP %U, remote IP %U\n",
                 format_pfcp_ie_node_id, &a->node_id, format_ip46_address,
                 &a->lcl_addr, IP46_TYPE_ANY, format_ip46_address,
                 &a->rmt_addr, IP46_TYPE_ANY);

  upf_assoc_delete (a, "heartbeat request failed");
}

static upf_pfcp_message_rv_t
_handle_association_setup_request (upf_pfcp_message_t *msg,
                                   pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *um = &upf_main;
  pfcp_msg_association_setup_request_t *req = &dmsg->association_setup_request;
  pfcp_decoded_msg_t resp_dmsg = {
    .type = PFCP_MSG_ASSOCIATION_SETUP_RESPONSE,
    .association_setup_response = {},
  };
  pfcp_msg_association_procedure_response_t *resp =
    &resp_dmsg.association_setup_response;

  memset (resp, 0, sizeof (*resp));
  BIT_SET (resp->grp.fields, ASSOCIATION_PROCEDURE_RESPONSE_CAUSE);
  resp->cause = PFCP_CAUSE_REQUEST_REJECTED;

  BIT_SET (resp->grp.fields, ASSOCIATION_PROCEDURE_RESPONSE_NODE_ID);
  copy_pfcp_ie_node_id (&resp->node_id, &um->node_id);

  BIT_SET (resp->grp.fields,
           ASSOCIATION_PROCEDURE_RESPONSE_RECOVERY_TIME_STAMP);
  resp->recovery_time_stamp = psm->recovery;

  BIT_SET (resp->grp.fields, ASSOCIATION_PROCEDURE_RESPONSE_TP_BUILD_ID);
  vec_add (resp->tp_build_id, vpe_version_string, strlen (vpe_version_string));

  upf_assoc_t *a = upf_assoc_get_by_nodeid (&req->request.node_id);
  if (a)
    {
      /* 3GPP TS 23.007, Sect. 19A:
       *
       * A PFCP function that receives a PFCP Association Setup Request
       * shall proceed with:
       *
       * - establishing the PFCP association and
       * - deleting the existing PFCP association and associated PFCP sessions,
       *   if a PFCP association was already established for the Node ID
       * received in the request, regardless of the Recovery Timestamp received
       * in the request.
       *
       * A PFCP function shall ignore the Recovery Timestamp received in
       * PFCP Association Setup Response message.
       *
       */
      upf_assoc_delete (a, "new association");
    }

  if (BIT_ISSET (req->grp.fields, ASSOCIATION_SETUP_REQUEST_SMF_SET_ID))
    if (!pfcp_can_ensure_smf_set (req->smf_set_id.fqdn))
      {
        vlib_log_err (
          um->log_class,
          "rejecting association setup due to smfset limit reached");
        return UPF_PFCP_MESSAGE_RV_SUCCESS;
      }

  a = upf_assoc_create (msg->k.session_handle, &msg->lcl_address,
                        &msg->k.rmt_address, &req->request.node_id);
  a->recovery_time_stamp = req->recovery_time_stamp;

  if (BIT_ISSET (req->grp.fields, ASSOCIATION_SETUP_REQUEST_SMF_SET_ID))
    pfcp_assoc_enter_smf_set (a, req->smf_set_id.fqdn);

  BIT_SET (resp->grp.fields,
           ASSOCIATION_PROCEDURE_RESPONSE_UP_FUNCTION_FEATURES);
  resp->up_function_features |= PFCP_F_UPFF_EMPU;
  resp->up_function_features |= PFCP_F_UPFF_MPAS;
  resp->up_function_features |= PFCP_F_UPFF_MNOP;
  if (um->pfcp_spec_version >= 16)
    {
      resp->up_function_features |= PFCP_F_UPFF_VTIME;
      resp->up_function_features |= PFCP_F_UPFF_FTUP;
      _build_ue_ip_address_information (&resp->ue_ip_address_pool_information);
      if (vec_len (resp->ue_ip_address_pool_information) != 0)
        BIT_SET (
          resp->grp.fields,
          ASSOCIATION_PROCEDURE_RESPONSE_UE_IP_ADDRESS_POOL_INFORMATION);
      BIT_SET (resp->grp.fields,
               ASSOCIATION_PROCEDURE_RESPONSE_BBF_UP_FUNCTION_FEATURES);
      resp->bbf_up_function_features |= PFCP_BBF_UP_NAT;
    }
  else
    {
      _build_user_plane_ip_resource_information (
        &resp->user_plane_ip_resource_information);
      if (vec_len (resp->user_plane_ip_resource_information) != 0)
        BIT_SET (
          resp->grp.fields,
          ASSOCIATION_PROCEDURE_RESPONSE_USER_PLANE_IP_RESOURCE_INFORMATION);
    }

  a->heartbeat_timer =
    upf_timer_start_secs (0, psm->heartbeat_cfg.timeout,
                          UPF_TIMER_KIND_PFCP_HEARTBEAT, a - um->assocs, 0);

  resp->cause = PFCP_CAUSE_REQUEST_ACCEPTED;

  upf_pfcp_server_send_response (msg, &resp_dmsg);

  return UPF_PFCP_MESSAGE_RV_SUCCESS;
}

/* this methods used for cases when incoming message decode is failed */
static void
_send_simple_response (upf_pfcp_message_t *req, u8 type, pfcp_ie_cause_t cause,
                       pfcp_ie_offending_ie_t *err)
{
  upf_main_t *um = &upf_main;
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_decoded_msg_t resp_dmsg = {
    .type = type,
    .simple_response = {},
  };
  pfcp_simple_response_t *resp = &resp_dmsg.simple_response;

  memset (resp, 0, sizeof (*resp));
  BIT_SET (resp->grp.fields, PFCP_RESPONSE_CAUSE);
  resp->response.cause = cause;

  switch (type)
    {
    case PFCP_MSG_HEARTBEAT_RESPONSE:
    case PFCP_MSG_PFD_MANAGEMENT_RESPONSE:
    case PFCP_MSG_SESSION_MODIFICATION_RESPONSE:
    case PFCP_MSG_SESSION_DELETION_RESPONSE:
    case PFCP_MSG_SESSION_REPORT_RESPONSE:
      break;

    default:
      BIT_SET (resp->grp.fields, PFCP_RESPONSE_NODE_ID);
      copy_pfcp_ie_node_id (&resp->response.node_id, &um->node_id);
      break;
    }

  switch (type)
    {
    case PFCP_MSG_HEARTBEAT_RESPONSE:
    case PFCP_MSG_ASSOCIATION_SETUP_RESPONSE:
      BIT_SET (resp->grp.fields, PFCP_RESPONSE_RECOVERY_TIME_STAMP);
      resp->response.recovery_time_stamp = psm->recovery;
      break;

    default:
      break;
    }

  if (vec_len (err) != 0)
    {
      BIT_SET (resp->grp.fields, PFCP_RESPONSE_OFFENDING_IE);
      resp->response.offending_ie = err[0];
    }

  upf_pfcp_server_send_response (req, &resp_dmsg);
}

static void
_handle_simple_decode_error (upf_pfcp_message_t *msg, pfcp_msg_type_t t,
                             pfcp_ie_cause_t cause,
                             pfcp_ie_offending_ie_t *decode_errs)
{
  _send_simple_response (msg, t + 1 /* response */, cause, decode_errs);
}

static void
_send_session_error_response (upf_pfcp_message_t *msg,
                              pfcp_msg_type_t resp_type, u64 cp_seid,
                              pfcp_ie_cause_t cause, const char *error_msg)
{
  pfcp_decoded_msg_t resp_dmsg = {
    .type = resp_type,
    .seid = cp_seid,
    .session_procedure_response = {},
  };
  pfcp_msg_session_procedure_response_t *failresp =
    &resp_dmsg.session_procedure_response;

  BIT_SET (failresp->grp.fields, SESSION_PROCEDURE_RESPONSE_CAUSE);
  failresp->cause = cause;

  if (error_msg)
    {
      BIT_SET (failresp->grp.fields,
               SESSION_PROCEDURE_RESPONSE_TP_ERROR_REPORT);
      BIT_SET (failresp->tp_error_report.grp.fields,
               TP_ERROR_REPORT_TP_ERROR_MESSAGE);
      failresp->tp_error_report.error_message = format (0, "%s", error_msg);
    }

  upf_pfcp_server_send_response_with_seid (msg, &resp_dmsg, cp_seid);
}

static void
_send_session_sxu_rv_error_response (upf_pfcp_message_t *msg,
                                     pfcp_msg_type_t resp_type, u64 cp_seid,
                                     upf_sxu_t *sxu)
{
  upf_main_t *um = &upf_main;

  pfcp_decoded_msg_t resp_dmsg = {
    .type = resp_type,
    .seid = cp_seid,
    .session_procedure_response = {},
  };
  pfcp_msg_session_procedure_response_t *resp =
    &resp_dmsg.session_procedure_response;

  if (sxu->has_error)
    {
      upf_sxu_error_t *e = &sxu->error;
      ASSERT (is_valid_id (e->cause));

      upf_debug (
        "preparing error: cause %d pfcp_id %d type %U xid %d oie %d msg: %v",
        e->cause, e->pfcp_id, format_upf_sxu_type, e->type, e->xid,
        e->offending_ie, e->message);

      BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CAUSE);
      resp->cause = e->cause;

      if (vec_len (e->message))
        {
          BIT_SET (resp->grp.fields,
                   SESSION_PROCEDURE_RESPONSE_TP_ERROR_REPORT);
          BIT_SET (resp->tp_error_report.grp.fields,
                   TP_ERROR_REPORT_TP_ERROR_MESSAGE);
          resp->tp_error_report.error_message = vec_dup (e->message);
        }

      if (is_valid_id (e->offending_ie))
        {
          BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_OFFENDING_IE);
          resp->offending_ie = e->offending_ie;
        }

      if (upf_sxu_type_backwalk_to_pfcp_failed_rule_id (
            sxu, e->type, e->xid, e->pfcp_id, &resp->failed_rule_id))
        {
          if (is_valid_id (e->pfcp_id))
            resp->failed_rule_id.id = e->pfcp_id;
          BIT_SET (resp->grp.fields,
                   SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
        }
    }
  else if (vec_len (sxu->endpoint_conflicts))
    {
      upf_sxu_conflict_t *conflict;
      // We should remove sessions only on IP duplicates.
      // TODO: check with control plane guys if it's ok
      // TODO: maybe it is better to implement policy configuration like:
      // "upf config terminate-on-conflict [ip,gtpu]"
      vec_foreach (conflict, sxu->endpoint_conflicts)
        {
          switch (conflict->type)
            {
            case UPF_SXU_TYPE_ue_ip_ep4:
            case UPF_SXU_TYPE_ue_ip_ep6:
              upf_debug ("removing sid %d due to %U conflict",
                         conflict->conflicted_session_id, format_upf_sxu_type,
                         conflict->type);
              upf_session_t *colliding_sx = pool_elt_at_index (
                um->sessions, conflict->conflicted_session_id);
              // should handle session id duplicates in list
              upf_session_trigger_deletion (
                colliding_sx,
                UPF_SESSION_TERMINATION_REASON_ENDPOINT_COLLISION);
              break;
            default:
              upf_debug ("keeping sid %d with %U conflict",
                         conflict->conflicted_session_id, format_upf_sxu_type,
                         conflict->type);
              break;
            }
        }

      BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CAUSE);
      resp->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      upf_sxu_conflict_t *any_conflict =
        vec_elt_at_index (sxu->endpoint_conflicts, 0);
      upf_session_t *colliding_sx =
        pool_elt_at_index (um->sessions, any_conflict->conflicted_session_id);

      BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_TP_ERROR_REPORT);
      BIT_SET (resp->tp_error_report.grp.fields,
               TP_ERROR_REPORT_TP_ERROR_MESSAGE);
      resp->tp_error_report.error_message =
        format (0,
                "Conflict on %U with session %d up_seid 0x%016" PRIx64
                " cp_seid 0x%016" PRIx64 "",
                format_upf_sxu_type, any_conflict->type,
                any_conflict->conflicted_session_id, colliding_sx->up_seid,
                colliding_sx->cp_seid);

      if (upf_sxu_type_backwalk_to_pfcp_failed_rule_id (
            sxu, any_conflict->type, any_conflict->xid, ~0,
            &resp->failed_rule_id))
        BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
    }

  upf_sxu_deinit (sxu);

  upf_pfcp_server_send_response_with_seid (msg, &resp_dmsg, cp_seid);
}

static upf_pfcp_message_rv_t
_handle_session_establishment_request (upf_pfcp_message_t *msg,
                                       pfcp_decoded_msg_t *dmsg)
{
  upf_main_t *um = &upf_main;
  pfcp_msg_session_establishment_request_t *req =
    &dmsg->session_establishment_request;

  upf_assoc_t *assoc = upf_assoc_get_by_nodeid (&req->request.node_id);
  u64 cp_seid = req->f_seid.seid;
  if (!assoc)
    {
      _send_session_error_response (
        msg, PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE, cp_seid,
        PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION,
        "No established PFCP Association");
      return UPF_PFCP_MESSAGE_RV_FAILED;
    }

  if (msg->k.session_handle != assoc->session_handle)
    vlib_log_err (um->log_class,
                  "request and assoc session handles don't match %d != %d",
                  msg->k.session_handle, assoc->session_handle);

  if (upf_session_get_by_cp_f_seid (&req->f_seid))
    {
      _send_session_error_response (
        msg, PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE, cp_seid,
        PFCP_CAUSE_REQUEST_REJECTED, "Duplicate F-SEID");
      return UPF_PFCP_MESSAGE_RV_FAILED;
    }

  u64 up_seid = upf_session_generate_up_seid (cp_seid);
  if (up_seid == 0)
    {
      _send_session_error_response (msg,
                                    PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE,
                                    cp_seid, PFCP_CAUSE_NO_RESOURCES_AVAILABLE,
                                    "Temporary failed to generate UP SEID");
      return UPF_PFCP_MESSAGE_RV_FAILED;
    }

  // Allocate session for session_id, so we could use it in rules
  upf_session_t *sx = upf_session_new (up_seid);

  upf_sxu_t sxu;
  upf_sxu_init (&sxu, sx - um->sessions, sx->session_generation,
                sx->thread_index, ~0);

  upf_sxu_pfcp_actions_t actions = {
    .create_pdrs = req->create_pdr,
    .create_fars = req->create_far,
    .create_urrs = req->create_urr,
    .create_qers = req->create_qer,
  };

  int sxu_rv = upf_sxu_stage_1_provide_pfcp_actions (&sxu, &actions);
  upf_debug ("1 %U", format_upf_sxu, &sxu);
  if (!sxu_rv)
    {
      sxu_rv = upf_sxu_stage_2_update_dynamic (&sxu);
      upf_debug ("2 %U", format_upf_sxu, &sxu);
    }

  if (sxu_rv)
    {
      _send_session_sxu_rv_error_response (
        msg, PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE, cp_seid, &sxu);
      upf_session_free (sx);
      return UPF_PFCP_MESSAGE_RV_FAILED;
    }

  // Session creation succeeded, init everything
  upf_session_init (sx, assoc, &req->f_seid);
  if (BIT_ISSET (req->grp.fields, SESSION_ESTABLISHMENT_REQUEST_USER_ID))
    upf_session_set_user_id (sx, &req->user_id);

  upf_sxu_stage_3_compile_rules (&sxu);

  upf_debug ("3 %U", format_upf_sxu, &sxu);

  sx->c_state = UPF_SESSION_STATE_CREATED;

  upf_rules_t *rules = pool_elt_at_index (um->rules, sxu.new_rules_id);
  if (BIT_ISSET (req->grp.fields,
                 SESSION_ESTABLISHMENT_REQUEST_USER_PLANE_INACTIVITY_TIMER))
    rules->inactivity_timeout = req->user_plane_inactivity_timer;

  _start_procedure_with_pfcp_request (sx, msg, UPF_MT_SESSION_REQ_CREATE, &sxu,
                                      NULL);
  return UPF_PFCP_MESSAGE_RV_SUCCESS;
}

static upf_pfcp_message_rv_t
_handle_session_modification_request (upf_pfcp_message_t *msg,
                                      pfcp_decoded_msg_t *dmsg)
{
  upf_main_t *um = &upf_main;

  upf_sxu_t sxu;
  bool sxu_created = false;

  pfcp_msg_session_modification_request_t *req =
    &dmsg->session_modification_request;

  upf_session_t *sx = upf_session_get_by_up_seid (dmsg->seid);
  if (sx == NULL)
    {
      upf_debug ("PFCP Session %" PRIu64 " not found.\n", dmsg->seid);

      _send_session_error_response (
        msg, PFCP_MSG_SESSION_MODIFICATION_RESPONSE, 0,
        PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, "Session not found");
      return UPF_PFCP_MESSAGE_RV_FAILED;
    }

  if (sx->c_state != UPF_SESSION_STATE_CREATED)
    {
      upf_debug ("PFCP Session %" PRIu64 " not in creation state %U.\n",
                 dmsg->seid, format_upf_session_state, sx->c_state);

      _send_session_error_response (
        msg, PFCP_MSG_SESSION_MODIFICATION_RESPONSE, 0,
        PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, "Session state invalid");
      return UPF_PFCP_MESSAGE_RV_FAILED;
    }

  upf_rules_t *old_rules = pool_elt_at_index (um->rules, sx->rules_id);
  upf_lidset_t old_urrs_slots = old_rules->slots.urrs;
  upf_lidset_t immediate_report_urr_lids = {};

  // > QAURR (Query All URRs) flag in the PFCPSMReq-Flags IE and the Query URR
  // > IE are exclusive
  if (BIT_ISSET (req->grp.fields, SESSION_MODIFICATION_REQUEST_QUERY_URR) &&
      vec_len (req->query_urr) != 0)
    {
      pfcp_ie_query_urr_t *qry;
      vec_foreach (qry, req->query_urr)
        {
          bool found = false;

          upf_lidset_foreach (lid, &old_urrs_slots)
            {
              rules_urr_t *curr = upf_rules_get_urr (old_rules, lid);
              pfcp_ie_urr_id_t curr_pfcp_id = curr->pfcp_id;

              if (qry->urr_id == curr_pfcp_id)
                {
                  found = true;
                  upf_lidset_set (&immediate_report_urr_lids, lid);
                  break;
                }
            }

          if (!found)
            {
              upf_debug ("havent found urr id %d", qry->urr_id);
              _send_session_error_response (
                msg, PFCP_MSG_SESSION_MODIFICATION_RESPONSE, sx->cp_seid,
                PFCP_CAUSE_REQUEST_REJECTED, "invalid query urr id");
              return UPF_PFCP_MESSAGE_RV_FAILED;
            }
        }
    }

  if (BIT_ISSET (req->grp.fields,
                 SESSION_MODIFICATION_REQUEST_PFCPSMREQ_FLAGS) &&
      req->pfcpsmreq_flags & PFCP_PFCPSMREQ_QAURR)
    {
      immediate_report_urr_lids = old_urrs_slots;
    }

  /* 3GPP TS 29.244 version 16.5.0 clause 5.2.2.3.1
   * When being instructed to remove a URR or the last PDR associated to a URR,
   * the UP function shall stop its ongoing measurements for the URR and
   * include a Usage Report in the PFCP Session Modification Response or in an
   * additional PFCP Session Report Request.
   */

  if (req->grp.fields &
      (BIT (SESSION_MODIFICATION_REQUEST_USER_PLANE_INACTIVITY_TIMER) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_PDR) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_FAR) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_URR) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_QER) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_BAR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_PDR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_FAR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_URR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_QER) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_BAR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_PDR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_FAR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_URR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_QER) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_BAR)))
    {
      // invoke the update process only if a update is included
      upf_sxu_init (&sxu, sx - um->sessions, sx->session_generation,
                    sx->thread_index, sx->rules_id);
      upf_debug ("update init:::\n%U", format_upf_sxu, &sxu);

      sxu_created = true;

      upf_sxu_pfcp_actions_t actions = {
        .create_pdrs = req->create_pdr,
        .update_pdrs = req->update_pdr,
        .remove_pdrs = req->remove_pdr,
        .create_fars = req->create_far,
        .update_fars = req->update_far,
        .remove_fars = req->remove_far,
        .create_urrs = req->create_urr,
        .update_urrs = req->update_urr,
        .remove_urrs = req->remove_urr,
        .create_qers = req->create_qer,
        .update_qers = req->update_qer,
        .remove_qers = req->remove_qer,
      };

      int sxu_rv = upf_sxu_stage_1_provide_pfcp_actions (&sxu, &actions);
      upf_debug ("1 %U", format_upf_sxu, &sxu);
      if (!sxu_rv)
        {
          sxu_rv = upf_sxu_stage_2_update_dynamic (&sxu);
          upf_debug ("2 %U", format_upf_sxu, &sxu);
        }

      if (sxu_rv)
        {
          _send_session_sxu_rv_error_response (
            msg, PFCP_MSG_SESSION_MODIFICATION_RESPONSE, sx->cp_seid, &sxu);
          return UPF_PFCP_MESSAGE_RV_FAILED;
        }

      upf_sxu_stage_3_compile_rules (&sxu);

      upf_debug ("3 %U", format_upf_sxu, &sxu);

      upf_rules_t *new_rules = pool_elt_at_index (um->rules, sxu.new_rules_id);
      if (BIT_ISSET (
            req->grp.fields,
            SESSION_ESTABLISHMENT_REQUEST_USER_PLANE_INACTIVITY_TIMER))
        {
          new_rules->flag_inactivity_timeout_reset = 1;
          new_rules->inactivity_timeout = req->user_plane_inactivity_timer;
        }
    }

  _start_procedure_with_pfcp_request (sx, msg, UPF_MT_SESSION_REQ_UPDATE,
                                      sxu_created ? &sxu : NULL,
                                      &immediate_report_urr_lids);
  return UPF_PFCP_MESSAGE_RV_SUCCESS;
}

static upf_pfcp_message_rv_t
_handle_session_deletion_request (upf_pfcp_message_t *msg,
                                  pfcp_decoded_msg_t *dmsg)
{
  upf_main_t *um = &upf_main;

  upf_sxu_t sxu;

  upf_session_t *sx = upf_session_get_by_up_seid (dmsg->seid);
  if (sx == NULL)
    {
      upf_debug ("PFCP Session %" PRIu64 " not found.\n", dmsg->seid);

      _send_session_error_response (msg, PFCP_MSG_SESSION_DELETION_RESPONSE, 0,
                                    PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND,
                                    "Session not found");
      return UPF_PFCP_MESSAGE_RV_FAILED;
    }

  if (sx->c_state != UPF_SESSION_STATE_CREATED)
    {
      upf_debug ("PFCP Session %" PRIu64 " not in creation state %U.\n",
                 dmsg->seid, format_upf_session_state, sx->c_state);

      _send_session_error_response (
        msg, PFCP_MSG_SESSION_DELETION_RESPONSE, sx->cp_seid,
        PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, "Session state invalid");
      return UPF_PFCP_MESSAGE_RV_FAILED;
    }

  upf_sxu_init (&sxu, sx - um->sessions, sx->session_generation,
                sx->thread_index, sx->rules_id);

  upf_sxu_stage_1_provide_delete_actions (&sxu);
  upf_debug ("1 %U", format_upf_sxu, &sxu);

  if (upf_sxu_stage_2_update_dynamic (&sxu))
    {
      clib_warning ("BUG: sxu session removal failed:\n%U", format_upf_sxu,
                    sxu);
      upf_sxu_deinit (&sxu);

      _send_session_error_response (msg, PFCP_MSG_SESSION_DELETION_RESPONSE,
                                    sx->cp_seid, PFCP_CAUSE_SYSTEM_FAILURE,
                                    "Sesssion rules removal bug");
      return UPF_PFCP_MESSAGE_RV_FAILED;
    }
  upf_debug ("2 %U", format_upf_sxu, &sxu);

  upf_sxu_stage_3_compile_rules (&sxu);
  upf_debug ("3 %U", format_upf_sxu, &sxu);

  u32 i;
#define _(name, plural)                                                       \
  vec_foreach_index (i, sxu.plural)                                           \
    {                                                                         \
      sxu_slot_##name##_t *slot = vec_elt_at_index (sxu.plural, i);           \
      ASSERT (slot->state.references == 0);                                   \
      ASSERT (slot->state.will_exist == 0);                                   \
    }
  foreach_sxu_type
#undef _

  _start_procedure_with_pfcp_request (sx, msg, UPF_MT_SESSION_REQ_DELETE, &sxu,
                                      NULL);

  sx->c_state = UPF_SESSION_STATE_DELETED;

  return UPF_PFCP_MESSAGE_RV_SUCCESS;
}

static void
_handle_session_report_request_timeout (upf_pfcp_request_t *req)
{
  upf_main_t *um = &upf_main;

  // Overload, bug on CP or similar. Remove only session, avoid removing entire
  // association
  ASSERT (is_valid_id (req->session.id));
  if (!is_valid_id (req->session.id))
    {
      // session deleted already (before acknowledging response)
      return;
    }

  ASSERT (is_valid_id (req->assoc.id));
  if (!is_valid_id (req->assoc.id))
    {
      clib_warning ("BUG: no assoc id during report timeout");
      return;
    }

  ASSERT (!pool_is_free_index (um->assocs, req->assoc.id));
  if (pool_is_free_index (um->assocs, req->assoc.id))
    {
      clib_warning ("BUG: invalid assoc id during report timeout");
      return;
    }

  ASSERT (!pool_is_free_index (um->sessions, req->session.id));
  if (pool_is_free_index (um->sessions, req->session.id))
    {
      clib_warning ("BUG: invalid session id during report timeout");
      return;
    }

  upf_assoc_t *a = pool_elt_at_index (um->assocs, req->assoc.id);
  ASSERT (!a->is_released);
  if (a->is_released)
    return;

  upf_session_t *sx = pool_elt_at_index (um->sessions, req->session.id);
  upf_session_trigger_deletion (sx, UPF_SESSION_TERMINATION_REASON_NO_ANSWER);
}

static upf_pfcp_response_rv_t
_handle_session_report_request_response (upf_pfcp_message_t *msg,
                                         upf_pfcp_request_t *our_req,
                                         pfcp_decoded_msg_t *dmsg)
{
  upf_main_t *um = &upf_main;

  if (dmsg->type != PFCP_MSG_SESSION_REPORT_RESPONSE)
    return UPF_PFCP_RESPONSE_RV_IGNORE;

  pfcp_msg_session_report_response_t *resp = &dmsg->session_report_response;

  if (!is_valid_id (our_req->session.id))
    {
      // session deleted already (before acknowledging response)
      return UPF_PFCP_RESPONSE_RV_ACCEPT;
    }
  if (pool_is_free_index (um->sessions, our_req->session.id))
    {
      ASSERT (0); // Shouldn't happen, precaution against buggy code
      clib_warning ("BUG: ignoring report response (no session)");
      return UPF_PFCP_RESPONSE_RV_ACCEPT;
    }

  upf_session_t *sx = pool_elt_at_index (um->sessions, our_req->session.id);

  upf_debug ("session report response cause %d", resp->response.cause);
  if (resp->response.cause == PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND)
    {
      upf_session_trigger_deletion (sx,
                                    UPF_SESSION_TERMINATION_REASON_CP_DESYNC);
      return UPF_PFCP_RESPONSE_RV_ACCEPT; // consume request
    }
  else if (resp->response.cause == PFCP_CAUSE_REQUEST_ACCEPTED)
    {
      if (dmsg->seid != sx->up_seid)
        {
          // Corrupted response from server, ignore it
          return UPF_PFCP_RESPONSE_RV_IGNORE; // keep request
        }

      if (sx->is_lost_smfset_cp)
        {
          // New CP F-SEID is provided, update it
          if (resp->grp.fields & SESSION_REPORT_RESPONSE_CP_F_SEID)
            {
              pfcp_ie_f_seid_t *cp_f_seid =
                &dmsg->session_report_response.cp_f_seid;

              // This is first response with cp_f_seid since we lost pfcp peer
              sx->is_lost_smfset_cp = 0;

              upf_session_set_cp_fseid (sx, cp_f_seid);

              upf_debug ("updated session cp_seid 0x%x (%U,%U)", sx->cp_seid,
                         format_ip4_address, &cp_f_seid->ip4,
                         format_ip6_address, &cp_f_seid->ip6);
            }
        }
      return UPF_PFCP_RESPONSE_RV_ACCEPT; // consume request
    }
  else
    {
      clib_warning ("unimplemented Session Report Response cause %d",
                    resp->response.cause);
      return UPF_PFCP_RESPONSE_RV_ACCEPT; // consume request
    }
}

upf_pfcp_message_handler_t
upf_pfcp_get_message_handler (pfcp_msg_type_t t)
{
  switch (t)
    {
    case PFCP_MSG_HEARTBEAT_REQUEST:
      return _handle_heartbeat_request;
    case PFCP_MSG_ASSOCIATION_SETUP_REQUEST:
      return _handle_association_setup_request;
    case PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST:
      return _handle_session_establishment_request;
    case PFCP_MSG_SESSION_MODIFICATION_REQUEST:
      return _handle_session_modification_request;
    case PFCP_MSG_SESSION_DELETION_REQUEST:
      return _handle_session_deletion_request;
    default:
      return NULL;
    }
}

upf_pfcp_response_handler_t
upf_pfcp_get_response_handler (pfcp_msg_type_t t)
{
  switch (t)
    {
    case PFCP_MSG_HEARTBEAT_REQUEST:
      return _handle_heartbeat_request_response;
    case PFCP_MSG_SESSION_REPORT_REQUEST:
      return _handle_session_report_request_response;
    default:
      return NULL;
    }
}

upf_pfcp_timeout_handler_t
upf_pfcp_get_timeout_handler (pfcp_msg_type_t t)
{
  switch (t)
    {
    case PFCP_MSG_HEARTBEAT_REQUEST:
      return _handle_heartbeat_request_timeout;
    case PFCP_MSG_SESSION_REPORT_REQUEST:
      return _handle_session_report_request_timeout;
    default:
      return NULL;
    }
}

upf_pfcp_decode_error_handler_t
upf_pfcp_get_on_decode_error_handler (pfcp_msg_type_t t)
{
  switch (t)
    {
    case PFCP_MSG_HEARTBEAT_REQUEST:
    case PFCP_MSG_PFD_MANAGEMENT_REQUEST:
    case PFCP_MSG_ASSOCIATION_SETUP_REQUEST:
    case PFCP_MSG_ASSOCIATION_UPDATE_REQUEST:
    case PFCP_MSG_ASSOCIATION_RELEASE_REQUEST:
    case PFCP_MSG_SESSION_SET_DELETION_REQUEST:
    case PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST:
    case PFCP_MSG_SESSION_MODIFICATION_REQUEST:
    case PFCP_MSG_SESSION_DELETION_REQUEST:
    case PFCP_MSG_SESSION_REPORT_REQUEST:
      return _handle_simple_decode_error;
    default:
      return NULL;
    }
}
