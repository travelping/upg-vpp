/*
 * Copyright (c) 2025 Travelping GmbH
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

#include <math.h>

#include <vlib/unix/plugin.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/random.h>
#include <vppinfra/sparse_vec.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/fib/fib_path_list.h>

#include "upf/upf.h"
#include "upf/utils/upf_mt.h"
#include "upf/utils/ip_helpers.h"
#include "upf/pfcp/pfcp_proto.h"
#include "upf/pfcp/upf_pfcp_handlers.h"
#include "upf/pfcp/upf_pfcp_server.h"
#include "upf/pfcp/upf_pfcp_assoc.h"
#include "upf/sxu/upf_session_update.h"
#include "upf/nat/nat.h"
#include "upf/rules/upf_gtpu.h"

#define UPF_DEBUG_ENABLE 0

static upf2_usage_report_t *_queued_usage_reports = NULL;

void
handle_mt_event_w2m_usage_report (u16 wk_thread_id, upf_mt_usage_report_t *ev)
{
  vec_add1 (_queued_usage_reports, ev->report);
}

static void
_upf_pfcp_init_response_up_f_seid (pfcp_ie_f_seid_t *up_f_seid, u64 up_seid,
                                   ip46_address_t *address, bool is_ip4)
{
  up_f_seid->seid = up_seid;
  if (is_ip4)
    {
      up_f_seid->flags |= PFCP_F_SEID_IP_ADDRESS_V4;
      up_f_seid->ip4 = address->ip4;
    }
  else
    {
      up_f_seid->flags |= PFCP_F_SEID_IP_ADDRESS_V6;
      up_f_seid->ip6 = address->ip6;
    }
}

static bool
_handle_mt_event_w2m_session_resp_include_created_pdr (
  upf_rules_t *rules, pfcp_ie_created_pdr_t **created_pdrs_vec,
  upf_lidset_t *created_pdr_lids)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  bool created = false;
  upf_lidset_foreach (pdr_lid, created_pdr_lids)
    {
      rules_pdr_t *pdr = upf_rules_get_pdr (rules, pdr_lid);
      rules_tep_t *tep = upf_rules_get_tep (rules, pdr->traffic_ep_lid);

      if (!tep->is_gtpu)
        continue;

      if (!is_valid_id (tep->match.gtpu.fteid_allocation_lid))
        continue;

      rules_f_teid_t *f_teid =
        upf_rules_get_f_teid (rules, tep->match.gtpu.fteid_allocation_lid);

      rules_ep_gtpu_t *gtpu_ep =
        upf_rules_get_ep_gtpu (rules, f_teid->gtpu_endpoint_lid);

      pfcp_ie_created_pdr_t *created_pdr;
      vec_add2 (*created_pdrs_vec, created_pdr, 1);
      memset (created_pdr, 0, sizeof (*created_pdr));

      BIT_SET (created_pdr->grp.fields, CREATED_PDR_PDR_ID);
      created_pdr->pdr_id = pdr->pfcp_id;

      upf_gtpu_endpoint_t *ep =
        pool_elt_at_index (ugm->endpoints, gtpu_ep->gtpu_ep_id);

      if (!ip4_address_is_zero (&ep->ip4))
        {
          created_pdr->f_teid.flags |= PFCP_F_TEID_V4;
          created_pdr->f_teid.ip4 = ep->ip4;
        }
      if (!ip6_address_is_zero (&ep->ip6))
        {
          created_pdr->f_teid.flags |= PFCP_F_TEID_V6;
          created_pdr->f_teid.ip6 = ep->ip6;
        }

      BIT_SET (created_pdr->grp.fields, CREATED_PDR_F_TEID);
      created_pdr->f_teid.teid = gtpu_ep->teid;

      created = true;
    }

  return created;
}

static bool
_handle_mt_event_w2m_session_resp_include_nat_binding (
  upf_rules_t *old_rules, upf_rules_t *new_rules,
  pfcp_ie_tp_created_binding_t *cb)
{
  upf_nat_main_t *unm = &upf_nat_main;

  if (!is_valid_id (new_rules->nat_binding_id))
    return false;

  if (old_rules && new_rules->nat_binding_id == old_rules->nat_binding_id)
    return false; // no change in rules

  upf_nat_binding_info_t info = {};
  upf_nat_binding_get_information (new_rules->nat_binding_id, &info);

  upf_nat_pool_t *nat_pool =
    pool_elt_at_index (unm->nat_pools, info.nat_pool_id);

  cb->block = vec_dup (nat_pool->name);
  cb->port_range.start_port = info.port_min;
  cb->port_range.end_port = info.port_max;
  cb->outside_addr.as_u32 = info.ext_addr.as_u32;

  BIT_SET (cb->grp.fields, TP_CREATED_BINDING_NAT_PORT_BLOCK);
  BIT_SET (cb->grp.fields, TP_CREATED_BINDING_NAT_OUTSIDE_ADDRESS);
  BIT_SET (cb->grp.fields, TP_CREATED_BINDING_NAT_EXTERNAL_PORT_RANGE);

  return true;
}

void
handle_mt_event_w2m_session_resp (u16 wk_thread_id, upf_mt_session_resp_t *ev)
{
  ASSERT_THREAD_MAIN ();

  upf_main_t *um = &upf_main;
  pfcp_server_main_t *psm = &pfcp_server_main;

  upf_session_t *sx = pool_elt_at_index (um->sessions, ev->session_id);
  upf_session_procedure_t *procedure =
    pool_elt_at_index (um->session_procedures, ev->procedure_id);

  ASSERT (sx->up_seid == ev->up_seid);
  ASSERT (procedure->session.id == ev->session_id);

  u32 old_rules_id = procedure->old_rules_id;
  ASSERT (procedure->session.id == ev->session_id);
  if (procedure->has_sxu)
    {
      ASSERT (old_rules_id == procedure->sxu.old_rules_id);
      upf_sxu_stage_5_after_rpc (&procedure->sxu);
    }

  upf_debug ("sx->state=%U ev->kind=%d; procedure->prev_state=%d",
             format_upf_session_state, sx->c_state, ev->kind,
             procedure->prev_state);

  // response always present unless session is terminated
  ASSERT (procedure->is_up_termination !=
          is_valid_id (procedure->response_id));

  if (is_valid_id (procedure->response_id))
    {
      upf_pfcp_response_t *pfcp_resp =
        pool_elt_at_index (psm->responses, procedure->response_id);
      pfcp_decoded_msg_t resp_dmsg = {
        .session_procedure_response = {},
      };
      pfcp_msg_session_procedure_response_t *resp =
        &resp_dmsg.session_procedure_response;

      if (ev->kind == UPF_MT_SESSION_REQ_CREATE)
        {
          resp_dmsg.type = PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE;

          BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CAUSE);
          resp->cause = PFCP_CAUSE_REQUEST_ACCEPTED;

          BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_NODE_ID);
          copy_pfcp_ie_node_id (&resp->node_id, &um->node_id);

          bool is_ip4 = ip46_address_is_ip4 (&pfcp_resp->m.k.rmt_address);
          BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_UP_F_SEID);

          _upf_pfcp_init_response_up_f_seid (
            &resp->up_f_seid, sx->up_seid, &pfcp_resp->m.lcl_address, is_ip4);

          upf_rules_t *rules = pool_elt_at_index (um->rules, ev->new_rules_id);

          if (_handle_mt_event_w2m_session_resp_include_created_pdr (
                rules, &resp->created_pdr, &procedure->sxu.created_pdr_lids))
            BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CREATED_PDR);

          if (_handle_mt_event_w2m_session_resp_include_nat_binding (
                NULL, rules, &resp->created_binding))
            BIT_SET (resp->grp.fields,
                     SESSION_PROCEDURE_RESPONSE_TP_CREATED_BINDING);
        }
      else if (ev->kind == UPF_MT_SESSION_REQ_DELETE)
        {
          resp_dmsg.type = PFCP_MSG_SESSION_DELETION_RESPONSE;

          BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CAUSE);
          resp->cause = PFCP_CAUSE_REQUEST_ACCEPTED;

          BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_USAGE_REPORT);
          upf_usage_report_add_queued_reports (&resp->usage_report,
                                               upf_time_now_main ());
        }
      else
        {
          resp_dmsg.type = PFCP_MSG_SESSION_MODIFICATION_RESPONSE;

          BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CAUSE);
          resp->cause = PFCP_CAUSE_REQUEST_ACCEPTED;

          BIT_SET (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_USAGE_REPORT);
          upf_usage_report_add_queued_reports (&resp->usage_report,
                                               upf_time_now_main ());

          if (is_valid_id (ev->new_rules_id) &&
              ev->new_rules_id != old_rules_id)
            {
              upf_rules_t *new_rules =
                pool_elt_at_index (um->rules, ev->new_rules_id);
              upf_rules_t *old_rules =
                pool_elt_at_index (um->rules, old_rules_id);

              if (_handle_mt_event_w2m_session_resp_include_created_pdr (
                    new_rules, &resp->created_pdr,
                    &procedure->sxu.created_pdr_lids))
                BIT_SET (resp->grp.fields,
                         SESSION_PROCEDURE_RESPONSE_CREATED_PDR);

              if (_handle_mt_event_w2m_session_resp_include_nat_binding (
                    old_rules, new_rules, &resp->created_binding))
                BIT_SET (resp->grp.fields,
                         SESSION_PROCEDURE_RESPONSE_TP_CREATED_BINDING);
            }
        }

      // send response
      u8 *resp_data = 0;
      upf_pfcp_message_encode (&pfcp_resp->m, &resp_dmsg, sx->cp_seid,
                               &resp_data);

      upf_debug ("sending response to 0x%x (0x%x,0x%x) with seq %d",
                 resp_dmsg.seid, sx->cp_seid, sx->up_seid, resp_dmsg.seq_no);

      pfcp_free_dmsg_contents (&resp_dmsg);
      upf_pfcp_response_populate (pfcp_resp, resp_data);
    }
  else if (procedure->is_up_termination)
    {
      /*
       * TS 29.244 clause 5.18.2: UP Function Initiated PFCP Session
       * Release FIXME: should include diagnostic information with
       * the reason for session termination
       */
      pfcp_decoded_msg_t dmsg = { .type = PFCP_MSG_SESSION_REPORT_REQUEST,
                                  .session_report_request = {} };
      pfcp_msg_session_report_request_t *req = &dmsg.session_report_request;

      BIT_SET (req->grp.fields, SESSION_REPORT_REQUEST_REPORT_TYPE);

      if (vec_len (_queued_usage_reports) > 0)
        {
          req->report_type = PFCP_REPORT_TYPE_USAR;

          BIT_SET (req->grp.fields, SESSION_REPORT_REQUEST_USAGE_REPORT);
          upf_usage_report_add_queued_reports (&req->usage_report,
                                               upf_time_now_main ());
        }
      else
        req->report_type = PFCP_REPORT_TYPE_UISR;

      BIT_SET (req->grp.fields, SESSION_REPORT_REQUEST_PFCPSRREQ_FLAGS);
      req->pfcpsrreq_flags = PFCP_PFCPSRREQ_PSDBU; // termination

      u8 *tp_err_msg = NULL;
      switch (sx->termination_reason)
        {
        case UPF_SESSION_TERMINATION_REASON_ASSOCIATION_LOST:
          tp_err_msg = format (0, "association lost");
          break;
        case UPF_SESSION_TERMINATION_REASON_CP_DESYNC:
          tp_err_msg = format (0, "report response cause session not found");
          break;
        case UPF_SESSION_TERMINATION_REASON_NO_ANSWER:
          tp_err_msg = format (0, "report response not received");
          break;
        case UPF_SESSION_TERMINATION_REASON_ENDPOINT_COLLISION:
          tp_err_msg = format (0, "fteid or ip collision");
          break;
        case UPF_SESSION_TERMINATION_REASON_DATAPLANE:
          tp_err_msg = format (0, "double monitoring time split for report");
          break;
        }

      if (tp_err_msg)
        {
          BIT_SET (dmsg.session_report_request.grp.fields,
                   SESSION_REPORT_REQUEST_TP_ERROR_MESSAGE);
          dmsg.session_report_request.tp_error_message = tp_err_msg;
        }

      // sending
      upf_assoc_t *assoc = pool_elt_at_index (um->assocs, sx->assoc.id);
      if (!assoc->is_released)
        {
          upf_pfcp_request_t *pfcp_req = upf_pfcp_request_create (assoc);
          upf_pfcp_request_link_session (pfcp_req, ev->session_id);
          u8 *data = 0;
          upf_pfcp_message_encode (&pfcp_req->m, &dmsg, sx->cp_seid, &data);
          upf_pfcp_request_send (pfcp_req, data,
                                 &pfcp_server_main.default_cfg);
        }
      else if (sx->termination_reason !=
               UPF_SESSION_TERMINATION_REASON_ASSOCIATION_LOST)
        {
          vlib_log_warn (um->log_class, "dropping received MT termination "
                                        "event due to association release");
        }

      pfcp_free_dmsg_contents (&dmsg);
    }

  if (procedure->has_sxu)
    upf_sxu_deinit (&procedure->sxu);

  if (CLIB_DEBUG > 0)
    memset (&procedure->sxu, 0xaa, sizeof (procedure->sxu));

  upf_session_procedures_list_remove (um->session_procedures, &sx->procedures,
                                      procedure);
  pool_put (um->session_procedures, procedure);

  if (ev->kind != UPF_MT_SESSION_REQ_DELETE)
    {
      // try to send next queued mt procedure
      upf_session_send_next_procedure (sx);
      return;
    }

  // now check if session should be removed

  ASSERT (sx->c_state == UPF_SESSION_STATE_DELETED);
  ASSERT (upf_session_procedures_list_is_empty (&sx->procedures));

  upf_assoc_t *assoc = pool_elt_at_index (um->assocs, sx->assoc.id);

  upf_session_deinit (sx);
  upf_session_free (sx);

  if (assoc->is_released)
    {
      // association was kept waiting for sessions to be late removed
      if (upf_assoc_sessions_list_is_empty (&assoc->sessions))
        {
          // all sessions removed from associations
          upf_debug ("trying to release assoc %U after session removals",
                     format_upf_assoc, assoc, 0);
          pool_put (um->assocs, assoc);
        }
    }
}

static void
_usage_report_from_mt_event (pfcp_ie_usage_report_t *r,
                             upf2_usage_report_t *ur)
{
  upf_main_t *um = &upf_main;

  BIT_SET (r->grp.fields, USAGE_REPORT_URR_ID);
  r->urr_id = ur->urr_id;

  BIT_SET (r->grp.fields, USAGE_REPORT_UR_SEQN);
  r->ur_seqn = ur->seq;

  BIT_SET (r->grp.fields, USAGE_REPORT_USAGE_REPORT_TRIGGER);
  r->usage_report_trigger = ur->usage_report_trigger;

  bool is_start_of_traffic =
    ur->usage_report_trigger & PFCP_USAGE_REPORT_TRIGGER_START_OF_TRAFFIC;

  if (!is_start_of_traffic)
    {
      // clib_warning ("report triggers: 0x%x", r->usage_report_trigger);

      upf2_usage_report_measurment_t *m = &ur->measurment;

      u32 start_time = (u32) trunc (m->time_start);
      u32 end_time = (u32) trunc (m->time_end);

      BIT_SET (r->grp.fields, USAGE_REPORT_VOLUME_MEASUREMENT);
      r->volume_measurement.fields = PFCP_VOLUME_ALL;

      r->volume_measurement.volume.ul = m->volume_measurments.bytes.ul;
      r->volume_measurement.volume.dl = m->volume_measurments.bytes.dl;
      r->volume_measurement.volume.total = m->volume_measurments.bytes.total;
      r->volume_measurement.packets.ul = m->volume_measurments.packets.ul;
      r->volume_measurement.packets.dl = m->volume_measurments.packets.dl;
      r->volume_measurement.packets.total =
        m->volume_measurments.packets.total;

      BIT_SET (r->grp.fields, USAGE_REPORT_DURATION_MEASUREMENT);
      r->duration_measurement = m->duration_measurement;

      BIT_SET (r->grp.fields, USAGE_REPORT_START_TIME);
      BIT_SET (r->grp.fields, USAGE_REPORT_END_TIME);
      r->start_time = start_time;
      r->end_time = end_time;

      BIT_SET (r->grp.fields, USAGE_REPORT_TP_START_TIME);
      BIT_SET (r->grp.fields, USAGE_REPORT_TP_END_TIME);
      BIT_SET (r->grp.fields, USAGE_REPORT_TP_NOW);
      r->tp_start_time = m->time_start;
      r->tp_end_time = m->time_end;
      r->tp_now = upf_time_now_main ();

      if (m->usage_information)
        {
          BIT_SET (r->grp.fields, USAGE_REPORT_USAGE_INFORMATION);
          r->usage_information = m->usage_information;
        }

      if (m->time_of_first_packet)
        {
          BIT_SET (r->grp.fields, USAGE_REPORT_TIME_OF_FIRST_PACKET);
          BIT_SET (r->grp.fields, USAGE_REPORT_TIME_OF_LAST_PACKET);
          r->time_of_first_packet = m->time_of_first_packet;
          r->time_of_last_packet = m->time_of_last_packet;
        }
    }
  else
    {
      ASSERT (ur->usage_report_trigger ==
              PFCP_USAGE_REPORT_TRIGGER_START_OF_TRAFFIC);

      upf2_usage_report_start_of_traffic_t *sot = &ur->start_of_traffic;

      BIT_SET (r->grp.fields, USAGE_REPORT_UE_IP_ADDRESS);
      if (ip46_address_is_ip4 (&sot->ue_ip_address))
        {
          r->ue_ip_address.flags = PFCP_UE_IP_ADDRESS_V4;
          r->ue_ip_address.ip4 = sot->ue_ip_address.ip4;
        }
      else
        {
          r->ue_ip_address.flags = PFCP_UE_IP_ADDRESS_V6;
          r->ue_ip_address.ip6 = sot->ue_ip_address.ip6;
        }

      if (is_valid_id (sot->nwi_id))
        {
          upf_nwi_t *nwi = pool_elt_at_index (um->nwis, sot->nwi_id);
          if (vec_len (nwi->name))
            {
              BIT_SET (r->grp.fields, USAGE_REPORT_NETWORK_INSTANCE);
              r->network_instance = vec_dup (nwi->name);
            }
        }
    }
}

void
upf_usage_report_add_queued_reports (pfcp_ie_usage_report_t **urs_vec,
                                     upf_time_t now)
{
  if (!vec_len (_queued_usage_reports))
    return;

  vec_validate (*urs_vec, vec_len (_queued_usage_reports) - 1);

  upf2_usage_report_t *ur;
  vec_foreach (ur, _queued_usage_reports)
    {
      pfcp_ie_usage_report_t *r =
        vec_elt_at_index (*urs_vec, ur - _queued_usage_reports);
      memset (r, 0, sizeof (*r));
      _usage_report_from_mt_event (r, ur);
    }

  vec_reset_length (_queued_usage_reports);
}

void
handle_mt_event_w2m_session_report (u16 wk_thread_id,
                                    upf_mt_session_report_t *ev)
{
  upf_main_t *um = &upf_main;
  upf2_session_report_t *sr = &ev->report;

  upf_session_t *sx = pool_elt_at_index (um->sessions, ev->session_id);
  ASSERT (sx->up_seid == ev->up_seid);

  pfcp_decoded_msg_t dmsg = {
    .type = PFCP_MSG_SESSION_REPORT_REQUEST,
    .session_report_request = {},
  };
  pfcp_msg_session_report_request_t *req = &dmsg.session_report_request;

  memset (req, 0, sizeof (*req));
  BIT_SET (req->grp.fields, SESSION_REPORT_REQUEST_REPORT_TYPE);
  req->report_type = sr->type;

  if (sr->type == PFCP_REPORT_TYPE_UISR)
    {
      ASSERT (!sx->is_dp_terminated);

      // UP Initiated Session Request with only possible reason being
      // PFCP Session Deleted By the UP function
      ASSERT (vec_len (_queued_usage_reports) == sr->usage_reports_count);
      BIT_SET (req->grp.fields, SESSION_REPORT_REQUEST_USAGE_REPORT);
      upf_usage_report_add_queued_reports (&req->usage_report,
                                           upf_time_now_main ());

      if (sr->usage_reports_count != 0)
        req->report_type = PFCP_REPORT_TYPE_USAR;

      BIT_SET (req->grp.fields, SESSION_REPORT_REQUEST_PFCPSRREQ_FLAGS);
      req->pfcpsrreq_flags = PFCP_PFCPSRREQ_PSDBU; // termination

      sx->is_dp_terminated = 1;

      upf_session_trigger_deletion (sx,
                                    UPF_SESSION_TERMINATION_REASON_DATAPLANE);
    }
  else if (sr->type == PFCP_REPORT_TYPE_USAR)
    { // Usage Report
      ASSERT (sr->usage_reports_count);
      ASSERT (vec_len (_queued_usage_reports) == sr->usage_reports_count);
      BIT_SET (req->grp.fields, SESSION_REPORT_REQUEST_USAGE_REPORT);
      upf_usage_report_add_queued_reports (&req->usage_report,
                                           upf_time_now_main ());
    }
  else if (sr->type == PFCP_REPORT_TYPE_ERIR)
    {
      ASSERT (vec_len (_queued_usage_reports) == 0);
      BIT_SET (req->grp.fields,
               SESSION_REPORT_REQUEST_ERROR_INDICATION_REPORT);

      upf2_session_report_error_indication_t *error = &sr->error_indication;

      pfcp_ie_f_teid_t f_teid = {
        .teid = error->teid,
      };

      if (ip46_address_is_ip4 (&error->addr))
        {
          f_teid.flags = PFCP_F_TEID_V4;
          f_teid.ip4 = error->addr.ip4;
        }
      else
        {
          f_teid.flags = PFCP_F_TEID_V6;
          f_teid.ip6 = error->addr.ip6;
        }

      BIT_SET (req->error_indication_report.grp.fields,
               ERROR_INDICATION_REPORT_F_TEID);
      vec_add1 (req->error_indication_report.f_teid, f_teid);
    }
  else
    {
      ASSERT (0 && "Invalid mt sr type");
      clib_warning ("BUG: unknown mt sr type %d", sr->type);
      return;
    }

  // sending
  upf_assoc_t *assoc = pool_elt_at_index (um->assocs, sx->assoc.id);
  if (!assoc->is_released)
    {
      upf_pfcp_request_t *pfcp_req = upf_pfcp_request_create (assoc);
      upf_pfcp_request_link_session (pfcp_req, ev->session_id);
      u8 *data = 0;
      upf_pfcp_message_encode (&pfcp_req->m, &dmsg, sx->cp_seid, &data);
      upf_pfcp_request_send (pfcp_req, data, &pfcp_server_main.default_cfg);
    }
  else
    {
      vlib_log_warn (
        um->log_class,
        "dropping received MT request event due to association release");
    }

  pfcp_free_dmsg_contents (&dmsg);
}
