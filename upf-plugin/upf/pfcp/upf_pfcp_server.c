/*
 * Copyright (c) 2016 Cisco and/or its affiliates
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

#include <inttypes.h>

#include <vppinfra/bihash_vec8_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

#include "upf/upf.h"
#include "upf/upf_stats.h"
#include "upf/utils/upf_timer.h"
#include "upf/pfcp/upf_pfcp_assoc.h"
#include "upf/pfcp/upf_pfcp_handlers.h"
#include "upf/pfcp/upf_pfcp_server.h"

#define UPF_DEBUG_ENABLE 0

#define RESPONSE_TIMEOUT 30

pfcp_server_main_t pfcp_server_main = {};

#define foreach_upf_pfcp_send_reason                                          \
  _ (request_init)                                                            \
  _ (request_retransmit)                                                      \
  _ (response_populate)                                                       \
  _ (response_resend)

typedef enum
{
#define _(reason) UPF_PFCP_SEND_REASON_##reason,
  foreach_upf_pfcp_send_reason
#undef _
} upf_pfcp_send_reason_t;

static void
_upf_pfcp_send_data (upf_pfcp_message_t *msg, u8 *data,
                     upf_pfcp_send_reason_t reason)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  app_session_transport_t at;
  svm_msg_q_t *mq;
  session_t *s;
  vlib_main_t *vm = vlib_get_main ();

  s = session_get_from_handle_if_valid (msg->k.session_handle);
  if (!s)
    {
      upf_stats_get_pfcp_message (pfcp_msg_type (data))->tx_fail += 1;
      return;
    }

  mq = session_main_get_vpp_event_queue (s->thread_index);
  at.is_ip4 = ip46_address_is_ip4 (&msg->lcl_address);
  at.lcl_ip = msg->lcl_address;
  at.rmt_ip = msg->k.rmt_address;
  at.lcl_port = msg->lcl_port;
  at.rmt_port = msg->k.rmt_port;

  static char *upf_pfcp_send_reason_strings[] = {
#define _(reason) #reason,
    foreach_upf_pfcp_send_reason
#undef _
  };

  upf_debug ("enqueued %U len %u reason %s", format_upf_pfcp_message, msg,
             vec_len (data), upf_pfcp_send_reason_strings[reason]);

  // only ratelimit reports
  if (pfcp_msg_type (data) == PFCP_MSG_SESSION_REPORT_REQUEST &&
      reason == UPF_PFCP_SEND_REASON_request_init)
    {
      tokenbucket_refill (&psm->pfcp_request_drop_ratelimit,
                          upf_time_now_main ());

      // rate limit only request related messages
      if (!tokenbucket_consume (&psm->pfcp_request_drop_ratelimit, 1))
        {
          upf_stats_get_pfcp_message (pfcp_msg_type (data))
            ->tx_drop_ratelimit += 1;
          return;
        }
    }

  int len = app_send_dgram_raw (s->tx_fifo, &at, mq, data, _vec_len (data),
                                SESSION_IO_EVT_TX, 1 /* do_evt */, 0);
  if (!len)
    {
      // QUEUE is full
      upf_stats_get_pfcp_message (pfcp_msg_type (data))->tx_fail += 1;
      return;
    }

  switch (reason)
    {
    case UPF_PFCP_SEND_REASON_request_init:
    case UPF_PFCP_SEND_REASON_response_populate:
      upf_stats_get_pfcp_message (pfcp_msg_type (data))->tx_ok += 1;
      break;
    case UPF_PFCP_SEND_REASON_request_retransmit:
    case UPF_PFCP_SEND_REASON_response_resend:
      upf_stats_get_pfcp_message (pfcp_msg_type (data))->tx_retransmit += 1;
      break;
    }

  // TODO: validate if not needed because of "poll-main" in "session" section
  // in startup.
  // This is needed in case if there are > 0 workers as PFCP still runs on the
  // main thread which can't process the session queue by itself w/o being
  // "nudged" this way
  if (vlib_num_workers ())
    session_queue_run_on_main_thread (vm);
}

upf_pfcp_request_t *
upf_pfcp_request_create (upf_assoc_t *assoc)
{
  upf_main_t *um = &upf_main;
  pfcp_server_main_t *psm = &pfcp_server_main;

  ASSERT (!assoc->is_released); // caller shoud be aware

  upf_pfcp_request_t *req;
  pool_get_zero (psm->requests, req);
  memset (req, 0, sizeof (*req));

  req->session.id = ~0;
  req->timer.as_u32 = ~0;
  upf_session_requests_list_anchor_init (req);
  upf_assoc_requests_list_anchor_init (req);

  req->assoc.id = assoc - um->assocs;
  req->m.k.session_handle = assoc->session_handle;
  req->m.k.rmt_address = assoc->rmt_addr;
  req->m.k.rmt_port = clib_host_to_net_u16 (UDP_DST_PORT_PFCP);
  req->m.lcl_address = assoc->lcl_addr;
  req->m.lcl_port = clib_host_to_net_u16 (UDP_DST_PORT_PFCP);
  req->m.k.seq_no = clib_atomic_add_fetch (&psm->seq_no, 1) % 0x1000000;

  upf_assoc_requests_list_insert_tail (psm->requests, &assoc->requests, req);

  return req;
}

void
upf_pfcp_request_link_session (upf_pfcp_request_t *req, u32 session_id)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *um = &upf_main;
  upf_session_t *sx = pool_elt_at_index (um->sessions, session_id);

  upf_session_requests_list_insert_tail (psm->requests, &sx->requests, req);
  req->session.id = session_id;
  req->session.up_seid = sx->up_seid;
}

void
upf_pfcp_request_unlink_session (upf_pfcp_request_t *req)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *um = &upf_main;
  upf_session_t *sx = pool_elt_at_index (um->sessions, req->session.id);

  upf_session_requests_list_remove (psm->requests, &sx->requests, req);
  req->session.id = ~0;
  req->session.up_seid = 0;
}

void
upf_pfcp_message_encode (upf_pfcp_message_t *msg, pfcp_decoded_msg_t *dmsg,
                         u64 seid, u8 **result_vec)
{
  dmsg->seq_no = msg->k.seq_no;
  dmsg->seid = seid;
  ASSERT (*result_vec == NULL);

  int rv = pfcp_encode_msg (dmsg, result_vec);
  if (rv)
    {
      clib_warning ("BUG: encode failed for %U", format_pfcp_dmsg, dmsg);
      ASSERT (0);
    }
}

void
upf_pfcp_request_send (upf_pfcp_request_t *req, u8 *data,
                       upf_pfcp_server_retransmit_config_t *retransmit_cfg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  u32 req_id = req - psm->requests;
  req->n1 = retransmit_cfg->retries;
  req->t1 = retransmit_cfg->timeout;
  req->timer = upf_timer_start_secs (
    0, req->t1, UPF_TIMER_KIND_PFCP_REQUEST_T1, req_id, 0);
  req->data = data;

  if (vec_len (data) == 0)
    {
      ASSERT (0);
      clib_warning ("BUG: encode of request {%U}", format_upf_pfcp_request,
                    req);
      return; // we will crash soon anyway
    }

  hash_set (psm->request_q, req->m.k.seq_no, req_id);

  _upf_pfcp_send_data (&req->m, req->data, UPF_PFCP_SEND_REASON_request_init);

  upf_debug ("sent %U", format_upf_pfcp_request, req);
}

void
upf_pfcp_request_delete (upf_pfcp_request_t *req)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *um = &upf_main;

  upf_debug ("%U", format_upf_pfcp_request, req);

  if (is_valid_id (req->session.id))
    {
      upf_session_t *sx = pool_elt_at_index (um->sessions, req->session.id);
      ASSERT (req->session.up_seid == sx->up_seid);
      upf_session_requests_list_remove (psm->requests, &sx->requests, req);
    }
  if (is_valid_id (req->assoc.id))
    {
      upf_assoc_t *assoc = pool_elt_at_index (um->assocs, req->assoc.id);
      upf_assoc_requests_list_remove (psm->requests, &assoc->requests, req);
    }

  upf_timer_stop_safe (0, &req->timer);
  hash_unset (psm->request_q, req->m.k.seq_no);
  vec_free (req->data);
  pool_put (psm->requests, req);
}

upf_pfcp_response_t *
upf_pfcp_response_create (upf_pfcp_message_t *in_req)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_pfcp_response_t *resp;

  pool_get (psm->responses, resp);
  resp->m = *in_req;
  resp->timer.as_u32 = ~0;
  resp->data = NULL; // not yet populated
  mhash_set (&psm->response_q, &resp->m.k, resp - psm->responses, NULL);
  return resp;
}

static void
_upf_pfcp_response_restart_timer (upf_pfcp_response_t *resp)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  upf_timer_stop_safe (0, &resp->timer);
  resp->timer = upf_timer_start_secs (0, RESPONSE_TIMEOUT,
                                      UPF_TIMER_KIND_PFCP_RESPONSE_RETRANSMIT,
                                      resp - psm->responses, 0);
}

void
upf_pfcp_response_populate (upf_pfcp_response_t *resp, u8 *data)
{
  resp->data = data;
  _upf_pfcp_response_restart_timer (resp);

  _upf_pfcp_send_data (&resp->m, data, UPF_PFCP_SEND_REASON_response_populate);
}

void
upf_pfcp_response_delete (upf_pfcp_response_t *resp)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  if (resp->data)
    {
      upf_timer_stop_safe (0, &resp->timer);
      vec_free (resp->data);
    }

  mhash_unset (&psm->response_q, &resp->m.k, NULL);
  pool_put (psm->responses, resp);
}

static void
_upf_pfcp_server_response_expire (u16 thread_id, upf_timer_kind_t kind,
                                  u32 opaque, u16 opaque2)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  u32 resp_id = opaque;

  upf_pfcp_response_t *resp = pool_elt_at_index (psm->responses, resp_id);
  upf_pfcp_response_delete (resp);
}

// Send resposne with different SEID, like during SEID collision
void
upf_pfcp_server_send_response_with_seid (upf_pfcp_message_t *in_req,
                                         pfcp_decoded_msg_t *dmsg, u64 seid)
{
  upf_pfcp_response_t *r = upf_pfcp_response_create (in_req);
  u8 *data = NULL;
  upf_pfcp_message_encode (&r->m, dmsg, seid, &data);
  upf_pfcp_response_populate (r, data);
  pfcp_free_dmsg_contents (dmsg);
}

void
upf_pfcp_server_send_response (upf_pfcp_message_t *in_req,
                               pfcp_decoded_msg_t *dmsg)
{
  upf_pfcp_server_send_response_with_seid (in_req, dmsg, 0);
}

static void
_upf_pfcp_handle_msg (upf_pfcp_message_t *msg, upf_pfcp_request_t *req,
                      u8 *data)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_msg_type_t type = pfcp_msg_type (data);

  upf_debug ("received message %U as %s", format_pfcp_msg_type,
             pfcp_msg_type (data), req ? "expected reply" : "new message");

  pfcp_decoded_msg_t dmsg;
  pfcp_ie_offending_ie_t *decode_errs = NULL;
  int decode_cause =
    pfcp_decode_msg (data, vec_len (data), &dmsg, &decode_errs);

  if (decode_cause < 0) // if decode fail
    {
      upf_debug ("PFCP: broken message");
      upf_stats_get_pfcp_message (type)->rx_fail += 1;
    }
  else if (decode_cause != 0) // if decode error with cause
    {
      upf_debug ("PFCP: error response %d", decode_cause);
      upf_stats_get_pfcp_message (dmsg.type)->rx_fail += 1;

      upf_pfcp_decode_error_handler_t handler =
        upf_pfcp_get_on_decode_error_handler (dmsg.type);
      if (handler)
        handler (msg, dmsg.type, decode_cause, decode_errs);
    }
  else if (req) // if got response for request
    {
      u32 saved_req_seq = req->m.k.seq_no;

      // get handler based on request message type instead of response one
      upf_pfcp_response_handler_t handler =
        upf_pfcp_get_response_handler (pfcp_msg_type (req->data));

      ASSERT (handler); // request iniciator should ensure handler
      switch (handler (msg, req, &dmsg))
        {
        case UPF_PFCP_RESPONSE_RV_ACCEPT:
          // remove request if it wasn't removed by handler
          if (!pool_is_free_index (psm->requests, req - psm->requests) &&
              req->m.k.seq_no == saved_req_seq)
            {
              upf_pfcp_request_delete (req);
            }
          upf_stats_get_pfcp_message (dmsg.type)->rx_ok += 1;
          break;
        case UPF_PFCP_RESPONSE_RV_IGNORE:
          upf_debug ("keeping request");
          upf_stats_get_pfcp_message (dmsg.type)->rx_ok += 1;
          break;
        }
    }
  else // if got new request
    {
      upf_pfcp_message_handler_t handler = upf_pfcp_get_message_handler (type);
      if (!handler)
        {
          upf_debug ("PFCP: msg type no handler: %d.", type);
          upf_stats_get_pfcp_message (type)->rx_fail += 1;
        }
      else
        {
          switch (handler (msg, &dmsg))
            {
            case UPF_PFCP_MESSAGE_RV_SUCCESS:
              upf_stats_get_pfcp_message (dmsg.type)->rx_ok += 1;
              break;
            case UPF_PFCP_MESSAGE_RV_FAILED:
              upf_stats_get_pfcp_message (dmsg.type)->rx_error += 1;
              break;
            }
        }
    }

  vec_free (decode_errs);
  pfcp_free_dmsg_contents (&dmsg);
}

void
upf_pfcp_server_rx_message (upf_pfcp_message_t *msg, u8 *data)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  upf_debug ("handling %U with len %d", format_upf_pfcp_message, msg,
             vec_len (data));

  u32 len = vec_len (data);
  if (len < 4)
    {
      upf_stats_get_pfcp_message (~0)->rx_fail += 1;
      upf_debug ("message too short");
      return;
    }

  upf_debug ("%U", format_pfcp_msg_header, (pfcp_msg_header_t *) data);

  pfcp_msg_header_t *mh = (pfcp_msg_header_t *) data;
  if (mh->version != 1)
    {
      upf_stats_get_pfcp_message (~0)->rx_fail += 1;
      upf_debug ("message version invalid: %d", mh->version);

      upf_pfcp_response_t *resp = upf_pfcp_response_create (msg);
      // TODO: test version not supported
      pfcp_decoded_msg_t dmsg = {};
      dmsg.type = PFCP_MSG_VERSION_NOT_SUPPORTED_RESPONSE;

      u8 *data = NULL;
      pfcp_encode_version_not_supported_response (&data);
      upf_pfcp_message_encode (&resp->m, &dmsg, 0, &data);
      upf_pfcp_response_populate (resp, data);
      return;
    }

  if (!pfcp_msg_enough_len (data, len))
    {
      upf_debug ("invalid message length, data %d, msg %d.", len,
                 pfcp_msg_length (data));
      upf_stats_get_pfcp_message (~0)->rx_fail += 1;
      return;
    }

  msg->k.seq_no = pfcp_msg_seq (data);

  // look for retransmit first

  // TODO: get rid of switch
  // TODO: follow 6.4 Reliable Delivery of PFCP Messages more closely:
  // A retransmitted PFCP message shall have the same message content,
  // including the same PFCP header, UDP ports, source and destination IP
  // addresses as the originally transmitted message A Request and its Response
  // messages are matched based on the Sequence Number and the IP address and
  // UDP port. A received Response message not matching an outstanding Request
  // message waiting for a reply should be discarded
  switch (pfcp_msg_type (data))
    {
    default:
      upf_stats_get_pfcp_message (pfcp_msg_type (data))->rx_error += 1;
      break;
    case PFCP_MSG_HEARTBEAT_REQUEST:
    case PFCP_MSG_PFD_MANAGEMENT_REQUEST:
    case PFCP_MSG_ASSOCIATION_SETUP_REQUEST:
    case PFCP_MSG_ASSOCIATION_UPDATE_REQUEST:
    case PFCP_MSG_ASSOCIATION_RELEASE_REQUEST:
    case PFCP_MSG_NODE_REPORT_REQUEST:
    case PFCP_MSG_SESSION_SET_DELETION_REQUEST:
    case PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST:
    case PFCP_MSG_SESSION_MODIFICATION_REQUEST:
    case PFCP_MSG_SESSION_DELETION_REQUEST:
    case PFCP_MSG_SESSION_REPORT_REQUEST:
      {
        uword *presp = mhash_get (&psm->response_q, &msg->k);

        if (!presp)
          {
            _upf_pfcp_handle_msg (msg, NULL, data);
          }
        else
          {
            // received retransmit
            upf_stats_get_pfcp_message (pfcp_msg_type (data))->rx_retransmit +=
              1;

            upf_pfcp_response_t *resp =
              pool_elt_at_index (psm->responses, presp[0]);

            upf_debug ("resend %U", format_upf_pfcp_response, resp);
            if (resp->data)
              {
                _upf_pfcp_send_data (&resp->m, resp->data,
                                     UPF_PFCP_SEND_REASON_response_resend);
                // prolong retransmit slot timer
                _upf_pfcp_response_restart_timer (resp);
              }
          }
        break;
      }

    case PFCP_MSG_HEARTBEAT_RESPONSE:
    case PFCP_MSG_PFD_MANAGEMENT_RESPONSE:
    case PFCP_MSG_ASSOCIATION_SETUP_RESPONSE:
    case PFCP_MSG_ASSOCIATION_UPDATE_RESPONSE:
    case PFCP_MSG_ASSOCIATION_RELEASE_RESPONSE:
    case PFCP_MSG_VERSION_NOT_SUPPORTED_RESPONSE:
    case PFCP_MSG_NODE_REPORT_RESPONSE:
    case PFCP_MSG_SESSION_SET_DELETION_RESPONSE:
    case PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE:
    case PFCP_MSG_SESSION_MODIFICATION_RESPONSE:
    case PFCP_MSG_SESSION_DELETION_RESPONSE:
    case PFCP_MSG_SESSION_REPORT_RESPONSE:
      {
        uword *p = hash_get (psm->request_q, msg->k.seq_no);
        upf_debug ("seq %u, id %d", msg->k.seq_no, p ? p[0] : ~0);
        if (!p)
          {
            upf_stats_get_pfcp_message (pfcp_msg_type (data))->rx_error += 1;
            upf_debug ("unexpected response for invalid request");
            return;
          }

        upf_pfcp_request_t *req = pool_elt_at_index (psm->requests, p[0]);
        _upf_pfcp_handle_msg (msg, req, data);
      }
    }
}

static void
_upf_pfcp_request_t1_expire (u16 thread_id, upf_timer_kind_t kind, u32 opaque,
                             u16 opaque2)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *um = &upf_main;
  u32 req_id = opaque;

  upf_pfcp_request_t *req = pool_elt_at_index (psm->requests, req_id);
  ASSERT (req->flags.is_stopped == 0);

  ASSERT (is_valid_id (req->assoc.id));

  upf_debug ("%U", format_upf_pfcp_request, req);

  upf_timer_stop_safe (0, &req->timer);

  // Make sure to resent reports to new peer if smfset peer is changed
  if (req->flags.is_migrated_in_smfset && is_valid_id (req->session.id) &&
      pfcp_msg_type (req->data) == PFCP_MSG_SESSION_REPORT_REQUEST)
    {
      upf_session_t *sx = pool_elt_at_index (um->sessions, req->session.id);

      pfcp_decoded_msg_t dmsg;
      pfcp_ie_offending_ie_t *err = NULL;

      // Decode request to dmesg so we can modify it and send new request
      pfcp_decode_msg (req->data, vec_len (req->data), &dmsg, &err);

      if (sx->is_lost_smfset_cp)
        {
          upf_cached_f_seid_t *cached_f_seid =
            pool_elt_at_index (um->cached_fseid_pool, sx->cached_fseid_id);
          BIT_SET (dmsg.session_report_request.grp.fields,
                   SESSION_REPORT_REQUEST_OLD_CP_F_SEID);
          dmsg.session_report_request.old_cp_f_seid.seid = sx->cp_seid;
          dmsg.session_report_request.old_cp_f_seid.flags =
            cached_f_seid->key.flags;
          dmsg.session_report_request.old_cp_f_seid.ip4 =
            cached_f_seid->key.ip4;
          dmsg.session_report_request.old_cp_f_seid.ip6 =
            cached_f_seid->key.ip6;
        }

      upf_assoc_t *new_assoc = pool_elt_at_index (um->assocs, sx->assoc.id);
      if (!new_assoc->is_released)
        {
          upf_debug ("resending request to assoc %U", format_upf_assoc,
                     new_assoc, 0);
          // encode and send new request
          upf_pfcp_request_t *new_req = upf_pfcp_request_create (new_assoc);
          upf_pfcp_request_link_session (new_req, sx - um->sessions);

          u8 *new_data = 0;
          upf_pfcp_message_encode (&new_req->m, &dmsg, 0, &new_data);
          upf_pfcp_request_send (new_req, new_data, &psm->default_cfg);
        }
      else
        {
          upf_debug ("NOT resending request to released assoc %U",
                     format_upf_assoc, new_assoc, 0);
        }

      pfcp_free_dmsg_contents (&dmsg);
      // stop old request directed to now lost association
      upf_pfcp_request_delete (req);
      return;
    }

  u8 type = pfcp_msg_type (req->data);
  if (--req->n1 != 0)
    {
      upf_debug ("retransmit %U", format_upf_pfcp_request, req);

      req->timer = upf_timer_start_secs (
        0, req->t1, UPF_TIMER_KIND_PFCP_REQUEST_T1, req_id, 0);

      _upf_pfcp_send_data (&req->m, req->data,
                           UPF_PFCP_SEND_REASON_request_retransmit);

      // warning specifically for this message
      if (type == PFCP_MSG_HEARTBEAT_REQUEST &&
          !pool_is_free_index (um->assocs, req->assoc.id))
        {
          upf_assoc_t *n = pool_elt_at_index (um->assocs, req->assoc.id);
          vlib_log_info (
            um->log_class,
            "PFCP Association unstable: node %U, local IP %U, remote IP %U\n",
            format_pfcp_ie_node_id, &n->node_id, format_ip46_address,
            &n->lcl_addr, IP46_TYPE_ANY, format_ip46_address, &n->rmt_addr,
            IP46_TYPE_ANY);
        }
    }
  else
    {
      upf_debug ("timeout %U", format_upf_pfcp_request, req);

      upf_stats_get_pfcp_message (pfcp_msg_type (req->data))->tx_req_timeout +=
        1;

      u32 saved_req_seq = req->m.k.seq_no;

      upf_pfcp_get_timeout_handler (pfcp_msg_type (req->data)) (req);

      // remove request if it wasn't removed by handler
      if (!pool_is_free_index (psm->requests, req_id) &&
          req->m.k.seq_no == saved_req_seq)
        {
          upf_pfcp_request_delete (req);
        }
    }
}

void
_upf_pfcp_server_handle_hb_on_time (u16 thread_id, upf_timer_kind_t kind,
                                    u32 opaque, u16 opaque2)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_decoded_msg_t dmsg = {
    .type = PFCP_MSG_HEARTBEAT_REQUEST,
    .heartbeat_request = {},
  };
  pfcp_msg_heartbeat_request_t *req = &dmsg.heartbeat_request;
  upf_main_t *um = &upf_main;
  upf_assoc_t *a;
  u32 assoc_id = opaque;

  a = pool_elt_at_index (um->assocs, assoc_id);

  upf_timer_stop (0, a->heartbeat_timer);
  a->heartbeat_timer.as_u32 = ~0;

  // The timer has expired, we shouldn't try to stop it when releasing the
  // association

  memset (req, 0, sizeof (*req));
  BIT_SET (req->grp.fields, HEARTBEAT_REQUEST_RECOVERY_TIME_STAMP);
  req->recovery_time_stamp = psm->recovery;

  ASSERT (!a->is_released); // shouldn't happen
  if (a->is_released)
    return;

  upf_pfcp_request_t *new_req = upf_pfcp_request_create (a);
  u8 *data = 0;
  upf_pfcp_message_encode (&new_req->m, &dmsg, 0, &data);
  upf_pfcp_request_send (new_req, data, &psm->heartbeat_cfg);
  pfcp_free_dmsg_contents (&dmsg);
}

u8 *
format_upf_pfcp_key (u8 *s, va_list *args)
{
  upf_pfcp_key_t *v = va_arg (*args, upf_pfcp_key_t *);

  s =
    format (s, "remote %U:%u handle 0x%x seq %u", format_ip46_address,
            &v->rmt_address, IP46_TYPE_ANY, clib_net_to_host_u16 (v->rmt_port),
            v->session_handle, v->seq_no);
  return s;
}

u8 *
format_upf_pfcp_message (u8 *s, va_list *args)
{
  upf_pfcp_message_t *v = va_arg (*args, upf_pfcp_message_t *);

  s = format (s, "k{%U} lcl %U:%u", format_upf_pfcp_key, &v->k,
              format_ip46_address, &v->lcl_address, IP46_TYPE_ANY,
              clib_net_to_host_u16 (v->lcl_port));
  return s;
}

u8 *
format_upf_pfcp_request (u8 *s, va_list *args)
{
  upf_pfcp_request_t *v = va_arg (*args, upf_pfcp_request_t *);

  uword msg_type = 0;
  if (v->data)
    msg_type = pfcp_msg_type (v->data);

  s = format (
    s,
    "m{%U} t %U len %d assoc %d sx %d seid 0x%x timer 0x%x n1 %d t1 %d "
    "msmfset %d stopped %d",
    format_upf_pfcp_message, &v->m, format_pfcp_msg_type, msg_type,
    vec_len (v->data), v->assoc.id, v->session.id, v->session.up_seid,
    v->timer.as_u32, v->n1, v->t1, v->flags.is_migrated_in_smfset,
    v->flags.is_stopped);
  return s;
}

u8 *
format_upf_pfcp_response (u8 *s, va_list *args)
{
  upf_pfcp_response_t *v = va_arg (*args, upf_pfcp_response_t *);

  uword msg_type = 0;
  if (v->data)
    msg_type = pfcp_msg_type (v->data);

  s = format (s, "m{%U} t %U len %d timer 0x%x", format_upf_pfcp_message,
              &v->m, format_pfcp_msg_type, msg_type, vec_len (v->data),
              v->timer.as_u32);
  return s;
}

int
upf_pfcp_heartbeat_config (u32 timeout, u32 retries)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  if (!timeout || timeout > PFCP_MAX_HB_INTERVAL ||
      retries > PFCP_MAX_HB_RETRIES)
    return -1;

  psm->heartbeat_cfg.timeout = timeout;
  psm->heartbeat_cfg.retries = retries;

  return 0;
}

vnet_api_error_t
upf_node_id_set (const pfcp_ie_node_id_t *node_id)
{
  upf_main_t *um = &upf_main;

  switch (node_id->type)
    {
    case PFCP_NID_IPv4:
    case PFCP_NID_IPv6:
    case PFCP_NID_FQDN:
      free_pfcp_ie_node_id (&um->node_id);
      copy_pfcp_ie_node_id (&um->node_id, (pfcp_ie_node_id_t *) node_id);
      return 0;
    }

  return VNET_API_ERROR_INVALID_ARGUMENT;
}

vnet_api_error_t
upf_ue_ip_pool_add_del (u8 *identity, u8 *nwi_name, int is_add)
{
  upf_main_t *um = &upf_main;
  upf_ue_ip_pool_info_t *ueip_pool = NULL;
  uword *p;

  identity = vec_dup (identity);

  p = hash_get_mem (um->ue_ip_pool_index_by_identity, identity);

  if (is_add)
    {
      if (p)
        return VNET_API_ERROR_VALUE_EXIST;

      pool_get (um->ueip_pools, ueip_pool);
      ueip_pool->identity = identity;
      ueip_pool->nwi_name = vec_dup (nwi_name);

      hash_set_mem (um->ue_ip_pool_index_by_identity, identity,
                    ueip_pool - um->ueip_pools);
    }
  else
    {
      if (!p)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      ueip_pool = pool_elt_at_index (um->ueip_pools, p[0]);
      hash_unset_mem (um->ue_ip_pool_index_by_identity, identity);
      vec_free (ueip_pool->identity);
      vec_free (ueip_pool->nwi_name);
      pool_put (um->ueip_pools, ueip_pool);
    }
  return 0;
}

void
pfcp_server_main_init ()
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  memset (psm, 0, sizeof (*psm));

  psm->recovery = time (NULL);

  mhash_init (&psm->response_q, sizeof (uword), sizeof (upf_pfcp_key_t));

  upf_debug ("recovery: %d, %x", psm->recovery, psm->recovery);

  psm->heartbeat_cfg.retries = PFCP_DEFAULT_REQUEST_RETRIES;
  psm->heartbeat_cfg.timeout = PFCP_DEFAULT_REQUEST_INTERVAL;
  psm->default_cfg.retries = PFCP_DEFAULT_REQUEST_RETRIES;
  psm->default_cfg.timeout = PFCP_DEFAULT_REQUEST_INTERVAL;

  tokenbucket_init (&psm->pfcp_request_drop_ratelimit, upf_time_now_main (),
                    PFCP_DEFAULT_PACKETS_DROP_RATELIMIT,
                    PFCP_DEFAULT_PACKETS_DROP_RATELIMIT);

  upf_timer_set_handler (UPF_TIMER_KIND_PFCP_REQUEST_T1,
                         _upf_pfcp_request_t1_expire);
  upf_timer_set_handler (UPF_TIMER_KIND_PFCP_HEARTBEAT,
                         _upf_pfcp_server_handle_hb_on_time);
  upf_timer_set_handler (UPF_TIMER_KIND_PFCP_RESPONSE_RETRANSMIT,
                         _upf_pfcp_server_response_expire);
}
