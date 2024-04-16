/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/** @file
    udp upf_pfcp server
*/

#include <math.h>
#include <inttypes.h>

#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

#include <vppinfra/bihash_vec8_8.h>
#include <vppinfra/bihash_template.h>

#include <vppinfra/bihash_template.c>

#include "upf_pfcp.h"
#include "upf_pfcp_api.h"
#include "upf_pfcp_server.h"

#define RESPONSE_TIMEOUT 30

/* use pow2 to avoid rounding error accumulation in timerwheel implementation
 */
#define TW_CLOCKS_PER_SECOND (128.0)
#define TW_SECS_PER_CLOCK    (1.0 / TW_CLOCKS_PER_SECOND)

/* as defined in vnet/policer, PPS-based QOS fixed size */
#define UPF_POLICER_FIXED_PKT_SIZE   256
#define LATE_TIMER_WARNING_THRESHOLD 5

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#define urr_debug_out(format, args...)                                        \
  _clib_error (CLIB_ERROR_WARNING, NULL, 0, format, ##args)

#else
#define upf_debug(...)                                                        \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)

#define urr_debug_out(...)                                                    \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

static void upf_pfcp_make_response (pfcp_msg_t *resp, pfcp_msg_t *req);
static void restart_response_timer (pfcp_msg_t *msg);
static void upf_pfcp_server_send_session_request (upf_session_t *sx,
                                                  pfcp_decoded_msg_t *dmsg);

pfcp_server_main_t pfcp_server_main;

#define MAX_HDRS_LEN 100 /* Max number of bytes for headers */

static u32
upf_pfcp_server_start_generic_timer (u32 user_handle, u32 ticks)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_timer_t *timer;
  u32 index;
  /*
   * Here we assume that 1<<32 timers don't get used up during the
   * lifetime of any of the timers. Otherwise the rollover is ok.
   * We don't reuse timer handles to detect the cases when the timer
   * is stopped twice
   */
  u32 handle = psm->next_timer_handle++;
  pool_get (psm->timers, timer);
  index = timer - psm->timers;
  timer->handle = handle;
  timer->tw_handle = TW (tw_timer_start) (&psm->timer, index, 0, ticks);
  timer->user_handle = user_handle;
  timer->next_expired_timer = ~0;
  hash_set (psm->timer_handle_map, handle, index);
  return handle;
}

#define upf_pfcp_server_stop_generic_timer(handle)                            \
  upf_pfcp_server_do_stop_generic_timer (handle, __FUNCTION__)

static void
upf_pfcp_server_do_stop_generic_timer (u32 handle, const char *what)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  uword *p;
  upf_timer_t *timer;

  p = hash_get (psm->timer_handle_map, handle);
  if (!p)
    {
      clib_warning (
        "timer error: %s: stopping timer that has already been stopped", what);
      return;
    }

  timer = pool_elt_at_index (psm->timers, p[0]);
  if (timer->tw_handle == ~0)
    {
      /*
       * We want to distinguish between stopping timer twice and stopping
       * expired timers for debugging purpose
       */
      clib_warning ("timer error: %s: stopping timer that has expired", what);
      return;
    }

  ASSERT (timer->handle == handle);

  TW (tw_timer_stop) (&psm->timer, timer->tw_handle);

  hash_unset (psm->timer_handle_map, handle);
  pool_put (psm->timers, timer);
}

static void
upf_pfcp_server_expire_timers ()
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  uword *p;
  upf_timer_t *timer;
  u32 idx;

  /*
   * Clean up timers that have expired during previous iteration
   */
  for (idx = psm->next_expired_timer; idx != ~0;
       idx = timer->next_expired_timer)
    {
      timer = pool_elt_at_index (psm->timers, idx);
      hash_unset (psm->timer_handle_map, timer->handle);
      pool_put (psm->timers, timer);
    }

  psm->next_expired_timer = ~0;

  psm->expired =
    TW (tw_timer_expire_timers_vec) (&psm->timer, psm->now, psm->expired);

  vec_foreach_index (idx, psm->expired)
    {
      timer = pool_elt_at_index (psm->timers, psm->expired[idx]);
      if (timer->tw_handle == ~0)
        {
          clib_warning ("timer error: a timer has expired twice (?)");
          continue;
        }

      timer->tw_handle = ~0;
      psm->expired[idx] = timer->user_handle;
      /*
       * Make it so that the timer entry will be cleaned up upon the
       * next iteration
       */
      timer->next_expired_timer = psm->next_expired_timer;
      psm->next_expired_timer = timer - psm->timers;
    }
}

static void
upf_pfcp_send_data (pfcp_msg_t *msg)
{
  app_session_transport_t at;
  svm_msg_q_t *mq;
  session_t *s;
  vlib_main_t *vm = vlib_get_main ();

  s = session_get_from_handle_if_valid (msg->session_handle);
  if (!s)
    return;

  mq = session_main_get_vpp_event_queue (s->thread_index);
  at.is_ip4 = ip46_address_is_ip4 (&msg->lcl.address);
  at.lcl_ip = msg->lcl.address;
  at.rmt_ip = msg->rmt.address;
  at.lcl_port = msg->lcl.port;
  at.rmt_port = msg->rmt.port;

  int r =
    app_send_dgram_raw (s->tx_fifo, &at, mq, msg->data, _vec_len (msg->data),
                        SESSION_IO_EVT_TX, 1 /* do_evt */, 0);
  /*
   * This is needed in case if there are > 0 workers
   * as PFCP still runs on the main thread which can't
   * process the session queue by itself w/o being
   * "nudged" this way
   */
  if (vm->thread_index == 0 && vlib_num_workers ())
    session_queue_run_on_main_thread (vm);
}

static int
encode_pfcp_session_msg (upf_session_t *sx, pfcp_decoded_msg_t *dmsg,
                         pfcp_msg_t *msg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *gtm = &upf_main;
  upf_node_assoc_t *n;
  int r = 0;

  init_pfcp_msg (msg);

  n = pool_elt_at_index (gtm->nodes, sx->assoc.node);

  msg->seq_no = clib_atomic_add_fetch (&psm->seq_no, 1) % 0x1000000;
  msg->node = sx->assoc.node;
  msg->session.idx = sx - gtm->sessions;
  msg->up_seid = sx->up_seid;

  if (dmsg->type == PFCP_MSG_SESSION_REPORT_REQUEST &&
      sx->flags & UPF_SESSION_LOST_CP)
    {
      upf_cached_f_seid_t *cached_f_seid =
        pool_elt_at_index (gtm->cached_fseid_pool, sx->cached_fseid_idx);
      UPF_SET_BIT (dmsg->session_report_request.grp.fields,
                   SESSION_REPORT_REQUEST_OLD_CP_F_SEID);
      dmsg->session_report_request.old_cp_f_seid.seid = sx->cp_seid;
      dmsg->session_report_request.old_cp_f_seid.flags =
        cached_f_seid->key.flags;
      dmsg->session_report_request.old_cp_f_seid.ip4 = cached_f_seid->key.ip4;
      dmsg->session_report_request.old_cp_f_seid.ip6 = cached_f_seid->key.ip6;

      dmsg->seid = 0;
    }
  else
    {
      dmsg->seid = sx->cp_seid;
    }

  dmsg->seq_no = msg->seq_no;
  if ((r = pfcp_encode_msg (dmsg, &msg->data)) != 0)
    return r;

  msg->session_handle = n->session_handle;
  msg->lcl.address = n->lcl_addr;
  msg->rmt.address = n->rmt_addr;
  msg->lcl.port = clib_host_to_net_u16 (UDP_DST_PORT_PFCP);
  msg->rmt.port = clib_host_to_net_u16 (UDP_DST_PORT_PFCP);

  upf_debug ("PFCP Session Msg on session 0x%016lx from %U:%d to %U:%d\n",
             msg->session_handle, format_ip46_address, &msg->lcl.address,
             IP46_TYPE_ANY, clib_net_to_host_u16 (msg->lcl.port),
             format_ip46_address, &msg->rmt.address, IP46_TYPE_ANY,
             clib_net_to_host_u16 (msg->rmt.port));

  return 0;
}

static int
encode_pfcp_node_msg (upf_node_assoc_t *n, pfcp_decoded_msg_t *dmsg,
                      pfcp_msg_t *msg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *gtm = &upf_main;
  int r = 0;

  init_pfcp_msg (msg);

  msg->seq_no = clib_atomic_add_fetch (&psm->seq_no, 1) % 0x1000000;
  msg->node = n - gtm->nodes;

  dmsg->seq_no = msg->seq_no;
  if ((r = pfcp_encode_msg (dmsg, &msg->data)) != 0)
    return r;

  msg->session_handle = n->session_handle;
  msg->lcl.address = n->lcl_addr;
  msg->rmt.address = n->rmt_addr;
  msg->lcl.port = clib_host_to_net_u16 (UDP_DST_PORT_PFCP);
  msg->rmt.port = clib_host_to_net_u16 (UDP_DST_PORT_PFCP);

  upf_debug ("PFCP Node Msg on session 0x%016lx from %U:%d to %U:%d\n",
             msg->session_handle, format_ip46_address, &msg->lcl.address,
             IP46_TYPE_ANY, clib_net_to_host_u16 (msg->lcl.port),
             format_ip46_address, &msg->rmt.address, IP46_TYPE_ANY,
             clib_net_to_host_u16 (msg->rmt.port));

  return 0;
}

static int
upf_pfcp_server_rx_msg (pfcp_msg_t *msg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  int len = vec_len (msg->data);

  if (len < 4)
    return -1;

  upf_debug ("%U", format_pfcp_msg_header, (pfcp_msg_header_t *) msg->data);

  if (!pfcp_msg_version_valid (msg->data))
    {
      pfcp_msg_t resp;

      upf_debug ("PFCP: msg version invalid: %d.",
                 pfcp_msg_version (msg->data));

      memset (&resp, 0, sizeof (resp));
      upf_pfcp_make_response (&resp, msg);
      pfcp_encode_version_not_supported_response (&msg->data);
      upf_pfcp_send_data (&resp);
      vec_free (resp.data);

      return 0;
    }

  if (!pfcp_msg_enough_len (msg->data, len))
    {
      upf_debug ("PFCP: msg length invalid, data %d, msg %d.", len,
                 pfcp_msg_length (msg->data));
      return -1;
    }

  msg->node = ~0;

  msg->seq_no = pfcp_msg_seq (msg->data);

  switch (pfcp_msg_type (msg->data))
    {
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
        uword *p = NULL;

        p = mhash_get (&psm->response_q, msg->request_key);
        if (!p)
          {
            upf_pfcp_handle_msg (msg);
          }
        else
          {
            pfcp_msg_t *resp = pfcp_msg_pool_elt_at_index (psm, p[0]);

            upf_debug ("resend... %d\n", p[0]);
            upf_pfcp_send_data (resp);
            restart_response_timer (resp);
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
        pfcp_msg_t *req;
        uword *p;

        p = hash_get (psm->request_q, msg->seq_no);
        upf_debug ("Msg Seq No: %u, %p, idx %u\n", msg->seq_no, p,
                   p ? p[0] : ~0);
        if (!p)
          break;

        req = pfcp_msg_pool_elt_at_index (psm, p[0]);

        msg->node = req->node;
        msg->session.idx = req->session.idx;
        msg->up_seid = req->up_seid;

        upf_pfcp_server_stop_msg_timer (req);

        upf_pfcp_handle_msg (msg);

        upf_pfcp_server_stop_request (req);

        break;
      }

    default:
      break;
    }

  return 0;
}

static pfcp_msg_t *
build_pfcp_session_msg (upf_session_t *sx, pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_msg_t *msg;
  int r = 0;

  msg = pfcp_msg_pool_get (psm);
  if ((r = encode_pfcp_session_msg (sx, dmsg, msg)) != 0)
    {
      pfcp_msg_pool_put (psm, msg);
      return NULL;
    }

  return msg;
}

static pfcp_msg_t *
build_pfcp_node_msg (upf_node_assoc_t *n, pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_msg_t *msg;
  int r = 0;

  msg = pfcp_msg_pool_get (psm);
  if ((r = encode_pfcp_node_msg (n, dmsg, msg)) != 0)
    {
      pfcp_msg_pool_put (psm, msg);
      return NULL;
    }

  return msg;
}

int
upf_pfcp_send_request (upf_session_t *sx, pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  vlib_main_t *vm = psm->vlib_main;
  pfcp_msg_t *msg;
  int r = -1;

  msg = clib_mem_alloc_aligned_no_fail (sizeof (*msg), CLIB_CACHE_LINE_BYTES);
  memset (msg, 0, sizeof (*msg));

  if ((r = encode_pfcp_session_msg (sx, dmsg, msg)) != 0)
    {
      clib_mem_free (msg);
      goto out_free;
    }

  upf_debug ("sending NOTIFY event %p", msg);
  vlib_process_signal_event_mt (vm, pfcp_api_process_node.index, EVENT_TX,
                                (uword) msg);

out_free:
  pfcp_free_dmsg_contents (dmsg);
  return r;
}

static void
enqueue_request (pfcp_msg_t *msg, u32 n1, u32 t1)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  u32 id = pfcp_msg_get_index (psm, msg);

  upf_debug ("Msg Seq No: %u, idx %u\n", msg->seq_no, id);
  msg->n1 = n1;
  msg->t1 = t1;

  hash_set (psm->request_q, msg->seq_no, id);
  if (msg->session.idx != ~0)
    {
      upf_session_requests_list_anchor_init (msg);
      upf_session_t *sx =
        pool_elt_at_index (upf_main.sessions, msg->session.idx);

      upf_session_requests_list_insert_tail (psm->msg_pool, &sx->requests,
                                             msg);
    }

  msg->timer =
    upf_pfcp_server_start_timer (PFCP_SERVER_T1, msg->seq_no, msg->t1);
  msg->expires_at = psm->now + msg->t1;
}

static void
request_t1_expired (u32 seq_no)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *gtm = &upf_main;
  pfcp_msg_t *req;
  uword *p;

  p = hash_get (psm->request_q, seq_no);
  upf_debug ("Msg Seq No: %u, %p, idx %u\n", seq_no, p, p ? p[0] : ~0);
  if (!p)
    /* msg already processed, overlap of timeout and late answer */
    return;

  req = pfcp_msg_pool_elt_at_index (psm, p[0]);
  ASSERT (req->flags.is_stopped == 0);
  req->timer = ~0;

  // handle edge case: timer expired in this iteration
  // TODO: this should not be needed after multithreading
  if (!req->data)
    return;

  upf_debug ("Msg Seq No: %u, %p, n1 %u\n", req->seq_no, req, req->n1);

  /* make sure to resent reports to new peer if smfset peer is changed */
  if (req->flags.is_migrated_in_smfset && req->session.idx != ~0 &&
      pfcp_msg_type (req->data) == PFCP_MSG_SESSION_REPORT_REQUEST)
    {
      upf_session_t *sx = pool_elt_at_index (gtm->sessions, req->session.idx);

      pfcp_decoded_msg_t dmsg;
      pfcp_ie_offending_ie_t *err = NULL;

      /* Decode request to dmesg so we can reencode it as new request */
      pfcp_decode_msg (req->data, vec_len (req->data), &dmsg, &err);
      upf_pfcp_server_send_session_request (sx, &dmsg);
      pfcp_free_dmsg_contents (&dmsg);

      /* stop old request */
      upf_pfcp_server_stop_request (req);
      return;
    }

  u8 type = pfcp_msg_type (req->data);

  if (--req->n1 != 0)
    {
      /*
         FIXME: here in pool_is_free_index we check for node index which can be
         reused as soon as node goes back. Instead we should stop all requests
         as soon as node is stopped. It should be easier to track since we can
         have only one heartbeat request at time
       */
      if (type == PFCP_MSG_HEARTBEAT_REQUEST &&
          !pool_is_free_index (gtm->nodes, req->node))
        {
          upf_node_assoc_t *n = pool_elt_at_index (gtm->nodes, req->node);
          upf_pfcp_associnfo (
            gtm,
            "PFCP Association unstable: node %U, local IP %U, remote IP %U\n",
            format_pfcp_ie_node_id, &n->node_id, format_ip46_address,
            &n->lcl_addr, IP46_TYPE_ANY, format_ip46_address, &n->rmt_addr,
            IP46_TYPE_ANY);
        }

      upf_debug ("resend...\n");
      req->timer =
        upf_pfcp_server_start_timer (PFCP_SERVER_T1, req->seq_no, req->t1);
      req->expires_at = psm->now + req->t1;

      upf_pfcp_send_data (req);
    }
  else
    {
      u32 node = req->node;

      upf_debug ("abort...\n");
      // TODO: handle communication breakdown....

      upf_pfcp_server_stop_request (req);

      /*
         TODO: this pool_is_free_index is invalid since pool id can be reused
         instead we should do checking based on persistent key or instead we
         could track or requests of node and forget them as soon as association
         is lost
       */
      if (type == PFCP_MSG_HEARTBEAT_REQUEST &&
          !pool_is_free_index (gtm->nodes, node))
        {
          upf_node_assoc_t *n = pool_elt_at_index (gtm->nodes, node);

          upf_pfcp_associnfo (
            gtm, "PFCP Association lost: node %U, local IP %U, remote IP %U\n",
            format_pfcp_ie_node_id, &n->node_id, format_ip46_address,
            &n->lcl_addr, IP46_TYPE_ANY, format_ip46_address, &n->rmt_addr,
            IP46_TYPE_ANY);

          pfcp_release_association (n);
        }
    }
}

void
upf_pfcp_server_stop_request (pfcp_msg_t *req)
{
  /* FIXME: ivan4th: handle edge case: t1 timer also expired in this iteration
   * for this seq_no */
  /* (do we really need any special handling there? unsure...) */

  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *gtm = &upf_main;

  if (req->session.idx != ~0)
    {
      upf_session_t *sx = pool_elt_at_index (gtm->sessions, req->session.idx);
      upf_session_requests_list_remove (psm->msg_pool, &sx->requests, req);
      req->session.idx = ~0;
    }
  upf_pfcp_server_stop_msg_timer (req);

  hash_unset (psm->request_q, req->seq_no);

  req->flags.is_stopped = 1;
  pfcp_msg_pool_put (psm, req);
}

static void
upf_pfcp_server_send_request (pfcp_msg_t *msg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  if (pfcp_msg_type (msg->data) == PFCP_MSG_HEARTBEAT_REQUEST)
    enqueue_request (msg, psm->hb_cfg.retries, psm->hb_cfg.timeout);
  else
    enqueue_request (msg, PFCP_DEFAULT_REQUEST_RETRIES,
                     PFCP_DEFAULT_REQUEST_INTERVAL);

  upf_pfcp_send_data (msg);
}

/* When TDF-U reports new UE IP session to TDF-C it creates Session Report
 * with Usage Report and Start of Traffic as a reporting trigger. Instead
 * of Usage Report triggered by application usage, there should be no
 * application detection information in the report. Also UE IP Address
 * should be reported in this case. To avoid TDF-C overload UPG can
 * hold number of such Session Report requests.
 */
static bool
upf_pfcp_police_message (upf_session_t *sx, pfcp_decoded_msg_t *dmsg)
{
  upf_main_t *gtm = &upf_main;
  u64 time_in_policer_periods;
  upf_node_assoc_t *n = pool_elt_at_index (gtm->nodes, sx->assoc.node);
  policer_t *p = pool_elt_at_index (gtm->pfcp_policers, n->policer_idx);

  if (dmsg->type != PFCP_MSG_SESSION_REPORT_REQUEST ||
      !dmsg->session_report_request.usage_report)
    return true;

  if (ISSET_BIT (dmsg->session_report_request.usage_report->grp.fields,
                 USAGE_REPORT_APPLICATION_DETECTION_INFORMATION) ||
      !ISSET_BIT (dmsg->session_report_request.usage_report->grp.fields,
                  USAGE_REPORT_UE_IP_ADDRESS) ||
      !(dmsg->session_report_request.usage_report->usage_report_trigger &
        PFCP_USAGE_REPORT_TRIGGER_START_OF_TRAFFIC))
    return true;

  time_in_policer_periods =
    clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

  return vnet_police_packet (p, UPF_POLICER_FIXED_PKT_SIZE, POLICE_CONFORM,
                             time_in_policer_periods) == POLICE_CONFORM;
}

static void
upf_pfcp_server_send_session_request (upf_session_t *sx,
                                      pfcp_decoded_msg_t *dmsg)
{
  pfcp_msg_t *msg;

  if (!upf_pfcp_police_message (sx, dmsg))
    return;

  if ((msg = build_pfcp_session_msg (sx, dmsg)))
    {
      upf_debug ("Msg: %p\n", msg);
      upf_pfcp_server_send_request (msg);
    }
}

static void
upf_pfcp_server_send_node_request (upf_node_assoc_t *n,
                                   pfcp_decoded_msg_t *dmsg)
{
  pfcp_msg_t *msg;

  if ((msg = build_pfcp_node_msg (n, dmsg)))
    {
      upf_debug ("Node Msg: %p\n", msg);
      upf_pfcp_server_send_request (msg);
    }
}

static void
response_expired (u32 id)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_msg_t *msg = pfcp_msg_pool_elt_at_index (psm, id);

  upf_debug ("Msg Seq No: %u, %p, idx %u\n", msg->seq_no, msg, id);
  upf_debug ("release...\n");

  mhash_unset (&psm->response_q, msg->request_key, NULL);
  pfcp_msg_pool_put (psm, msg);
}

static void
restart_response_timer (pfcp_msg_t *msg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  u32 id = pfcp_msg_get_index (psm, msg);

  upf_debug ("Msg Seq No: %u, idx %u\n", msg->seq_no, id);

  upf_pfcp_server_stop_msg_timer (msg);
  msg->timer =
    upf_pfcp_server_start_timer (PFCP_SERVER_RESPONSE, id, RESPONSE_TIMEOUT);
  msg->expires_at = psm->now + RESPONSE_TIMEOUT;
}

static void
enqueue_response (pfcp_msg_t *msg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  u32 id = pfcp_msg_get_index (psm, msg);

  upf_debug ("Msg Seq No: %u, idx %u\n", msg->seq_no, id);

  mhash_set (&psm->response_q, msg->request_key, id, NULL);
  msg->timer =
    upf_pfcp_server_start_timer (PFCP_SERVER_RESPONSE, id, RESPONSE_TIMEOUT);
  msg->expires_at = psm->now + RESPONSE_TIMEOUT;
}

static void
upf_pfcp_make_response (pfcp_msg_t *resp, pfcp_msg_t *req)
{
  resp->timer = ~0;
  resp->seq_no = req->seq_no;
  resp->session_handle = req->session_handle;
  resp->lcl = req->lcl;
  resp->rmt = req->rmt;
  resp->data = 0;
}

int
upf_pfcp_send_response (pfcp_msg_t *req, pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_msg_t *resp;
  int r;

  resp = pfcp_msg_pool_get (psm);
  upf_pfcp_make_response (resp, req);
  dmsg->seq_no = pfcp_msg_seq (req->data);

  if ((r = pfcp_encode_msg (dmsg, &resp->data)) != 0)
    {
      pfcp_msg_pool_put (psm, resp);
    }
  else
    {
      upf_pfcp_send_data (resp);
      enqueue_response (resp);
    }

  pfcp_free_dmsg_contents (dmsg);
  return r;
}

static int
urr_check_counter (u64 bytes, u64 consumed, u64 threshold, u64 quota)
{
  u32 r = 0;

  if (quota != 0 && consumed >= quota)
    r |= PFCP_USAGE_REPORT_TRIGGER_VOLUME_QUOTA;

  if (threshold != 0 && bytes > threshold)
    r |= PFCP_USAGE_REPORT_TRIGGER_VOLUME_THRESHOLD;

  return r;
}

void
upf_pfcp_session_up_deletion_report (upf_session_t *sx)
{
  /*
   * TS 29.244 clause 5.18.2: UP Function Initiated PFCP Session
   * Release FIXME: should include diagnostic information with
   * the reason for session termination
   */
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_decoded_msg_t dmsg = { .type = PFCP_MSG_SESSION_REPORT_REQUEST };
  pfcp_msg_session_report_request_t *req = &dmsg.session_report_request;
  struct rules *active;
  f64 now = psm->now;

  memset (req, 0, sizeof (*req));
  UPF_SET_BIT (req->grp.fields, SESSION_REPORT_REQUEST_REPORT_TYPE);

  active = pfcp_get_rules (sx, PFCP_ACTIVE);
  if (vec_len (active->urr) != 0)
    {
      upf_usage_report_t report;

      req->report_type = PFCP_REPORT_TYPE_USAR;

      UPF_SET_BIT (req->grp.fields, SESSION_REPORT_REQUEST_USAGE_REPORT);

      upf_usage_report_init (&report, vec_len (active->urr));
      upf_usage_report_set (
        &report, PFCP_USAGE_REPORT_TRIGGER_TERMINATION_BY_UP_FUNCTION_REPORT,
        now);
      upf_usage_report_build (sx, NULL, active->urr, now, &report,
                              &req->usage_report);
      upf_usage_report_free (&report);
    }
  else
    req->report_type = PFCP_REPORT_TYPE_UISR;

  UPF_SET_BIT (req->grp.fields, SESSION_REPORT_REQUEST_PFCPSRREQ_FLAGS);
  /* PSDBU = PFCP Session Deleted By the UP function */
  req->pfcpsrreq_flags = PFCP_PFCPSRREQ_PSDBU;

  upf_pfcp_server_send_session_request (sx, &dmsg);
  pfcp_free_dmsg_contents (&dmsg);
}

static void
upf_pfcp_session_usage_report (upf_session_t *sx, ip46_address_t *ue,
                               upf_event_urr_data_t *uev, f64 now)
{
  pfcp_decoded_msg_t dmsg = { .type = PFCP_MSG_SESSION_REPORT_REQUEST };
  pfcp_msg_session_report_request_t *req = &dmsg.session_report_request;
  upf_main_t *gtm = &upf_main;
  u32 si = sx - gtm->sessions;
  upf_event_urr_data_t *ev;
  upf_usage_report_t report;
  struct rules *active;
  upf_urr_t *urr;
  int send = 0;

  active = pfcp_get_rules (sx, PFCP_ACTIVE);

  upf_debug ("Active: %p (%d)\n", active, vec_len (active->urr));

  if (vec_len (active->urr) == 0)
    /* how could that happen? */
    return;

  memset (req, 0, sizeof (*req));
  UPF_SET_BIT (req->grp.fields, SESSION_REPORT_REQUEST_REPORT_TYPE);
  req->report_type = PFCP_REPORT_TYPE_USAR;

  UPF_SET_BIT (req->grp.fields, SESSION_REPORT_REQUEST_USAGE_REPORT);

  upf_usage_report_init (&report, vec_len (active->urr));

  vec_foreach (ev, uev)
    {
      urr = pfcp_get_urr_by_id (active, ev->urr_id);
      if (!urr)
        continue;

      if (ev->trigger & URR_START_OF_TRAFFIC)
        {
          upf_usage_report_trigger (&report, urr - active->urr,
                                    PFCP_USAGE_REPORT_TRIGGER_START_OF_TRAFFIC,
                                    urr->liusa_bitmap, now);
          send = 1;

          if (urr->traffic_timer.handle == ~0)
            {
              urr->traffic_timer.base = now;
              upf_pfcp_session_start_stop_urr_time (si, &urr->traffic_timer,
                                                    1);
            }
        }
    }

  vec_foreach (urr, active->urr)
    {
      u32 trigger = 0;

      upf_debug ("URR: %p\n", urr);
      if (urr->status & URR_REPORTED)
        /* skip already reported URR */
        continue;

#define urr_check(V, D)                                                       \
  urr_check_counter (V.measure.bytes.D, V.measure.consumed.D, V.threshold.D,  \
                     V.quota.D)

      trigger = urr_check (urr->volume, ul);
      trigger |= urr_check (urr->volume, dl);
      trigger |= urr_check (urr->volume, total);

#undef urr_check

      if (trigger != 0)
        {
          upf_usage_report_trigger (&report, urr - active->urr, trigger,
                                    urr->liusa_bitmap, now);
          urr->status |= URR_REPORTED;
          send = 1;
        }
    }

  if (send)
    {
      upf_usage_report_build (sx, ue, active->urr, now, &report,
                              &req->usage_report);
      upf_pfcp_server_send_session_request (sx, &dmsg);
    }

  pfcp_free_dmsg_contents (&dmsg);
  upf_usage_report_free (&report);
}

void
upf_pfcp_session_stop_up_inactivity_timer (urr_time_t *t)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  if (t->handle != ~0 && t->expected > vlib_time_now (psm->vlib_main))
    upf_pfcp_server_stop_generic_timer (t->handle);

  t->handle = ~0;
  t->expected = 0;
}

void
upf_pfcp_session_start_up_inactivity_timer (u32 si, f64 last, urr_time_t *t)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  i64 interval;
  f64 period;

  if (t->handle != ~0 || t->period == 0)
    return;

  // start timer.....

  period = t->period - trunc (vlib_time_now (psm->vlib_main) - last);
  t->expected = vlib_time_now (psm->vlib_main) + period;

  interval = psm->timer.ticks_per_second * period;
  interval = clib_max (interval, 1); /* make sure interval is at least 1 */
  t->handle = upf_pfcp_server_start_generic_timer (si, interval);

  upf_debug ("starting UP inactivity timer on sidx %u, handle 0x%08x: "
             "now is %.4f, expire in %lu ticks "
             " clib_now %.4f, current tick: %u",
             si, t->handle, psm->timer.last_run_time, interval,
             unix_time_now (), psm->timer.current_tick);
}

void
upf_pfcp_session_stop_urr_time (urr_time_t *t, const f64 now)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  if (t->handle != ~0 &&
      t->expected > now) // XXXX: t->expected == now possible? (unlikely...)
    {
      /* The timer wheel stop expired timers automatically. We don't map
       * expired timers to their urr_time_t structure, therefore the handle
       * might already be reused.
       * Only stop the timer if we are sure that it can not possibly have
       * expired yet.
       * Failing to stop a timer is not a problem. The timer will fire, but
       * the URR scan woun't find any expired URRs.
       */
      upf_pfcp_server_stop_generic_timer (t->handle);
    }

  t->handle = ~0;
  t->expected = 0;
}

void
upf_pfcp_session_start_stop_urr_time (u32 si, urr_time_t *t, u8 start_it)
{
  pfcp_server_main_t *psm = &pfcp_server_main;

  /* the timer interval must be based on tw->current_tick, so for calculating
   * that we need to use the now timestamp of that current_tick */
  const f64 now = psm->timer.last_run_time;

  if (t->handle != ~0)
    upf_pfcp_session_stop_urr_time (t, now);

  if (t->period != 0 && start_it)
    {
      i64 interval;

      // start timer.....

      t->expected = t->base + t->period;
      interval = psm->timer.ticks_per_second * (t->expected - now) + 1;
      interval = clib_max (interval, 1); /* make sure interval is at least 1 */
      t->handle = upf_pfcp_server_start_generic_timer (si, interval);

      upf_debug ("starting URR timer on sidx %u, handle 0x%08x: "
                 "now is %.4f, base is %.4f, expire in %lu ticks "
                 " @ %.4f (%U), clib_now %.4f, current tick: %u",
                 si, t->handle, now, t->base, interval, t->expected,
                 format_time_float, NULL, t->expected, unix_time_now (),
                 psm->timer.current_tick);
    }
}

static void
upf_pfcp_session_urr_timer (upf_session_t *sx, f64 now)
{
  pfcp_decoded_msg_t dmsg = { .type = PFCP_MSG_SESSION_REPORT_REQUEST };
  pfcp_msg_session_report_request_t *req = &dmsg.session_report_request;
  upf_main_t *gtm = &upf_main;
  u32 si = sx - gtm->sessions;
  upf_usage_report_t report;
  struct rules *active;
  u32 idx;

#if CLIB_DEBUG > 1
  f64 vnow = vlib_time_now (gtm->vlib_main);
#endif

  active = pfcp_get_rules (sx, PFCP_ACTIVE);

  upf_debug ("upf_pfcp_session_urr_timer (%p, 0x%016" PRIx64 " @ %u, %.4f)\n"
             "  UP Inactivity Timer: %u secs, inactive %12.4f secs (0x%08x)",
             sx, sx->up_seid, sx - gtm->sessions, now,
             active->inactivity_timer.period,
             vlib_time_now (gtm->vlib_main) - sx->last_ul_traffic,
             active->inactivity_timer.handle);

  memset (req, 0, sizeof (*req));
  UPF_SET_BIT (req->grp.fields, SESSION_REPORT_REQUEST_REPORT_TYPE);

  if (active->inactivity_timer.handle != ~0 &&
      active->inactivity_timer.period != 0)
    {
      if (ceil (vlib_time_now (gtm->vlib_main) - sx->last_ul_traffic) >=
          active->inactivity_timer.period)
        {
          active->inactivity_timer.handle = ~0;
          req->report_type |= PFCP_REPORT_TYPE_UPIR;
        }
      else
        {
          upf_pfcp_session_stop_up_inactivity_timer (
            &active->inactivity_timer);
          upf_pfcp_session_start_up_inactivity_timer (
            si, sx->last_ul_traffic, &active->inactivity_timer);
        }
    }

  upf_usage_report_init (&report, vec_len (active->urr));

  vec_foreach_index (idx, active->urr)
    {
      upf_urr_t *urr = vec_elt_at_index (active->urr, idx);
      f64 trigger_now = now;
      u32 trigger = 0;

#define urr_check(V, NOW)                                                     \
  (((V).base != 0) && ((V).period != 0) && ((V).expected != 0) &&             \
   (V).expected < (NOW))
#define urr_check_late(V, NOW)                                                \
  do                                                                          \
    {                                                                         \
      if ((V).expected < (NOW) -LATE_TIMER_WARNING_THRESHOLD)                 \
        {                                                                     \
          vlib_increment_simple_counter (                                     \
            &gtm->upf_simple_counters[UPF_TIMERS_MISSED],                     \
            vlib_get_thread_index (), 0, 1);                                  \
          clib_warning ("WARNING: timer late by %.4f seconds: " #V,           \
                        (NOW) - (V).expected);                                \
        }                                                                     \
    }                                                                         \
  while (0)

#define URR_COND_TIME(t, time) (t).period != 0 ? time : 0
#define URR_DEBUG_HEADER                                                      \
  "Rule       | base                                | period   | expire at  " \
  "             | in secs              | ticks     | handle     | check "     \
  "result\n"
#define URR_DEUBG_LINE                                                        \
  "%-10s | %U (%9.3f) | %8lu | %U | %9.3f, %9.3f | %9.3f | 0x%08x | %u\n"
#define URR_DEUBG_ABS_LINE "%-10s | %U | %12.4f | %U | %12.4f\n"
#define URR_DEBUG_VALUES(Label, t)                                            \
  (Label), format_time_float, NULL, (t).base,                                 \
    URR_COND_TIME (t, ((t).base - now)), (t).period, format_time_float, NULL, \
    (t).base + (f64) (t).period,                                              \
    URR_COND_TIME (t, (((t).base + (f64) (t).period) - now)),                 \
    URR_COND_TIME (t, ((t).expected - now)),                                  \
    URR_COND_TIME (t, ((t).expected - now) * TW_CLOCKS_PER_SECOND),           \
    (t).handle, urr_check (t, now)

#define URR_DEBUG_ABS_VALUES(Label, t)                                        \
  (Label), format_time_float, NULL, (t).unix_time, (t).unix_time - now,       \
    format_vlib_time, gtm->vlib_main, (t).vlib_time, (t).vlib_time - vnow

      upf_debug ("URR: %p, Id: %u", urr, urr->id);
      urr_debug_out (
        URR_DEBUG_HEADER URR_DEUBG_LINE URR_DEUBG_LINE URR_DEUBG_LINE
          URR_DEUBG_ABS_LINE,
        URR_DEBUG_VALUES ("Period", urr->measurement_period),
        URR_DEBUG_VALUES ("Threshold", urr->time_threshold),
        URR_DEBUG_VALUES ("Quota", urr->time_quota),
        URR_DEBUG_ABS_VALUES ("Monitoring", urr->monitoring_time));

      if (urr_check (urr->measurement_period, now))
        {
          urr_check_late (urr->measurement_period, now);
          if (urr->triggers & PFCP_REPORTING_TRIGGER_PERIODIC_REPORTING)
            {
              trigger |= PFCP_USAGE_REPORT_TRIGGER_PERIODIC_REPORTING;
              trigger_now =
                clib_min (trigger_now, urr->measurement_period.expected);
            }

          urr->measurement_period.base += urr->measurement_period.period;
          if ((urr->measurement_period.base + urr->measurement_period.period) <
              now)
            {
              clib_warning (
                "WARNING: URR %p, Measurement Period wrong, Session "
                "0x%016" PRIx64 ", URR: %u\n" URR_DEBUG_HEADER URR_DEUBG_LINE,
                urr, sx->up_seid, urr->id,
                URR_DEBUG_VALUES ("Period", urr->measurement_period));
#if CLIB_DEBUG > 0
              ASSERT ((urr->measurement_period.base +
                       urr->measurement_period.period) < now);
#endif
              while ((urr->measurement_period.base +
                      urr->measurement_period.period) < now)
                {
                  urr->measurement_period.base +=
                    urr->measurement_period.period;
                }
            }

          /* rearm Measurement Period */
          upf_pfcp_session_start_stop_urr_time (si, &urr->measurement_period,
                                                1);
        }
      if (urr_check (urr->time_threshold, now))
        {
          urr_check_late (urr->time_threshold, now);
          if (urr->triggers & PFCP_REPORTING_TRIGGER_TIME_THRESHOLD)
            {
              trigger |= PFCP_USAGE_REPORT_TRIGGER_TIME_THRESHOLD;
              trigger_now =
                clib_min (trigger_now, urr->time_threshold.expected);
            }

          upf_pfcp_session_stop_urr_time (&urr->time_threshold, now);
        }
      if (urr_check (urr->time_quota, now))
        {
          urr_check_late (urr->time_quota, now);
          if (urr->triggers & PFCP_REPORTING_TRIGGER_TIME_QUOTA)
            {
              trigger |= PFCP_USAGE_REPORT_TRIGGER_TIME_QUOTA;
              trigger_now = clib_min (trigger_now, urr->time_quota.expected);
            }

          upf_pfcp_session_stop_urr_time (&urr->time_quota, now);
          urr->time_quota.period = 0;
          urr->status |= URR_OVER_QUOTA;
        }
      if (urr_check (urr->quota_validity_time, now))
        {
          urr_check_late (urr->quota_validity_time, now);
          if (urr->triggers & PFCP_REPORTING_TRIGGER_QUOTA_VALIDITY_TIME)
            {
              trigger |= PFCP_USAGE_REPORT_TRIGGER_QUOTA_VALIDITY_TIME;
              trigger_now =
                clib_min (trigger_now, urr->quota_validity_time.expected);
            }

          upf_pfcp_session_stop_urr_time (&urr->quota_validity_time, now);
          urr->quota_validity_time.period = 0;
          urr->status |= URR_OVER_QUOTA;
        }

      if (urr_check (urr->traffic_timer, now))
        {
          upf_urr_traffic_t **expired = NULL;
          upf_urr_traffic_t *tt = NULL;

          urr_check_late (urr->traffic_timer, now);

          pool_foreach (tt, urr->traffic)
            {
              if (tt->first_seen + 60 < now)
                vec_add1 (expired, tt);
            };

          for (int i = 0; i < vec_len (expired); i++)
            {
              hash_unset_mem_free (&urr->traffic_by_ue, &expired[i]->ip);
              pool_put (urr->traffic, expired[i]);
            }
          vec_free (expired);

          if (pool_elts (urr->traffic) != 0)
            {
              urr->traffic_timer.base = now;
              upf_pfcp_session_start_stop_urr_time (si, &urr->traffic_timer,
                                                    1);
            }
        }

#undef urr_check

      if (trigger != 0)
        {
          req->report_type |= PFCP_REPORT_TYPE_USAR;
          UPF_SET_BIT (req->grp.fields, SESSION_REPORT_REQUEST_USAGE_REPORT);

          upf_usage_report_trigger (&report, idx, trigger, urr->liusa_bitmap,
                                    trigger_now);

          // clear reporting on the time based triggers, until rearmed by
          // update
          urr->triggers &= ~(PFCP_REPORTING_TRIGGER_TIME_THRESHOLD |
                             PFCP_REPORTING_TRIGGER_TIME_QUOTA |
                             PFCP_REPORTING_TRIGGER_QUOTA_VALIDITY_TIME);
        }
    }

  if (req->report_type != 0)
    {
      upf_usage_report_build (sx, NULL, active->urr, now, &report,
                              &req->usage_report);
      upf_pfcp_server_send_session_request (sx, &dmsg);
    }

  pfcp_free_dmsg_contents (&dmsg);
  upf_usage_report_free (&report);
}

#if CLIB_DEBUG > 10

static void
upf_validate_session_timer (upf_session_t *sx)
{
  f64 now = unix_time_now ();
  struct rules *r;
  upf_urr_t *urr;
  int error = 0;

#define urr_check(V, NOW) (~0 != (V).handle)

  r = pfcp_get_rules (sx, PFCP_PENDING);
  vec_foreach (urr, r->urr)
    {
      if (!urr_check (urr->measurement_period, now) &&
          !(urr->monitoring_time.vlib_time != INFINITY) &&
          !urr_check (urr->time_threshold, now) &&
          !urr_check (urr->time_quota, now))
        continue;

      error++;
      clib_warning ("WARNING: Pending URR %p with active timer handler, "
                    "Session 0x%016" PRIx64
                    ", URR: %u\n" URR_DEBUG_HEADER URR_DEUBG_LINE
                      URR_DEUBG_LINE URR_DEUBG_LINE URR_DEUBG_ABS_LINE,
                    urr, sx->up_seid, urr->id,
                    URR_DEBUG_VALUES ("Period", urr->measurement_period),
                    URR_DEBUG_VALUES ("Threshold", urr->time_threshold),
                    URR_DEBUG_VALUES ("Quota", urr->time_quota));
    URR_DEBUG_ABS_VALUES ("Monitoring", urr->monitoring_time));
    }
#undef urr_check

#define urr_check(V, NOW) (((V).handle != ~0) && (V).expected < ((NOW) -1))

  r = pfcp_get_rules (sx, PFCP_ACTIVE);
  vec_foreach (urr, r->urr)
    {
      if (!urr_check (urr->measurement_period, now) &&
          !urr_check (urr->monitoring_time, now) &&
          !urr_check (urr->time_threshold, now) &&
          !urr_check (urr->time_quota, now))
        continue;

      error++;
      clib_warning (
        "WARNING: Active URR %p with expired timer, Session 0x%016" PRIx64
        ", URR: %u\n" URR_DEBUG_HEADER URR_DEUBG_LINE URR_DEUBG_LINE
          URR_DEUBG_LINE URR_DEUBG_ABS_LINE,
        urr, sx->up_seid, urr->id,
        URR_DEBUG_VALUES ("Period", urr->measurement_period),
        URR_DEBUG_VALUES ("Threshold", urr->time_threshold),
        URR_DEBUG_VALUES ("Quota", urr->time_quota),
        URR_DEBUG_ABS_VALUES ("Monitoring", urr->monitoring_time));
    }
#undef urr_check

  ASSERT (error == 0);
}

static void
upf_validate_session_timers ()
{
  upf_main_t *gtm = &upf_main;
  upf_session_t *sx = NULL;

  pool_foreach (sx, gtm->sessions)
    {
      upf_validate_session_timer (sx);
    }
}

#endif

void
upf_pfcp_server_stop_msg_timer (pfcp_msg_t *msg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  u32 id_resp, *exp_id, id_t1;

  if (msg->timer == ~0)
    return;

  id_t1 = ((0x80 | PFCP_SERVER_T1) << 24) | msg->seq_no;
  id_resp =
    ((0x80 | PFCP_SERVER_RESPONSE) << 24) | pfcp_msg_get_index (psm, msg);

  /*
   * Prevent timer handlers from being invoked in case the expiration
   * has already been registered for the current iteration of
   * pfcp_process() loop
   */
  vec_foreach (exp_id, psm->expired)
    {
      if (*exp_id == id_t1 || *exp_id == id_resp)
        {
          msg->timer = ~0;
          *exp_id = ~0;
        }
    }

  /*
   * Don't call tw_timer_stop() on expired timer handles as they're invalid
   * Ref: https://www.mail-archive.com/vpp-dev@lists.fd.io/msg10495.html
   */
  if (msg->timer != ~0)
    upf_pfcp_server_stop_generic_timer (msg->timer);
  msg->timer = ~0;
}

void
upf_pfcp_server_stop_heartbeat_timer (upf_node_assoc_t *n)
{
  if (n->heartbeat_handle != ~0)
    {
      upf_pfcp_server_stop_generic_timer (n->heartbeat_handle);
      n->heartbeat_handle = ~0;
    }
}

u32
upf_pfcp_server_start_timer (u8 type, u32 id, u32 seconds)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  i64 interval = seconds * psm->timer.ticks_per_second;

  ASSERT (type < 8);
  ASSERT ((id & 0xff000000) == 0);

  return upf_pfcp_server_start_generic_timer (((0x80 | type) << 24) | id,
                                              interval);
}

void
upf_pfcp_server_deferred_free_msgs_by_node (u32 node)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  hash_set (psm->free_msgs_by_node, node, 1);
}

void
upf_server_handle_hb_timer (u32 node_idx)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_decoded_msg_t dmsg = { .type = PFCP_MSG_HEARTBEAT_REQUEST };
  pfcp_msg_heartbeat_request_t *req = &dmsg.heartbeat_request;
  upf_main_t *gtm = &upf_main;
  upf_node_assoc_t *n;

  n = pool_elt_at_index (gtm->nodes, node_idx);

  /*
   * The timer has expired, we shouldn't try to stop it when
   * releasing the association
   */
  n->heartbeat_handle = ~0;

  memset (req, 0, sizeof (*req));
  UPF_SET_BIT (req->grp.fields, HEARTBEAT_REQUEST_RECOVERY_TIME_STAMP);
  req->recovery_time_stamp = psm->start_time;

  upf_pfcp_server_send_node_request (n, &dmsg);
}

static int
timer_id_cmp (void *a1, void *a2)
{
  u32 *n1 = a1;
  u32 *n2 = a2;

  if (*n1 < *n2)
    return -1;
  else if (*n1 == *n2)
    return 0;
  else
    return 1;
}

static uword
pfcp_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  uword event_type, *event_data = 0;
  upf_main_t *gtm = &upf_main;
  u32 last_expired;
  pfcp_msg_t *msg;

  pfcp_msg_pool_init (psm);
  psm->now = unix_time_now ();
  psm->timer.last_run_time = floor (psm->now);

  while (1)
    {
      u32 ticks_until_expiration;
      f64 timeout;

      ticks_until_expiration =
        TW (tw_timer_first_expires_in_ticks) (&psm->timer);
      /* min 1 tick wait */
      ticks_until_expiration = clib_max (ticks_until_expiration, 1);
      /* sleep max 1s */
      ticks_until_expiration =
        clib_min (ticks_until_expiration, TW_CLOCKS_PER_SECOND);

      timeout = (f64) ticks_until_expiration * TW_SECS_PER_CLOCK;

      (void) vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, &event_data);

      pfcp_msg_pool_loop_start (psm);
      psm->now = unix_time_now ();

      /* run the timing wheel first, to that the internal base for new and
       * updated timers is set to now */
      upf_pfcp_server_expire_timers ();

      switch (event_type)
        {
        case ~0: /* timeout */
          // upf_debug ("timeout....");
          break;

        case EVENT_RX:
          {
            for (int i = 0; i < vec_len (event_data); i++)
              {
                pfcp_msg_t *msg = (pfcp_msg_t *) event_data[i];

                upf_pfcp_server_rx_msg (msg);

                vec_free (msg->data);
                clib_mem_free (msg);
              }
            break;
          }

        case EVENT_TX:
          {
            for (int i = 0; i < vec_len (event_data); i++)
              {
                pfcp_msg_t *tx = (pfcp_msg_t *) event_data[i];
                // Handle case when session was removed before
                // receiving this event
                if (!pool_is_free_index (gtm->nodes, tx->node) &&
                    !pool_is_free_index (gtm->sessions, tx->session.idx) &&
                    pool_elt_at_index (gtm->sessions, tx->session.idx)
                        ->up_seid == tx->up_seid)
                  {
                    pfcp_msg_t *msg;

                    msg = pfcp_msg_pool_add (psm, tx);
                    upf_pfcp_server_send_request (msg);
                  }
                else
                  {
                    upf_debug ("ignored tx event because session deleted");
                    vec_free (tx->data);
                  }

                clib_mem_free (tx);
              }
            break;
          }

        case EVENT_URR:
          {
            for (int i = 0; i < vec_len (event_data); i++)
              {
                upf_event_urr_data_t *uev =
                  (upf_event_urr_data_t *) event_data[i];
                /* TBD: re-verify! */
                upf_event_urr_hdr_t *ueh =
                  (upf_event_urr_hdr_t *) vec_header (uev);
                upf_session_t *sx = 0;

                /*
                 * The session could have been freed or replaced after
                 * this even has been queued, but before it has been
                 * handled. So we check if the pool entry is free, and
                 * also verify that UP-SEID in the session matches
                 * UP-SEID in the event.
                 */
                if (!pool_is_free_index (gtm->sessions, ueh->session_idx))
                  sx = pool_elt_at_index (gtm->sessions, ueh->session_idx);

                if (!sx || sx->up_seid != ueh->up_seid)
                  goto next_ev_urr;

                if (!(ueh->status & URR_DROP_SESSION))
                  {
                    upf_debug ("URR Event on Session Idx: %wd, %p, UE: %U, "
                               "Events: %u\n",
                               ueh->session_idx, sx, format_ip46_address,
                               &ueh->ue, IP46_TYPE_ANY, vec_len (uev));
                    upf_pfcp_session_usage_report (sx, &ueh->ue, uev,
                                                   psm->now);
                  }
                else
                  {
                    /*
                     * The session has a fatal reporting issue such as
                     * multiple Monitoring Time splits being queued
                     */
                    upf_debug ("URR Event on Session Idx: DROP: %wd, %p\n",
                               ueh->session_idx, sx);
                    upf_pfcp_session_up_deletion_report (sx);
                    pfcp_disable_session (sx);
                    pfcp_free_session (sx);
                  }

              next_ev_urr:
                vec_free (uev);
              }
            break;
          }

        default:
          upf_debug ("event %ld, %p. ", event_type, event_data[0]);
          break;
        }

      vec_sort_with_function (psm->expired, timer_id_cmp);
      last_expired = ~0;

      for (int i = 0; i < vec_len (psm->expired); i++)
        {
          /*
           * Check if the timer has been stopped while handling other
           * timers in this iteration of the upf_process() loop
           */
          if (psm->expired[i] == ~0)
            continue;

          switch (psm->expired[i] >> 24)
            {
            case 0 ... 0x7f:
              if (last_expired == psm->expired[i])
                continue;
              last_expired = psm->expired[i];

              {
                const u32 si = psm->expired[i] & 0x7FFFFFFF;
                upf_session_t *sx;

                if (pool_is_free_index (gtm->sessions, si))
                  continue;

                sx = pool_elt_at_index (gtm->sessions, si);
                upf_pfcp_session_urr_timer (sx, psm->now);
              }
              break;

            case 0x80 | PFCP_SERVER_HB_TIMER:
              /*
               * It is important that the heartbeat timer handler runs
               * before the T1 timer below, which is ensured by the
               * value of PFCP_SERVER_HB_TIMER and PFCP_SERVER_T1
               * constants, and also by sorting the expired timers
               * above. This way, if the association is released due
               * to a T1 timeout, no attempt is made to stop the
               * expired heartbeat timer.
               * upf_server_handle_hb_timer() clears the expired
               * heartbeat timer handle.
               */
              upf_debug ("PFCP Server Heartbeat Timeout: %u",
                         psm->expired[i] & 0x00FFFFFF);
              upf_server_handle_hb_timer (psm->expired[i] & 0x00FFFFFF);
              break;

            case 0x80 | PFCP_SERVER_T1:
              upf_debug ("PFCP Server T1 Timeout: %u",
                         psm->expired[i] & 0x00FFFFFF);
              request_t1_expired (psm->expired[i] & 0x00FFFFFF);
              break;

            case 0x80 | PFCP_SERVER_RESPONSE:
              upf_debug ("PFCP Server Response Timeout: %u",
                         psm->expired[i] & 0x00FFFFFF);
              response_expired (psm->expired[i] & 0x00FFFFFF);
              break;

            default:
              upf_debug ("timeout for unknown id: %u", psm->expired[i] >> 24);
              break;
            }
        }

      /* Free messages that must be freed after the loop */
      pool_foreach (msg, psm->msg_pool)
        {
          if (!msg->flags.is_valid_pool_item)
            continue;

          ASSERT (msg->expires_at);

          /* TODO: replace this workaround with proper msg removal inplace */
          if (!hash_get (psm->free_msgs_by_node, msg->node))
            {
              /*
               * This should not happen unless a timer didn't fire for some
               * reason
               */
              if (psm->now > msg->expires_at + 1)
                clib_warning (
                  "Deleting expired message from %U:%d to %U:%d, seq_no %d, "
                  "expired %f seconds ago",
                  format_ip46_address, &msg->lcl.address, IP46_TYPE_ANY,
                  clib_net_to_host_u16 (msg->lcl.port), format_ip46_address,
                  &msg->rmt.address, IP46_TYPE_ANY,
                  clib_net_to_host_u16 (msg->rmt.port), msg->seq_no,
                  psm->now - msg->expires_at);
              else
                continue;
            }

          hash_unset (psm->request_q, msg->seq_no);
          mhash_unset (&psm->response_q, msg->request_key, NULL);
          upf_pfcp_server_stop_msg_timer (msg);
          pfcp_msg_pool_put (psm, msg);
        }

      vec_reset_length (psm->expired);
      vec_reset_length (event_data);
      hash_free (psm->free_msgs_by_node);

#if CLIB_DEBUG > 10
      upf_validate_session_timers ();
#endif
    }

  return (0);
}

void
upf_pfcp_server_session_usage_report (upf_event_urr_data_t *uev)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  vlib_main_t *vm = psm->vlib_main;

  vlib_process_signal_event_mt (vm, pfcp_api_process_node.index, EVENT_URR,
                                (uword) uev);
}

/*********************************************************/

clib_error_t *
pfcp_server_main_init (vlib_main_t *vm)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, vnet_interface_cli_init)))
    return error;

  psm->vlib_main = vm;
  psm->start_time = time (NULL);
  mhash_init (&psm->response_q, sizeof (uword), sizeof (u64) * 4);

  TW (tw_timer_wheel_init)
  (&psm->timer, NULL, TW_SECS_PER_CLOCK /* 10ms timer interval */, ~0);

  upf_debug ("PFCP: start_time: %p, %d, %x.", psm, psm->start_time,
             psm->start_time);

  psm->hb_cfg.retries = PFCP_DEFAULT_REQUEST_RETRIES;
  psm->hb_cfg.timeout = PFCP_DEFAULT_REQUEST_INTERVAL;

  psm->next_expired_timer = ~0;

  return 0;
}

/* clang-format off */
VLIB_REGISTER_NODE (pfcp_api_process_node) = {
    .function = pfcp_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .process_log2_n_stack_bytes = 16,
    .runtime_data_bytes = sizeof (void *),
    .name = "pfcp-api",
};

/* clang-format on */
