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

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>

#include "upf/upf.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/rules/upf_gtpu_proto.h"
#include "upf/utils/upf_mt.h"
#include "upf/core/upf_buffer_opaque.h"

#define UPF_DEBUG_ENABLE 0

/* Statistics (not all errors) */
#define foreach_upf_gtpu_error_indication_error                               \
  _ (RECEIVED, "received") /* just to reserve 0 for conditional */            \
  _ (HANDOFF, "handoff to other worker")                                      \
  _ (NO_SUCH_TUNNEL, "no such tunnel packets")                                \
  _ (DECODE_FAIL, "decode failed")                                            \
  _ (OLD_SESSION, "previously removed session")

static char *upf_gtpu_error_indication_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_gtpu_error_indication_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_GTPU_ERROR_INDICATION_ERROR_##sym,
  foreach_upf_gtpu_error_indication_error
#undef _
    UPF_GTPU_ERROR_INDICATION_N_ERROR,
} gtpu_error_ind_error_t;

typedef enum
{
  UPF_GTPU_ERROR_INDICATION_NEXT_DROP,
  UPF_GTPU_ERROR_INDICATION_NEXT_HANDOFF,
  UPF_GTPU_ERROR_INDICATION_N_NEXT,
} gtpu_error_ind_next_t;

typedef struct
{
  u32 session_index;
  upf2_session_report_error_indication_t indication;
  gtpu_error_ind_error_t error;
  gtpu_error_ind_next_t next;
} gtpu_error_ind_trace_t;

static u8 *
format_gtpu_error_ind_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpu_error_ind_trace_t *t = va_arg (*args, gtpu_error_ind_trace_t *);

  if (is_valid_id (t->session_index))
    {
      s = format (s,
                  "GTPU Error Indication from ip=%U, for upf_session=%d "
                  "teid=0x%08x error %d",
                  format_ip46_address, &t->indication.addr, IP46_TYPE_ANY,
                  t->session_index, t->indication.teid, t->error);
    }
  else
    {
      s = format (
        s, "GTPU decap error - session for ip=%U teid=0x%08x does not exist",
        format_ip46_address, &t->indication.addr, IP46_TYPE_ANY,
        t->indication.teid);
    }
  return s;
}

static void
decode_error_indication_ext_hdr (vlib_buffer_t *b, u8 next_ext_type,
                                 upf2_session_report_error_indication_t *error)
{
  u8 *start, *end, *p;

  start = p = vlib_buffer_get_current (b);
  end = vlib_buffer_get_tail (b);

  while (next_ext_type != 0 && p < end)
    {
      u16 length = (*p++ * 4) - 2;

      if (end - p < length)
        break;

      switch (next_ext_type)
        {
        case 0x40: /* UDP Port number */
          if (length < 2)
            break;

          error->port = clib_net_to_host_unaligned_mem_u16 ((u16 *) p);
          break;

        default:
          break;
        }
      p += length;
      next_ext_type = *p++;
    }

  vlib_buffer_advance (b, p - start);
  return;
}

static int
decode_error_indication (vlib_buffer_t *b,
                         upf2_session_report_error_indication_t *error)
{
  u8 *p = vlib_buffer_get_current (b);
  u8 *end = vlib_buffer_get_tail (b);
  u8 flag = 0;
  u16 length;
  while (p < end)
    {
      upf_debug ("IE: %d", *p);
      switch (*p++)
        {
        case 14: /* Recovery */
          upf_debug ("IE: Recovery");
          p++;
          break;

        case 16: /* Tunnel Endpoint Identifier Data I */
          upf_debug ("IE: TEID I, %d", end - p);
          if ((flag & 1) | (end - p < 4))
            return -1;
          flag |= 1;
          error->teid = clib_net_to_host_u32 (*(u32 *) p);
          upf_debug ("IE: TEID I, 0x%08x", error->teid);
          p += 4;
          break;

        case 133: /* GTP-U Peer Address */
          upf_debug ("IE: Peer, %d", end - p);
          if ((flag & 2) | (end - p < 2))
            return -1;
          flag |= 2;
          length = clib_net_to_host_u16 (*(u16 *) p);
          upf_debug ("IE: Peer Length, %d, %d", length, end - p);
          p += 2;
          if ((end - p) < length)
            return -1;
          if (length != 4 && length != 16)
            return -1;
          error->addr = to_ip46 (length == 16, p);
          upf_debug ("IE: Peer %U", format_ip46_address, &error->addr,
                     IP46_TYPE_ANY);
          p += length;
          break;

        default:
          return -1;
        }
    }

  if (flag != 3)
    return -1;

  return 0;
}

VLIB_NODE_FN (upf_gtpu_error_ind_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;

  u16 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u16 next = 0;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi = from[0];
          to_next[0] = bi;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          u32 error0 = UPF_GTPU_ERROR_INDICATION_ERROR_RECEIVED;
          next = UPF_GTPU_ERROR_INDICATION_NEXT_DROP;

          vlib_buffer_t *b = vlib_get_buffer (vm, bi);
          UPF_CHECK_INNER_NODE (b);
          vlib_buffer_reset (b);
          vlib_buffer_advance (b, vnet_buffer (b)->l4_hdr_offset);
          gtpu_header_t *gtpu = vlib_buffer_get_current (b);

          upf_debug ("P: %U", format_hex_bytes, gtpu, 16);
          upf_debug ("%p, TEID: %u, Flags: %02x, Ext: %u", gtpu, gtpu->h.teid,
                     gtpu->h.ver_flags & GTPU_E_S_PN_BIT, gtpu->next_ext_type);

          upf2_session_report_error_indication_t sr_error_ind = {};

          if (PREDICT_FALSE ((gtpu->h.ver_flags & GTPU_E_S_PN_BIT) != 0))
            {
              /* Pop gtpu header */
              vlib_buffer_advance (b, sizeof (gtpu_header_t));

              if ((gtpu->h.ver_flags & GTPU_E_BIT) != 0)
                decode_error_indication_ext_hdr (b, gtpu->next_ext_type,
                                                 &sr_error_ind);
            }
          else
            {
              /* Pop gtpu header */
              vlib_buffer_advance (b, sizeof (gtpu_header_tpdu_t));
            }

          if (decode_error_indication (b, &sr_error_ind) != 0)
            {
              error0 = UPF_GTPU_ERROR_INDICATION_ERROR_DECODE_FAIL;
              goto trace;
            }

          u16 session_thread = ~0;
          u16 session_generation;
          u32 session_id = ~0;
          u8 session_f_teid_lid0;
          bool is_active;

          // TODO: This is INCORRECT
          // We should do REVERSE lookup in FAR endpoints and remote peers,
          // instead of this. For now keep it like this, since this is old UPF
          // behavior and it is not trivial to implement such reverse lookup

          if (ip46_address_is_ip4 (&sr_error_ind.addr))
            {
              if (PREDICT_FALSE (!upf_gtpu_tunnel4_lookup (
                    sr_error_ind.teid, sr_error_ind.addr.ip4, &session_id,
                    &session_generation, &session_thread, &session_f_teid_lid0,
                    &is_active)))
                {
                  error0 = UPF_GTPU_ERROR_INDICATION_ERROR_NO_SUCH_TUNNEL;
                  goto trace;
                }
            }
          else
            {
              if (PREDICT_FALSE (!upf_gtpu_tunnel6_lookup (
                    sr_error_ind.teid, sr_error_ind.addr.ip6, &session_id,
                    &session_generation, &session_thread, &session_f_teid_lid0,
                    &is_active)))
                {
                  error0 = UPF_GTPU_ERROR_INDICATION_ERROR_NO_SUCH_TUNNEL;
                  goto trace;
                }
            }

          if (session_thread != thread_index)
            {
              upf_buffer_opaque (b)->handoff.thread_id = session_thread;
              error0 = UPF_GTPU_ERROR_INDICATION_ERROR_HANDOFF;
              next = UPF_GTPU_ERROR_INDICATION_NEXT_HANDOFF;
              goto trace_no_error;
            }

          upf_dp_session_t *dsx =
            upf_wk_get_dp_session (thread_index, session_id);

          if (dsx->session_generation != session_generation)
            {
              error0 = UPF_GTPU_ERROR_INDICATION_ERROR_OLD_SESSION;
              next = UPF_GTPU_ERROR_INDICATION_NEXT_DROP;
              goto trace;
            }

          // TODO: Do rate limiting for error indication

          upf_mt_event_t ev = {
            .kind = UPF_MT_EVENT_W2M_SESSION_REPORT,
            .w2m_session_report =
              (upf_mt_session_report_t){
                .session_id = session_id,
                .up_seid = dsx->up_seid,
                .report.type = PFCP_REPORT_TYPE_ERIR,
                .report.error_indication = sr_error_ind,
              },
          };

          upf_mt_enqueue_to_main (thread_index, &ev, 1);

        trace:
          b->error = node->errors[error0];

        trace_no_error:
          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              gtpu_error_ind_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));
              tr->session_index = session_id;
              tr->indication = sr_error_ind;
              tr->error = error0;
              tr->next = next;
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi, next);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (upf_gtpu_error_ind_node) = {
  .name = "upf-gtp-error-indication",
  .vector_size = sizeof (u32),

  .n_errors = UPF_GTPU_ERROR_INDICATION_N_ERROR,
  .error_strings = upf_gtpu_error_indication_error_strings,

  .n_next_nodes = UPF_GTPU_ERROR_INDICATION_N_NEXT,
  .next_nodes = {
    [UPF_GTPU_ERROR_INDICATION_NEXT_DROP] = "error-drop",
    [UPF_GTPU_ERROR_INDICATION_NEXT_HANDOFF] =  "upf-gtp-error-indication-hoff",
  },

  .format_trace = format_gtpu_error_ind_trace,
};

#include "upf/utils/upf_handoff_template.h"

VLIB_NODE_FN (upf_gtpu_error_ind_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  return upf_handoff_template_node (vm, node, from_frame,
                                    ugm->fq_gtpu_err_ind_handoff_index);
}

VLIB_REGISTER_NODE (upf_gtpu_error_ind_handoff_node) =
  UPF_HANDOFF_TEMPLATE_NODE_REGISTRATION ("upf-gtp-error-indication-hoff");
