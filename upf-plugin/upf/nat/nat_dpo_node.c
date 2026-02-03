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

#include <inttypes.h>
#include <vppinfra/error.h>
#include <vnet/vnet.h>

#include "upf/core/upf_buffer_opaque.h"
#include "upf/nat/nat.h"
#include "upf/nat/nat_private.h"
#include "upf/flow/flowtable.h"
#include "upf/upf_stats.h"
#include "upf/utils/ip_helpers.h"

#define UPF_DEBUG_ENABLE 0

#include "upf/nat/nat_node_inlines.h"

#define foreach_upf_nat_dpo_error                                             \
  _ (NO_ERROR, "no error")                                                    \
  _ (UNKNOWN_FLOW, "unknown flow")                                            \
  _ (UNKNOWN_ICMP_FLOW, "unknown ICMP flow")                                  \
  _ (UNSUPPORTED_IP_PROTO, "unsupported IP protocol")                         \
  _ (UNSUPPORTED_ICMP_TYPE, "unsupported ICMP type")                          \
  _ (HANDOFF, "handoff to other worker")

static char *upf_nat_dpo_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_nat_dpo_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_NAT_DPO_ERROR_##sym,
  foreach_upf_nat_dpo_error
#undef _
    UPF_NAT_DPO_N_ERROR,
} upf_nat_dpo_error_t;

typedef enum
{
  UPF_NAT_DPO_NEXT_DROP,
  UPF_NAT_DPO_NEXT_NETCAP,
  UPF_NAT_DPO_NEXT_FLOW_PROCESS,
  UPF_NAT_DPO_NEXT_HANDOFF,
  UPF_NAT_DPO_N_NEXT,
} upf_nat_dpo_next_t;

typedef struct
{
  u32 nat_pool_id;
  u32 binding_id;
  upf_nat_dpo_next_t next;
  u32 binding_session_id;
  u8 packet_data[64];
} upf_nat_dpo_trace_t;

static u8 *
_format_upf_nat_dpo_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_nat_dpo_trace_t *t = va_arg (*args, upf_nat_dpo_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "nat_pool=%d next=%d\n%U", t->nat_pool_id, t->next,
              format_white_space, indent);

  if (is_valid_id (t->binding_id))
    {
      s = format (s, "upf_session=%d binding=%d\n%U", t->binding_session_id,
                  t->binding_id, format_white_space, indent);
    }
  else
    {
      s = format (s, "no binding information\n%U", format_white_space, indent);
    }

  s = format (s, "%U", format_ip_header, t->packet_data,
              sizeof (t->packet_data));
  return s;
}

always_inline upf_nat_binding_t *
_nat_o2i_handle_icmp_echo (upf_nat_wk_t *unw, u16 thread_index, u32 now,
                           ip4_header_t *ip0, icmp46_header_t *icmp0,
                           u32 nat_pool_id, upf_dir_op_t dir_op,
                           ip_csum_t *icmp_error_csum, u16 *p_handoff_thread)
{
  upf_nat_main_t *unm = &upf_nat_main;
  u32 nat_flow_id;
  u16 lookup_thread_id;
  if (!_nat_icmp_echo_lookup (unw, thread_index, ip0, icmp0, nat_pool_id,
                              false, dir_op, &nat_flow_id, &lookup_thread_id))
    return NULL;

  if (lookup_thread_id != thread_index)
    {
      *p_handoff_thread = lookup_thread_id;
      return NULL;
    }

  upf_nat_icmp_flow_t *nif = pool_elt_at_index (unw->icmp_flows, nat_flow_id);

  upf_nat_binding_t *binding =
    upf_worker_pool_elt_at_index (unm->bindings, nif->binding_id);

  _nat_icmp_echo_refresh (unw, binding, nif, now);

  _nat_icmp_echo_rewrite (ip0, icmp0, nif->in_addr,
                          clib_host_to_net_u16 (nif->og_identifier),
                          UPF_EL_UL_DST ^ dir_op, icmp_error_csum);

  return binding;
}

always_inline upf_nat_binding_t *
_nat_o2i_handle_tcpudp (upf_nat_wk_t *unw, u32 thread_index, ip4_header_t *ip0,
                        void *l4_hdr0, u32 nat_pool_id, upf_dir_op_t dir_op,
                        ip_csum_t *icmp_error_csum, u16 *p_handoff_thread)
{
  upf_nat_main_t *unm = &upf_nat_main;
  u32 nat_flow_id;
  u16 lookup_thread_id;
  if (!_nat_tcpudp_lookup_o2i (unw, ip0, l4_hdr0, nat_pool_id, dir_op,
                               &nat_flow_id, &lookup_thread_id))
    return NULL;

  if (lookup_thread_id != thread_index)
    {
      *p_handoff_thread = lookup_thread_id;
      return NULL;
    }

  upf_nat_flow_t *nf = pool_elt_at_index (unw->flows, nat_flow_id);

  flow_entry_t *flow =
    flowtable_get_flow_by_id (thread_index, nf->upf_flow_id);
  ASSERT (flow->nat_flow_id == nat_flow_id);

  _nat_tcpudp_rewrite (ip0, l4_hdr0, flow->ip[UPF_EL_UL_SRC].ip4,
                       clib_host_to_net_u16 (flow->port[UPF_EL_UL_SRC]),
                       UPF_EL_UL_DST ^ dir_op, icmp_error_csum);

  return upf_worker_pool_elt_at_index (unm->bindings, nf->binding_id);
}

always_inline void
_nat_icmp_error_rewrite_o2i (ip4_header_t *ip0, icmp46_header_t *icmp0,
                             ip4_address_t new_addr0,
                             ip_csum_t icmp_error_csum)
{
  ip4_address_t old_addr0 = ip0->dst_address;
  ip0->dst_address = new_addr0;

  ip_csum_t sum_ip = ip0->checksum;
  sum_ip = ip_csum_update (sum_ip, old_addr0.as_u32, new_addr0.as_u32,
                           ip4_header_t, dst_address /* changed member */);
  ip0->checksum = ip_csum_fold (sum_ip);

  icmp0->checksum = ip_csum_fold (icmp_error_csum);
}

VLIB_NODE_FN (upf_nat_ip4_dpo_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_nat_main_t *unm = &upf_nat_main;

  u16 thread_index = vm->thread_index;
  upf_nat_wk_t *unw = vec_elt_at_index (unm->workers, thread_index);
  u32 vlib_now = (u32) vlib_time_now (vm);

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          upf_nat_dpo_error_t error;
          upf_nat_dpo_next_t next;

          bi = from[0];
          to_next[0] = bi;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b = vlib_get_buffer (vm, bi);

          index_t nat_pool_id = vnet_buffer (b)->ip.adj_index[VLIB_TX];

          ip4_header_t *ip0 = vlib_buffer_get_current (b);

          upf_vnet_buffer_l3l4_hdr_offset_current_ip (b, true);

          void *l4_hdr0 = b->data + vnet_buffer (b)->l4_hdr_offset;

          u32 b_len = vlib_buffer_length_in_chain (vm, b);

          u16 handoff_thread_id = ~0;

          upf_debug ("IP hdr before rewrite: %U", format_ip4_header, ip0,
                     b->current_length);

          upf_nat_binding_t *binding;

          if (PREDICT_TRUE (ip0->protocol == IP_PROTOCOL_TCP ||
                            ip0->protocol == IP_PROTOCOL_UDP))
            {
              binding = _nat_o2i_handle_tcpudp (
                unw, thread_index, ip0, l4_hdr0, nat_pool_id, UPF_DIR_OP_SAME,
                NULL, &handoff_thread_id);
              if (binding == NULL)
                {
                  if (is_valid_id (handoff_thread_id))
                    goto do_handoff;

                  upf_debug ("binding not found");
                  error = UPF_NAT_DPO_ERROR_UNKNOWN_FLOW;
                  next = UPF_NAT_DPO_NEXT_DROP;
                  goto trace;
                }
            }
          else if (ip0->protocol == IP_PROTOCOL_ICMP)
            {
              icmp46_header_t *icmp0 = l4_hdr0;
              if (icmp0->type == ICMP4_echo_reply)
                {
                  binding = _nat_o2i_handle_icmp_echo (
                    unw, thread_index, vlib_now, ip0, icmp0, nat_pool_id,
                    UPF_DIR_OP_SAME, NULL, &handoff_thread_id);
                  if (binding == NULL)
                    {
                      if (is_valid_id (handoff_thread_id))
                        goto do_handoff;

                      upf_debug ("ICMP echo reply binding not found");
                      error = UPF_NAT_DPO_ERROR_UNKNOWN_ICMP_FLOW;
                      next = UPF_NAT_DPO_NEXT_DROP;
                      goto trace;
                    }
                }
              else if (icmp_type_is_error_message (icmp0->type))
                {
                  nat_icmp_echo_header_t *err_icmp_echo =
                    (nat_icmp_echo_header_t *) (icmp0 + 1);
                  ip4_header_t *err_ip0 = (ip4_header_t *) (err_icmp_echo + 1);
                  void *err_l4_hdr0 = ip4_next_header (err_ip0);

                  ip_csum_t icmp_error_csum = icmp0->checksum;

                  if (err_ip0->protocol == IP_PROTOCOL_ICMP)
                    {
                      /* o2i ICMP error containing original i2o ICMP haders */
                      icmp46_header_t *err_icmp0 = err_l4_hdr0;
                      if (err_icmp0->type != ICMP4_echo_request)
                        {
                          upf_debug ("ICMP error msg: inside ICMP type is not "
                                     "echo request");
                          error = UPF_NAT_DPO_ERROR_UNSUPPORTED_ICMP_TYPE;
                          next = UPF_NAT_DPO_NEXT_DROP;
                          goto trace;
                        }

                      binding = _nat_o2i_handle_icmp_echo (
                        unw, thread_index, vlib_now, err_ip0, err_icmp0,
                        nat_pool_id, UPF_DIR_OP_FLIP, &icmp_error_csum,
                        &handoff_thread_id);
                      if (binding == NULL)
                        {
                          if (is_valid_id (handoff_thread_id))
                            goto do_handoff;

                          upf_debug (
                            "ICMP error msg: inside ICMP echo request "
                            "binding not found");
                          error = UPF_NAT_DPO_ERROR_UNKNOWN_ICMP_FLOW;
                          next = UPF_NAT_DPO_NEXT_DROP;
                          goto trace;
                        }
                    }
                  else if (err_ip0->protocol == IP_PROTOCOL_TCP ||
                           err_ip0->protocol == IP_PROTOCOL_UDP)
                    {
                      /* o2i ICMP error containing i2o TCPUDP haders */
                      binding = _nat_o2i_handle_tcpudp (
                        unw, thread_index, err_ip0, err_l4_hdr0, nat_pool_id,
                        UPF_DIR_OP_FLIP, &icmp_error_csum, &handoff_thread_id);
                      if (binding == NULL)
                        {
                          if (is_valid_id (handoff_thread_id))
                            goto do_handoff;

                          upf_debug (
                            "ICMP error msg: inside binding not found");
                          error = UPF_NAT_DPO_ERROR_UNKNOWN_FLOW;
                          next = UPF_NAT_DPO_NEXT_DROP;
                          goto trace;
                        }
                    }
                  else
                    {
                      upf_debug (
                        "ICMP error msg: inside IP protocol unsupported");
                      error = UPF_NAT_DPO_ERROR_UNSUPPORTED_IP_PROTO;
                      next = UPF_NAT_DPO_NEXT_DROP;
                      goto trace;
                    }

                  _nat_icmp_error_rewrite_o2i (
                    ip0, icmp0, err_ip0->src_address, icmp_error_csum);
                }
              else
                {
                  upf_debug ("ICMP type unsupported");
                  error = UPF_NAT_DPO_ERROR_UNSUPPORTED_ICMP_TYPE;
                  next = UPF_NAT_DPO_NEXT_DROP;
                  goto trace;
                }
            }
          else
            {
              upf_debug ("IP protocol unsupported");
              error = UPF_NAT_DPO_ERROR_UNSUPPORTED_IP_PROTO;
              next = UPF_NAT_DPO_NEXT_DROP;
              goto trace;
            }

          upf_debug ("IP hdr after  rewrite: %U", format_ip4_header, ip0,
                     b->current_length);

          vlib_increment_combined_counter (&upf_stats_main.wk.nat_pool_out2in,
                                           thread_index, nat_pool_id, 1,
                                           b_len);

          UPF_ENTER_SUBGRAPH (b, binding->session_id, UPF_PACKET_SOURCE_NAT, 0,
                              true, false);

          if (PREDICT_FALSE (binding->want_netcap))
            next = UPF_NAT_DPO_NEXT_NETCAP;
          else
            next = UPF_NAT_DPO_NEXT_FLOW_PROCESS;
          goto trace_no_error;

        do_handoff:
          upf_buffer_opaque (b)->handoff.thread_id = handoff_thread_id;
          next = UPF_NAT_DPO_NEXT_HANDOFF;
          error = UPF_NAT_DPO_ERROR_HANDOFF;
          goto trace;

        trace:
          b->error = node->errors[error];

        trace_no_error:
          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_nat_dpo_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));
              tr->nat_pool_id = nat_pool_id;
              tr->binding_id = binding ? (binding - unm->bindings) : ~0;
              tr->next = next;
              tr->binding_session_id = binding ? binding->session_id : ~0;
              clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
                           sizeof (tr->packet_data));
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi, next);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (upf_nat_ip4_dpo_node) = {
  .name = "upf-ip4-nat-dpo",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_nat_dpo_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(upf_nat_dpo_error_strings),
  .error_strings = upf_nat_dpo_error_strings,

  .n_next_nodes = UPF_NAT_DPO_N_NEXT,
  .next_nodes = {
    [UPF_NAT_DPO_NEXT_DROP]         = "error-drop",
    [UPF_NAT_DPO_NEXT_NETCAP]       = "upf-netcap4",
    [UPF_NAT_DPO_NEXT_FLOW_PROCESS] = "upf-ip4-flow-process",
    [UPF_NAT_DPO_NEXT_HANDOFF]      = "upf-ip4-nat-dpo-handoff",
  },
};

#include "upf/utils/upf_handoff_template.h"

VLIB_NODE_FN (upf_nat_ip4_dpo_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  upf_nat_main_t *unm = &upf_nat_main;

  return upf_handoff_template_node (vm, node, from_frame,
                                    unm->fq_nat_dpo_handoff_index);
}

VLIB_REGISTER_NODE (upf_nat_ip4_dpo_handoff_node) =
  UPF_HANDOFF_TEMPLATE_NODE_REGISTRATION ("upf-ip4-nat-dpo-handoff");
