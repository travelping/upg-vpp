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
#include <vnet/vnet.h>

#include "upf/upf.h"
#include "upf/upf_stats.h"
#include "upf/flow/flowtable.h"
#include "upf/nat/nat.h"
#include "upf/nat/nat_private.h"
#include "upf/utils/ip_helpers.h"
#include "upf/core/upf_buffer_opaque.h"

#define UPF_DEBUG_ENABLE 0

#include "upf/nat/nat_node_inlines.h"

/* Statistics (not all errors) */
#define foreach_upf_nat_forward_error                                         \
  _ (UNSUPPORTED_IP_PROTO, "unsupported IP protocol")                         \
  _ (UNSUPPORTED_ICMP_TYPE, "unsupported ICMP type")                          \
  _ (ICMP_LIMIT_PER_BINDING, "ICPM flows limit per binding")                  \
  _ (ICMP_OUT_OF_PORTS, "ICMP out of ports")

static char *upf_nat_forward_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_nat_forward_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_NAT_FORWARD_ERROR_##sym,
  foreach_upf_nat_forward_error
#undef _
    UPF_NAT_FORWARD_N_ERROR,
} upf_nat_forward_error_t;

typedef enum
{
  UPF_NAT_FORWARD_NEXT_DROP,
  UPF_NAT_FORWARD_NEXT_IP_LOOKUP,
  UPF_NAT_FORWARD_N_NEXT,
} upf_nat_forward_next_t;

typedef struct
{
  u64 up_seid;
  u32 session_id;
  u32 nat_binding_id;
  u32 nat_pool_id;
  u32 nwif_id;
  u8 packet_data[64];
} upf_nat_forward_trace_t;

static u8 *
_format_upf_nat_forward_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_nat_forward_trace_t *t = va_arg (*args, upf_nat_forward_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session=%d seid=0x%016" PRIx64 "\n%U", t->session_id,
              t->up_seid, format_white_space, indent);
  s = format (s, "nat_pool=%d nat_binding=%d nwif_id=%d\n%U", t->nat_pool_id,
              t->nat_binding_id, t->nwif_id, format_white_space, indent);
  s = format (s, "%U", format_ip_header, t->packet_data,
              sizeof (t->packet_data));
  return s;
}

VLIB_NODE_FN (upf_ip4_nat_forward_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *um = &upf_main;
  upf_nat_main_t *unm = &upf_nat_main;
  flowtable_main_t *fm = &flowtable_main;

  u16 thread_index = vm->thread_index;
  upf_nat_wk_t *unw = vec_elt_at_index (unm->workers, thread_index);
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, thread_index);
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
          bi = from[0];
          to_next[0] = bi;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          u32 error = 0;
          u32 next = UPF_NAT_FORWARD_NEXT_DROP;

          b = vlib_get_buffer (vm, bi);
          UPF_CHECK_INNER_NODE (b);

          u32 session_id = upf_buffer_opaque (b)->gtpu.session_id;

          upf_dp_session_t *dsx =
            upf_wk_get_dp_session (thread_index, session_id);

          upf_rules_t *rules = upf_wk_get_rules (thread_index, dsx->rules_id);

          upf_nat_binding_t *binding = upf_worker_pool_elt_at_index (
            unm->bindings, rules->nat_binding_id);

          ip4_header_t *ip0 = vlib_buffer_get_current (b);
          void *l4_hdr0 = ip4_next_header (ip0);
          u32 b_len = vlib_buffer_length_in_chain (vm, b);

          upf_debug ("IP hdr before rewrite: %U", format_ip4_header, ip0,
                     b->current_length);

          upf_nat_pool_t *nat_pool =
            pool_elt_at_index (unm->nat_pools, binding->nat_pool_id);

          if (ip0->protocol == IP_PROTOCOL_ICMP)
            {
              icmp46_header_t *icmp0 = l4_hdr0;
              if (icmp0->type != ICMP4_echo_request)
                {
                  error = UPF_NAT_FORWARD_ERROR_UNSUPPORTED_ICMP_TYPE;
                  next = UPF_NAT_FORWARD_NEXT_DROP;
                  goto error_trace;
                }

              u32 nat_icmp_flow_id;
              u16 lookup_thread_id;
              upf_nat_icmp_flow_t *nif;
              if (_nat_icmp_echo_lookup (
                    unw, thread_index, ip0, icmp0, binding->nat_pool_id, true,
                    UPF_DIR_OP_SAME, &nat_icmp_flow_id, &lookup_thread_id))
                {
                  // UPF already processes this packet on proper thread for
                  // this nat binding
                  ASSERT (lookup_thread_id == thread_index);

                  nif = pool_elt_at_index (unw->icmp_flows, nat_icmp_flow_id);
                  _nat_icmp_echo_refresh (unw, binding, nif, vlib_now);
                }
              else
                {
                  upf_nat_icmp_flow_create_error_t cerr;
                  nat_icmp_flow_id = upf_nat_icmp_flow_create (
                    thread_index, rules->nat_binding_id, ip0, icmp0, vlib_now,
                    &cerr);
                  if (!is_valid_id (nat_icmp_flow_id))
                    {
                      if (cerr ==
                          UPF_NAT_ICMP_FLOW_CREATE_ERROR_LIMIT_PER_BINDING)
                        error = UPF_NAT_FORWARD_ERROR_ICMP_LIMIT_PER_BINDING;
                      else if (cerr ==
                               UPF_NAT_ICMP_FLOW_CREATE_ERROR_OUT_OF_PORTS)
                        error = UPF_NAT_FORWARD_ERROR_ICMP_OUT_OF_PORTS;
                      else
                        ASSERT (0 && "Invalid cerr value");

                      next = UPF_NAT_FORWARD_NEXT_DROP;
                      goto error_trace;
                    }

                  nif = pool_elt_at_index (unw->icmp_flows, nat_icmp_flow_id);
                }

              ASSERT (nif->binding_id == rules->nat_binding_id);

              _nat_icmp_echo_rewrite (
                ip0, icmp0, nif->nat_addr,
                clib_host_to_net_u16 (nif->nat_identifier), UPF_EL_UL_SRC,
                NULL);
            }
          else if (ip0->protocol == IP_PROTOCOL_UDP ||
                   ip0->protocol == IP_PROTOCOL_TCP)
            {
              ASSERT (is_valid_id (upf_buffer_opaque (b)->gtpu.flow_id));

              flow_entry_t *flow = pool_elt_at_index (
                fwk->flows, upf_buffer_opaque (b)->gtpu.flow_id);

              ASSERT (is_valid_id (flow->nat_flow_id));

              upf_nat_flow_t *nf =
                pool_elt_at_index (unw->flows, flow->nat_flow_id);

              ASSERT (nf->binding_id == rules->nat_binding_id);

              _nat_tcpudp_rewrite (ip0, l4_hdr0, binding->external_addr,
                                   clib_host_to_net_u16 (nf->nat_port),
                                   UPF_EL_UL_SRC, NULL);
            }
          else
            {
              error = UPF_NAT_FORWARD_ERROR_UNSUPPORTED_IP_PROTO;
              next = UPF_NAT_FORWARD_NEXT_DROP;
              goto error_trace;
            }

          upf_debug ("IP hdr after  rewrite: %U", format_ip4_header, ip0,
                     b->current_length);

          vlib_increment_combined_counter (&upf_stats_main.wk.nat_pool_in2out,
                                           thread_index, binding->nat_pool_id,
                                           1, b_len);

          upf_interface_t *nwif =
            pool_elt_at_index (um->nwi_interfaces, nat_pool->nwif_id);

          vnet_buffer (b)->sw_if_index[VLIB_TX] =
            nwif->tx_fib_index[FIB_PROTOCOL_IP4];

          next = UPF_NAT_FORWARD_NEXT_IP_LOOKUP;
          goto trace;

        error_trace:
          b->error = node->errors[error];

        trace:
          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_nat_forward_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));
              tr->up_seid = dsx->up_seid;
              tr->session_id = session_id;
              tr->nat_binding_id = binding - unm->bindings;
              tr->nat_pool_id = binding->nat_pool_id;
              tr->nwif_id = nat_pool->nwif_id;
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

VLIB_REGISTER_NODE (upf_ip4_nat_forward_node) = {
  .name = "upf-ip4-nat-forward",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_nat_forward_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_nat_forward_error_strings),
  .error_strings = upf_nat_forward_error_strings,
  .n_next_nodes = UPF_NAT_FORWARD_N_NEXT,
  .next_nodes = {
    [UPF_NAT_FORWARD_NEXT_DROP]          = "error-drop",
    [UPF_NAT_FORWARD_NEXT_IP_LOOKUP]     = "ip4-lookup",
  },
};
