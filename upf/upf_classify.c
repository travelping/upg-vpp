/*
 * Copyright (c) 2020 Travelping GmbH
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

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>
#include <upf/upf_app_db.h>
#include <upf/upf_pfcp.h>
#include <upf/upf_proxy.h>
#include <upf/upf_app_dpo.h>
#include <upf/upf_ipfix.h>

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)                                                        \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

/* Statistics (not all errors) */
#define foreach_upf_classify_error _ (CLASSIFY, "good packets classify")

static char *upf_classify_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_classify_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_CLASSIFY_ERROR_##sym,
  foreach_upf_classify_error
#undef _
    UPF_CLASSIFY_N_ERROR,
} upf_classify_error_t;

typedef enum
{
  UPF_CLASSIFY_NEXT_DROP,
  UPF_CLASSIFY_NEXT_PROCESS,
  UPF_CLASSIFY_NEXT_FORWARD,
  UPF_CLASSIFY_NEXT_PROXY,
  UPF_CLASSIFY_N_NEXT,
} upf_classify_next_t;

static upf_classify_next_t upf_classify_flow_next[] = {
  [FT_NEXT_DROP] = UPF_CLASSIFY_NEXT_DROP,
  [FT_NEXT_CLASSIFY] = UPF_CLASSIFY_NEXT_DROP,
  [FT_NEXT_PROCESS] = UPF_CLASSIFY_NEXT_PROCESS,
  [FT_NEXT_PROXY] = UPF_CLASSIFY_NEXT_PROXY,
};

typedef struct
{
  u32 session_index;
  u64 up_seid;
  u32 pdr_idx;
  u32 next_index;
  u8 packet_data[64 - 1 * sizeof (u32)];
} upf_classify_trace_t;

static u8 *
format_upf_classify_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_classify_trace_t *t = va_arg (*args, upf_classify_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (
    s, "upf_session%d up-seid 0x%016" PRIx64 " pdr %d, next_index = %d\n%U%U",
    t->session_index, t->up_seid, t->pdr_idx, t->next_index,
    format_white_space, indent, format_ip4_header, t->packet_data,
    sizeof (t->packet_data));
  return s;
}

// return true if matches
always_inline bool
ip46_address_is_equal_masked (const ip46_address_t *a, const ip46_address_t *b,
                              const ip46_address_t *mask, bool is_ip4)
{
  if (is_ip4)
    {
      u32 umask = mask->ip4.as_u32;
      u32 a_masked = a->ip4.as_u32 & umask;
      u32 b_masked = b->ip4.as_u32 & umask;
      return a_masked == b_masked;
    }
  else
    {
      u64 umask[2], a_masked[2], b_masked[2];
      umask[0] = mask->ip6.as_u64[0];
      umask[1] = mask->ip6.as_u64[1];
      a_masked[0] = a->ip6.as_u64[0] & umask[0];
      a_masked[1] = a->ip6.as_u64[1] & umask[1];
      b_masked[0] = b->ip6.as_u64[0] & umask[0];
      b_masked[1] = b->ip6.as_u64[1] & umask[1];
      return a_masked[0] == b_masked[0] && a_masked[1] == b_masked[1];
    }
}

always_inline bool
acl_ip46_is_equal_masked (const ip46_address_t *ip, upf_acl_t *acl, int field,
                          bool is_ip4)
{
  return ip46_address_is_equal_masked (ip, &acl->match.address[field],
                                       &acl->mask.address[field], is_ip4);
}

always_inline int
acl_port_in_range (const u16 port, upf_acl_t *acl, int field)
{
  return (port >= acl->mask.port[field] && port <= acl->match.port[field]);
}

always_inline int
upf_acl_classify_one (vlib_main_t *vm, u32 teid, flow_entry_t *flow,
                      flow_direction_t direction, u8 is_ip4, upf_acl_t *acl,
                      struct rules *active)
{
  u32 pf_len = is_ip4 ? 32 : 64;

  if (!!is_ip4 != !!acl->is_ip4)
    return 0;

  if (acl->match_teid)
    {
      upf_debug ("match  TEID: %08x, Match %u, ACL %08x\n", teid,
                 acl->match_teid, acl->teid);

      if (teid != acl->teid)
        return 0;
    }

  switch (acl->match_ue_ip)
    {
    case UPF_ACL_UL:
      upf_debug ("match  UL: UE %U, Src: %U\n", format_ip46_address,
                 &acl->ue_ip, IP46_TYPE_ANY, format_ip46_address,
                 &flow->key.ip[FTK_EL_SRC ^ direction], IP46_TYPE_ANY);
      if (!ip46_address_is_equal_masked (
            &acl->ue_ip, &flow->key.ip[FTK_EL_SRC ^ direction],
            (ip46_address_t *) &ip6_main.fib_masks[pf_len], is_ip4))
        return 0;
      break;
    case UPF_ACL_DL:
      upf_debug ("match  DL: UE %U, Dst: %U\n", format_ip46_address,
                 &acl->ue_ip, IP46_TYPE_ANY, format_ip46_address,
                 &flow->key.ip[FTK_EL_DST ^ direction], IP46_TYPE_ANY);
      if (!ip46_address_is_equal_masked (
            &acl->ue_ip, &flow->key.ip[FTK_EL_DST ^ direction],
            (ip46_address_t *) &ip6_main.fib_masks[pf_len], is_ip4))
        return 0;
      break;
    default:
      break;
    }

  if (acl->match_ip_app)
    {
      upf_pdr_t *pdr;

      /* FIXME: should be able to handle PDRs w/o UE IP */
      if (!acl->match_ue_ip)
        return 0;

      pdr = vec_elt_at_index (active->pdr, acl->pdr_idx);
      upf_debug ("match APP: IP app db_id %d", pdr->pdi.adr.db_id);
      if (!upf_app_ip_rule_match (pdr->pdi.adr.db_id, flow, &acl->ue_ip))
        return 0;
    }

  upf_debug ("match Proto: 0x%04x/0x%04x, 0x%04x\n", acl->match.protocol,
             acl->mask.protocol, flow->key.proto);

  if ((flow->key.proto & acl->mask.protocol) !=
      (acl->match.protocol & acl->mask.protocol))
    return 0;

  if (!acl_ip46_is_equal_masked (&flow->key.ip[FTK_EL_SRC ^ direction], acl,
                                 UPF_ACL_FIELD_SRC, is_ip4) ||
      !acl_ip46_is_equal_masked (&flow->key.ip[FTK_EL_DST ^ direction], acl,
                                 UPF_ACL_FIELD_DST, is_ip4))
    return 0;

  if (!acl_port_in_range (
        clib_net_to_host_u16 (flow->key.port[FTK_EL_SRC ^ direction]), acl,
        UPF_ACL_FIELD_SRC) ||
      !acl_port_in_range (
        clib_net_to_host_u16 (flow->key.port[FTK_EL_DST ^ direction]), acl,
        UPF_ACL_FIELD_DST))
    return 0;

  return 1;
}

always_inline u32
upf_acl_classify_forward (vlib_main_t *vm, u32 teid, flow_entry_t *flow,
                          struct rules *active, u8 is_ip4, u32 *pdr_idx)
{
  u32 next = UPF_CLASSIFY_NEXT_DROP;
  upf_acl_t *acl, *acl_vec;

  /*
   * If the proxy was used before session modification,
   * we must either continue using it or drop the traffic
   * for this flow
   */
  u8 reclassifying_proxy_flow = flow->is_l3_proxy;

  if (pdr_idx)
    *pdr_idx = ~0;
  if (teid != 0)
    {
      flow_side (flow, FT_INITIATOR)->teid = teid;
    }
  else
    {
      teid = flow_side (flow, FT_INITIATOR)->teid;
    }

  if (flow->key.proto == IP_PROTOCOL_TCP && active->proxy_pdr_idx != ~0)
    {
      /* bypass flow classification if we decided to proxy */
      flow->is_l3_proxy = 1;
      flow_side (flow, FT_INITIATOR)->next = FT_NEXT_PROXY;
      flow_side (flow, FT_RESPONDER)->next = FT_NEXT_CLASSIFY;
      next = UPF_CLASSIFY_NEXT_PROXY;
    }
  else
    {
      /* no matching ACL and not pending ADF */
      flow->is_l3_proxy = 0;
      flow_side (flow, FT_INITIATOR)->next = FT_NEXT_DROP;
      flow_side (flow, FT_RESPONDER)->next = FT_NEXT_DROP;
      next = UPF_CLASSIFY_NEXT_DROP;
    }

  acl_vec = is_ip4 ? active->v4_acls : active->v6_acls;
  upf_debug ("TEID %08x, ACLs %p (%u)\n", teid, acl_vec, vec_len (acl_vec));

  /* find ACL with the highest precedence that matches this flow */
  vec_foreach (acl, acl_vec)
    {
      upf_debug ("%d forward acl pdr %d", acl - acl_vec, acl->pdr_idx);
      if (upf_acl_classify_one (vm, teid, flow, FT_INITIATOR, is_ip4, acl,
                                active))
        {
          upf_pdr_t *pdr;

          pdr = vec_elt_at_index (active->pdr, acl->pdr_idx);
          flow_side (flow, FT_INITIATOR)->pdr_id = pdr->id;

          /* FIXME: the following needs more testing for the reclassify case */
          if (!flow->is_l3_proxy ||
              acl->precedence <= active->proxy_precedence)
            {
              upf_far_t *far;

              if (pdr_idx)
                *pdr_idx = acl->pdr_idx;

              far = pfcp_get_far_by_id (active, pdr->far_id);

              if (flow->key.proto == IP_PROTOCOL_TCP && far &&
                  far->forward.flags & FAR_F_REDIRECT_INFORMATION)
                {
                  flow->is_l3_proxy = 1;
                  flow->is_redirect = 1;
                  flow_side (flow, FT_INITIATOR)->next = FT_NEXT_PROXY;
                  flow_side (flow, FT_RESPONDER)->next = FT_NEXT_CLASSIFY;
                  flow_side (flow, FT_RESPONDER)->pdr_id = pdr->id;
                  next = UPF_CLASSIFY_NEXT_PROXY;
                }
              else if (reclassifying_proxy_flow)
                {
                  /* can't undo proxying that was already there */
                  flow->is_l3_proxy = 1;
                  flow_side (flow, FT_INITIATOR)->next = FT_NEXT_PROXY;
                  flow_side (flow, FT_RESPONDER)->next = FT_NEXT_CLASSIFY;
                  next = UPF_CLASSIFY_NEXT_PROXY;
                }
              else
                {
                  flow->is_l3_proxy = 0;
                  flow_side (flow, FT_INITIATOR)->next = FT_NEXT_PROCESS;
                  flow_side (flow, FT_RESPONDER)->next = FT_NEXT_CLASSIFY;
                  next = UPF_CLASSIFY_NEXT_PROCESS;
                }

              if (pdr->pdi.fields & F_PDI_APPLICATION_ID)
                flow->application_id = pdr->pdi.adr.application_id;
            }

          upf_debug ("match PDR: %u, Proxy: %d, Redirect: %d\n", acl->pdr_idx,
                     flow->is_l3_proxy, flow->is_redirect);
          break;
        }
    }

  return next;
}

/* Classify traffic from the proxy towards the UE */
always_inline u32
upf_acl_classify_proxied (vlib_main_t *vm, u32 teid, flow_entry_t *flow,
                          struct rules *active, u8 is_ip4, u32 *pdr_idx)
{
  u32 next = UPF_CLASSIFY_NEXT_DROP;
  upf_acl_t *acl, *acl_vec;

  if (teid)
    flow_side (flow, FT_RESPONDER)->teid = teid;
  else
    teid = flow_side (flow, FT_RESPONDER)->teid;

  acl_vec = is_ip4 ? active->v4_acls : active->v6_acls;
  upf_debug ("TEID %08x, ACLs %p (%u)\n", teid, acl_vec, vec_len (acl_vec));

  /* find ACL with the highest precedence that matches this flow */
  vec_foreach (acl, acl_vec)
    {
      upf_debug ("%d proxied acl pdr %d", acl - acl_vec, acl->pdr_idx);
      if (upf_acl_classify_one (vm, teid, flow, FT_RESPONDER, is_ip4, acl,
                                active))
        {
          upf_pdr_t *pdr;
          pdr = vec_elt_at_index (active->pdr, acl->pdr_idx);

          if (pdr_idx)
            *pdr_idx = acl->pdr_idx;
          next = UPF_CLASSIFY_NEXT_FORWARD;

          if (flow_side (flow, FT_RESPONDER)->pdr_id == ~0)
            {
              /* load the best matching ACL into the flow */
              flow_side (flow, FT_RESPONDER)->pdr_id = pdr->id;
            }

          if (pdr->pdi.fields & F_PDI_APPLICATION_ID)
            flow->application_id = pdr->pdi.adr.application_id;

          upf_debug ("match PDR: %u, Proxy: %d, Redirect: %d\n", acl->pdr_idx,
                     flow->is_l3_proxy, flow->is_redirect);
          break;
        }
    }

  return next;
}

always_inline u32
upf_acl_classify_return (vlib_main_t *vm, u32 teid, flow_entry_t *flow,
                         struct rules *active, u8 is_ip4, u32 *pdr_idx)
{
  u32 next = UPF_CLASSIFY_NEXT_DROP;
  upf_acl_t *acl, *acl_vec;

  if (teid)
    flow_side (flow, FT_RESPONDER)->teid = teid;
  else
    teid = flow_side (flow, FT_RESPONDER)->teid;

  acl_vec = is_ip4 ? active->v4_acls : active->v6_acls;
  upf_debug ("TEID %08x, ACLs %p (%u)\n", teid, acl_vec, vec_len (acl_vec));

  /* find ACL with the highest precedence that matches this flow */
  vec_foreach (acl, acl_vec)
    {
      upf_debug ("%d return acl pdr %d", acl - acl_vec, acl->pdr_idx);
      if (upf_acl_classify_one (vm, teid, flow, FT_RESPONDER, is_ip4, acl,
                                active))
        {
          upf_pdr_t *pdr;

          pdr = vec_elt_at_index (active->pdr, acl->pdr_idx);

          if (pdr_idx)
            *pdr_idx = acl->pdr_idx;
          flow_side (flow, FT_RESPONDER)->pdr_id = pdr->id;

          if (flow->is_l3_proxy)
            {
              flow_side (flow, FT_RESPONDER)->next = FT_NEXT_PROXY;
              next = UPF_CLASSIFY_NEXT_PROXY;
            }
          else
            {
              flow_side (flow, FT_RESPONDER)->next = FT_NEXT_PROCESS;
              next = UPF_CLASSIFY_NEXT_PROCESS;
            }

          if (pdr->pdi.fields & F_PDI_APPLICATION_ID)
            flow->application_id = pdr->pdi.adr.application_id;

          upf_debug ("match PDR: %u, Proxy: %d, Redirect: %d\n", acl->pdr_idx,
                     flow->is_l3_proxy, flow->is_redirect);
          break;
        }
    }

  return next;
}

always_inline uword
upf_classify_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
                 vlib_frame_t *from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *gtm = &upf_main;
  vnet_main_t *vnm = gtm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  flowtable_main_t *fm = &flowtable_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 thread_index = vlib_get_thread_index ();
  u32 next = 0;
  upf_session_t *sess = NULL;
  struct rules *active;
  u32 sidx = 0;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      flow_entry_t *flow;
      flow_direction_t direction;
      u32 bi;
      u8 reclassify_proxy_flow;
      adr_result_t ar;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          bi = from[0];
          to_next[0] = bi;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b = vlib_get_buffer (vm, bi);
          UPF_CHECK_INNER_NODE (b);

          /* Get next node index and adj index from tunnel next_dpo */
          sidx = upf_buffer_opaque (b)->gtpu.session_index;
          sess = pool_elt_at_index (gtm->sessions, sidx);
          active = pfcp_get_rules (sess, PFCP_ACTIVE);

          next = UPF_CLASSIFY_NEXT_PROCESS;

          upf_debug ("flow: %p (%u): %U\n",
                     fm->flows + upf_buffer_opaque (b)->gtpu.flow_id,
                     upf_buffer_opaque (b)->gtpu.flow_id, format_flow_key,
                     &(fm->flows + upf_buffer_opaque (b)->gtpu.flow_id)->key);
          flow =
            pool_elt_at_index (fm->flows, upf_buffer_opaque (b)->gtpu.flow_id);

          direction = upf_buffer_opaque (b)->gtpu.direction;
          /*
           * In case of a proxy flow surviving session modification,
           * we need to classify both ends of the flow to re-run the
           * app detection just once
           */
          reclassify_proxy_flow = flow->is_l3_proxy;
          upf_debug (
            "pkt_direction %s, dir %s\n",
            upf_buffer_opaque (b)->gtpu.pkt_key_direction == FT_FORWARD ?
              "FT_FORWARD" :
              "FT_REVERSE",
            direction == FT_INITIATOR ? "FT_INITIATOR" : "FT_RESPONDER");

          if (flow_side (flow, direction)->next != FT_NEXT_CLASSIFY)
            {
              /* we shouldn't be here, this can happend when multiple
               * packets from the same connection are in the pipeline,
               * the first packet changes the flow next state, but the
               * following packets have already been queue to us.
               * push then to their intended node
               */

              /* need to reload pdr_idx, as the flow entry was not ready at
               * that time */
              upf_buffer_opaque (b)->gtpu.pdr_idx =
                flow_pdr_idx (flow, direction, active);
              next = upf_classify_flow_next[flow_side (flow, direction)->next];
            }
          else if (direction == FT_INITIATOR)
            {
              next = upf_acl_classify_forward (
                vm, upf_buffer_opaque (b)->gtpu.teid, flow, active, is_ip4,
                &upf_buffer_opaque (b)->gtpu.pdr_idx);
              if (reclassify_proxy_flow) /* for app detection */
                {
                  if (upf_buffer_opaque (b)->gtpu.is_proxied)
                    upf_acl_classify_proxied (vm, 0, flow, active, is_ip4, 0);
                  else
                    upf_acl_classify_return (vm, 0, flow, active, is_ip4, 0);
                }
            }
          else
            {
              if (reclassify_proxy_flow) /* for app detection */
                upf_acl_classify_forward (vm, 0, flow, active, is_ip4, 0);
              if (upf_buffer_opaque (b)->gtpu.is_proxied)
                next = upf_acl_classify_proxied (
                  vm, upf_buffer_opaque (b)->gtpu.teid, flow, active, is_ip4,
                  &upf_buffer_opaque (b)->gtpu.pdr_idx);
              else
                next = upf_acl_classify_return (
                  vm, upf_buffer_opaque (b)->gtpu.teid, flow, active, is_ip4,
                  &upf_buffer_opaque (b)->gtpu.pdr_idx);
            }

          if (flow->app_detection_done)
            {
              /* try to reclassify the app based on the saved URI, if any */
              upf_debug ("re-run app detection (reverse)");
              ar = upf_application_detection (vm, 0, flow, active);
              ASSERT (ar == ADR_OK);
              upf_buffer_opaque (b)->gtpu.pdr_idx =
                flow_pdr_idx (flow, direction, active);
            }

          upf_debug ("Next: %u", next);
          ASSERT (flow_side (flow, FT_INITIATOR)->next != FT_NEXT_PROXY ||
                  flow_side (flow, FT_INITIATOR)->pdr_id != ~0);
          ASSERT (flow_side (flow, FT_RESPONDER)->next != FT_NEXT_PROXY ||
                  flow_side (flow, FT_RESPONDER)->pdr_id != ~0);

          upf_debug ("flow: %p (%u): %U\n",
                     fm->flows + upf_buffer_opaque (b)->gtpu.flow_id,
                     upf_buffer_opaque (b)->gtpu.flow_id, format_flow_key,
                     &(fm->flows + upf_buffer_opaque (b)->gtpu.flow_id)->key);

          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_classify_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));
              tr->session_index = sidx;
              tr->up_seid = sess->up_seid;
              tr->pdr_idx = upf_buffer_opaque (b)->gtpu.pdr_idx;
              tr->next_index = next;
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

VLIB_NODE_FN (upf_ip4_classify_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_classify_fn (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_classify_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_classify_fn (vm, node, from_frame, /* is_ip4 */ 0);
}

/* clang-format off */
VLIB_REGISTER_NODE (upf_ip4_classify_node) = {
  .name = "upf-ip4-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_classify_error_strings),
  .error_strings = upf_classify_error_strings,
  .n_next_nodes = UPF_CLASSIFY_N_NEXT,
  .next_nodes = {
    [UPF_CLASSIFY_NEXT_DROP]    = "error-drop",
    [UPF_CLASSIFY_NEXT_PROCESS] = "upf-ip4-input",
    [UPF_CLASSIFY_NEXT_FORWARD] = "upf-ip4-forward",
    [UPF_CLASSIFY_NEXT_PROXY]   = "upf-ip4-proxy-input",
  },
};
/* clang-format on */

/* clang-format off */
VLIB_REGISTER_NODE (upf_ip6_classify_node) = {
  .name = "upf-ip6-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_classify_error_strings),
  .error_strings = upf_classify_error_strings,
  .n_next_nodes = UPF_CLASSIFY_N_NEXT,
  .next_nodes = {
    [UPF_CLASSIFY_NEXT_DROP]    = "error-drop",
    [UPF_CLASSIFY_NEXT_PROCESS] = "upf-ip6-input",
    [UPF_CLASSIFY_NEXT_FORWARD] = "upf-ip6-forward",
    [UPF_CLASSIFY_NEXT_PROXY]   = "upf-ip6-proxy-input",
  },
};
