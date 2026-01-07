/*
 * Copyright (c) 2017 Intel and/or its affiliates
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
#include "upf/upf_stats.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/rules/upf_gtpu_proto.h"
#include "upf/core/upf_buffer_opaque.h"
#include "upf/utils/ip_helpers.h"

#define UPF_DEBUG_ENABLE 0

typedef enum
{
  UPF_GTPU_INPUT_NEXT_DROP,
  UPF_GTPU_INPUT_NEXT_HANDOFF,
  UPF_GTPU_INPUT_NEXT_IP4_FLOW_PROCESS,
  UPF_GTPU_INPUT_NEXT_IP6_FLOW_PROCESS,
  UPF_GTPU_INPUT_NEXT_IP4_FLOWLESS,
  UPF_GTPU_INPUT_NEXT_IP6_FLOWLESS,
  UPF_GTPU_INPUT_NEXT_IP4_NETCAP,
  UPF_GTPU_INPUT_NEXT_IP6_NETCAP,
  UPF_GTPU_INPUT_NEXT_ERROR_INDICATION,
  UPF_GTPU_INPUT_NEXT_ECHO_REQUEST,
  UPF_GTPU_INPUT_N_NEXT,
} gtpu_input_next_t;

#define foreach_upf_gtpu_error                                                \
  _ (DECAPSULATED, "good packets decapsulated")                               \
  _ (NO_SUCH_TUNNEL, "no such tunnel packets")                                \
  _ (HANDOFF, "handoff to other worker")                                      \
  _ (BAD_VER, "bad version in gtpu header")                                   \
  _ (UNSUPPORTED_TYPE, "gtp type unsupported")                                \
  _ (LENGTH_ERROR, "packets with length errors")                              \
  _ (NO_ECHO_SEQ, "no seq in the echo")                                       \
  _ (OLD_SESSION, "previously removed session")                               \
  _ (INACTIVE_SESSION, "not yet active session")                              \
  _ (ERROR_INDICATION, "got error indication")                                \
  _ (ECHO_RESPONSE, "got echo response")                                      \
  _ (INVALID_INNER_IP4_CSUM, "invalid inner IPv4 csum")

typedef enum
{
#define _(n, s) UPF_GTPU_ERROR_##n,
  foreach_upf_gtpu_error
#undef _
    UPF_GTPU_N_ERROR,
} upf_gtpu_input_error_t;

static char *upf_gtpu_error_strings[] = {
#define _(n, s) s,
  foreach_upf_gtpu_error
#undef _
};

typedef struct
{
  u32 session_index;
  u32 teid;
  upf_lid_t gtpu_ep_lid;
  upf_gtpu_input_error_t error;
  gtpu_input_next_t next;
} gtpu_rx_trace_t;

static u8 *
format_gtpu_rx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpu_rx_trace_t *t = va_arg (*args, gtpu_rx_trace_t *);

  if (t->next == UPF_GTPU_INPUT_NEXT_ERROR_INDICATION)
    {
      /*
       * In this case, session index is retrieved on the error
       * indication node, so let's not add a misleading error message
       */
      s = format (s, "received GTPU Error Indication");
    }
  else if (t->next == UPF_GTPU_INPUT_NEXT_HANDOFF)
    {
      s = format (s, "found session on other thread");
    }
  else if (is_valid_id (t->session_index))
    {
      s = format (
        s, "GTPU upf_session=%d teid=0x%08x gtpu_ep_lid=%d next=%d error=%d",
        t->session_index, t->teid, (u32) t->gtpu_ep_lid, t->next, t->error);
    }
  else
    {
      s = format (s, "upf_session for teid=0x%08x does not exist", t->teid);
    }
  return s;
}

static gtpu_input_next_t
_upf_gtpu_signalling_msg (gtpu_header_tpdu_t *gtpu,
                          upf_gtpu_input_error_t *error)
{
  if (PREDICT_FALSE ((gtpu->ver_flags & GTPU_S_BIT) == 0))
    {
      *error = UPF_GTPU_ERROR_NO_ECHO_SEQ;
      return UPF_GTPU_INPUT_NEXT_DROP;
    }

  switch (gtpu->type)
    {
    case GTPU_TYPE_ECHO_REQUEST:
      return UPF_GTPU_INPUT_NEXT_ECHO_REQUEST;

    case GTPU_TYPE_ECHO_RESPONSE:
      // TODO: next0 = UPF_GTPU_INPUT_NEXT_ECHO_RESPONSE;
      *error = UPF_GTPU_ERROR_ECHO_RESPONSE;
      return UPF_GTPU_INPUT_NEXT_DROP;

    default:
      *error = UPF_GTPU_ERROR_UNSUPPORTED_TYPE;
      return UPF_GTPU_INPUT_NEXT_DROP;
    }
}

// return gtpv1 packet size including gtpv1 header
static u16
_encode_error_indication (gtpu_header_t *gtpu, gtpu_error_ind_t *error,
                          int is_ip4)
{
  gtpu->h.ver_flags = GTPU_V1_VER | GTPU_PT_GTP | GTPU_S_BIT | GTPU_E_BIT;
  gtpu->h.type = GTPU_TYPE_ERROR_IND;
  gtpu->h.teid = 0;   // required
  gtpu->sequence = 0; // required
  gtpu->next_ext_type = GTPU_EXT_HEADER_UDP_PORT;

  // do not include type field for first extension, since it is part of header
  gtpu_ext_header_t *ext0 = (void *) ((size_t) (gtpu + 1) - 1);
  // already set: ext0->type = GTPU_EXT_HEADER_UDP_PORT;
  ext0->len = 1;                       // in 4 byte units
  *((u16 *) &ext0->pad) = error->port; // already in net order

  u8 *ext_end = (void *) (ext0 + 1);
  *ext_end = GTPU_EXT_HEADER_NEXT_HEADER_NO_MORE;

  gtpu_tv_ie_t *ie0 = (void *) (ext_end + 1);
  ie0->id = GTPU_IE_TEID_I;
  *((u32 *) ie0->data) = error->teid; // already in net order

  gtpu_tv_ie_t *ie1 = (void *) (ie0->data + sizeof (u32));
  ie1->id = GTPU_IE_RECOVERY;
  *((u8 *) ie1->data) = 0;

  gtpu_tlv_ie_t *ie2 = (void *) (ie1->data + sizeof (u8));
  ie2->id = GTPU_IE_GSN_ADDRESS;
  void *end;
  if (is_ip4)
    {
      ie2->len = clib_host_to_net_u16 (sizeof (ip4_address_t));
      *((ip4_address_t *) ie2->data) = error->addr.ip4;
      end = ie2->data + sizeof (ip4_address_t);
    }
  else
    {
      ie2->len = clib_host_to_net_u16 (sizeof (ip6_address_t));
      *((ip6_address_t *) ie2->data) = error->addr.ip6;
      end = ie2->data + sizeof (ip6_address_t);
    }

  gtpu->h.length =
    clib_host_to_net_u16 ((size_t) end - (size_t) (&gtpu->h + 1));

  return (size_t) end - (size_t) gtpu;
}

// buffer current should point to GTPv1 header
static void
_upf_send_gtpu_error_ind (vlib_main_t *vm, vlib_buffer_t *rx_b, int is_ip4)
{
  upf_main_t *um = &upf_main;
  ip4_main_t *i4m = &ip4_main;
  ip6_main_t *i6m = &ip6_main;

  u8 host_config_ttl = i4m->host_config.ttl;

  u32 tx_bi = ~0;
  if (vlib_buffer_alloc (vm, &tx_bi, 1) != 1)
    {
      vlib_log_err (um->log_class,
                    "No buffers for gtpu error indication available");
      return;
    }

  vlib_buffer_t *tx_b = vlib_get_buffer (vm, tx_bi);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (tx_b);

  // TODO: In a packet trace it looks fine, we can see p0 traced for TX
  // But shouldn't we allocate new trace for it?
  tx_b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  tx_b->flags |= rx_b->flags & (~VLIB_BUFFER_IS_TRACED);
  tx_b->trace_handle = rx_b->trace_handle;

  /* For ip46-lookup get used FIB */
  u32 tx_fib_index;
  u32 tx_node_index;

  ASSERT (rx_b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID);

  // l4 offset is not valid, but we are currently on UDP header, so use it
  udp_header_t *rx_udp =
    (udp_header_t *) (rx_b->data + rx_b->current_data - sizeof (udp_header_t));
  gtpu_header_t *rx_gtpu = (gtpu_header_t *) (rx_udp + 1);

  if (is_ip4)
    {
      tx_fib_index = vec_elt (i4m->fib_index_by_sw_if_index,
                              vnet_buffer (rx_b)->sw_if_index[VLIB_RX]);

      ip4_header_t *rx_ip4 =
        (ip4_header_t *) (rx_b->data + vnet_buffer (rx_b)->l3_hdr_offset);

      ip4_header_t *tx_ip4 = (ip4_header_t *) vlib_buffer_get_current (tx_b);
      udp_header_t *tx_udp = (udp_header_t *) (tx_ip4 + 1);
      gtpu_header_t *tx_gtpu = (gtpu_header_t *) (tx_udp + 1);

      /* Reuse IP settings of original packet */
      memcpy (tx_ip4, rx_ip4, sizeof (ip4_header_t));

      /* Swap addresses, save src addr to be encoded */
      tx_ip4->ip_version_and_header_length = 0x45; // reset header len
      tx_ip4->dst_address = rx_ip4->src_address;
      tx_ip4->src_address = rx_ip4->dst_address;
      tx_ip4->fragment_id = 0;
      tx_ip4->ttl = host_config_ttl;

      gtpu_error_ind_t error;
      ip46_address_set_ip4 (&error.addr, &rx_ip4->src_address);
      error.teid = rx_gtpu->h.teid;  // net order
      error.port = rx_udp->src_port; // net order

      tx_udp->src_port = rx_udp->dst_port;
      tx_udp->dst_port = clib_host_to_net_u16 (GTPU_UDP_PORT);

      u16 gtpu_len = _encode_error_indication (tx_gtpu, &error, is_ip4);

      tx_b->current_length =
        sizeof (ip4_header_t) + sizeof (udp_header_t) + gtpu_len;

      tx_ip4->length = clib_host_to_net_u16 (tx_b->current_length);
      tx_udp->length =
        clib_host_to_net_u16 (tx_b->current_length - sizeof (ip4_header_t));

      tx_ip4->checksum = ip4_header_checksum (tx_ip4);
      tx_udp->checksum = 0;
      tx_udp->checksum = ip4_tcp_udp_compute_checksum (vm, tx_b, tx_ip4);
      if (tx_udp->checksum == 0)
        tx_udp->checksum = 0xffff;

      tx_node_index = ip4_lookup_node.index;
    }
  else
    {
      tx_fib_index = vec_elt (i6m->fib_index_by_sw_if_index,
                              vnet_buffer (rx_b)->sw_if_index[VLIB_RX]);

      ip6_header_t *rx_ip6 =
        (ip6_header_t *) (rx_b->data + vnet_buffer (rx_b)->l3_hdr_offset);

      ip6_header_t *tx_ip6 = (ip6_header_t *) vlib_buffer_get_current (tx_b);
      udp_header_t *tx_udp = (udp_header_t *) (tx_ip6 + 1);
      gtpu_header_t *tx_gtpu = (gtpu_header_t *) (tx_udp + 1);

      /* Reuse IP settings of original packet */
      memcpy (tx_ip6, rx_ip6, sizeof (ip6_header_t));

      /* Swap addresses, save src addr to be encoded */
      tx_ip6->dst_address = rx_ip6->src_address;
      tx_ip6->src_address = rx_ip6->dst_address;
      tx_ip6->hop_limit = host_config_ttl;

      gtpu_error_ind_t error;
      ip46_address_set_ip6 (&error.addr, &rx_ip6->src_address);
      error.teid = rx_gtpu->h.teid;  // net order
      error.port = rx_udp->src_port; // net order

      tx_udp->src_port = rx_udp->dst_port;
      tx_udp->dst_port = clib_host_to_net_u16 (GTPU_UDP_PORT);

      u16 gtpu_len = _encode_error_indication (tx_gtpu, &error, is_ip4);

      u16 ip6_payload_length = sizeof (udp_header_t) + gtpu_len;

      tx_b->current_length = sizeof (ip6_header_t) + ip6_payload_length;

      tx_ip6->payload_length = clib_host_to_net_u16 (ip6_payload_length);
      tx_udp->length = clib_host_to_net_u16 (ip6_payload_length);

      int bogus;
      tx_udp->checksum = 0;
      tx_udp->checksum =
        ip6_tcp_udp_icmp_compute_checksum (vm, tx_b, tx_ip6, &bogus);
      if (tx_udp->checksum == 0)
        tx_udp->checksum = 0xffff;

      tx_node_index = ip6_lookup_node.index;
    }

  vnet_buffer (tx_b)->sw_if_index[VLIB_TX] = tx_fib_index;

  vlib_frame_t *f = vlib_get_frame_to_node (vm, tx_node_index);
  u32 *to_next = vlib_frame_vector_args (f);
  to_next[0] = tx_bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, tx_node_index, f);
}

always_inline uword
upf_gtpu_input (vlib_main_t *vm, vlib_node_runtime_t *node,
                vlib_frame_t *from_frame, u8 is_ip4)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  u32 n_left_from, next_index, *from, *to_next;
  u32 session_id = ~0;
  u16 session_thread = ~0;
  u16 session_generation0;
  u8 gtpu_ep_lid = ~0;
  bool is_session_ep_activated = false;
  upf_gtpu4_tunnel_key_t last_key4;
  upf_gtpu6_tunnel_key_t last_key6;

  u16 thread_index = vm->thread_index;

  if (is_ip4)
    last_key4.as_u64 = ~0;
  else
    memset (&last_key6, 0xff, sizeof (last_key6));

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

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

          u32 next;
          upf_gtpu_input_error_t error;
          vlib_buffer_t *b = vlib_get_buffer (vm, bi);

          // TODO: this is not L4, but L5. Maybe use other method to pass size
          // to error indication?
          vnet_buffer (b)->l4_hdr_offset = b->current_data;

          // udp node leaves current_data pointing at the gtpu header
          gtpu_header_tpdu_t *gtpu = vlib_buffer_get_current (b);

          // len of outer ip+udp to get to inner ip
          u16 outer_ip_udp_len =
            (b->current_data - vnet_buffer (b)->l3_hdr_offset);
          ASSERT (outer_ip_udp_len ==
                  (is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t)) +
                    sizeof (udp_header_t));

          void *outer_ip = b->data + vnet_buffer (b)->l3_hdr_offset;

          if (PREDICT_FALSE ((gtpu->ver_flags & GTPU_VER_MASK) != GTPU_V1_VER))
            {
              error = UPF_GTPU_ERROR_BAD_VER;
              next = UPF_GTPU_INPUT_NEXT_DROP;
              goto _trace;
            }

          if (PREDICT_FALSE (gtpu->type != GTPU_TYPE_GTPU))
            {
              // no need in handower, advance to outer ip header
              vlib_buffer_advance (b, -outer_ip_udp_len);

              upf_debug ("got not PDU gtpu %U", format_ip_header,
                         vlib_buffer_get_current (b), b->current_length);

              switch (gtpu->type)
                {
                case GTPU_TYPE_ERROR_IND:
                  vlib_node_increment_counter (
                    vm, node->node_index, UPF_GTPU_INPUT_NEXT_ERROR_INDICATION,
                    1);

                  UPF_ENTER_SUBGRAPH (b, ~0, UPF_PACKET_SOURCE_GTPU, ~0,
                                      is_ip4, false);
                  next = UPF_GTPU_INPUT_NEXT_ERROR_INDICATION;
                  upf_debug ("next error indication");
                  break;

                case GTPU_TYPE_ECHO_REQUEST:
                case GTPU_TYPE_ECHO_RESPONSE:
                  UPF_ENTER_SUBGRAPH (b, ~0, UPF_PACKET_SOURCE_GTPU, ~0,
                                      is_ip4, false);
                  next = _upf_gtpu_signalling_msg (gtpu, &error);
                  upf_debug ("echo req/resp");
                  break;

                default:
                  error = UPF_GTPU_ERROR_UNSUPPORTED_TYPE;
                  next = UPF_GTPU_INPUT_NEXT_DROP;
                  upf_debug ("unsupported type 0x%x", gtpu->type);
                  break;
                }

              goto _trace;
            }

          if (is_ip4)
            {
              ip4_header_t *outer_ip4 = outer_ip;
              upf_gtpu4_tunnel_key_t key4 = {
                .ep_ip4 = outer_ip4->dst_address,
                .teid = clib_net_to_host_u32 (gtpu->teid),
              };

              if (PREDICT_TRUE (key4.as_u64 != last_key4.as_u64))
                {
                  clib_bihash_kv_8_8_t kv = {}, value;
                  kv.key = key4.as_u64;

                  if (PREDICT_FALSE (clib_bihash_search_8_8 (
                        &ugm->tunnel_by_fteid4, &kv, &value)))
                    {
                      _upf_send_gtpu_error_ind (vm, b, is_ip4);
                      error = UPF_GTPU_ERROR_NO_SUCH_TUNNEL;
                      next = UPF_GTPU_INPUT_NEXT_DROP;
                      goto _trace;
                    }

                  gtpu_tunnel_lookup_value_unpack (
                    value.value, &session_id, &session_generation0,
                    &session_thread, &gtpu_ep_lid, &is_session_ep_activated);
                  last_key4 = key4;
                }
            }
          else /* !is_ip4 */
            {
              ip6_header_t *outer_ip6 = outer_ip;
              upf_gtpu6_tunnel_key_t key6 = {
                .ep_ip6 = outer_ip6->dst_address,
                .teid = clib_net_to_host_u32 (gtpu->teid),
              };

              if (PREDICT_TRUE (key6.as_u64 != last_key6.as_u64))
                {
                  clib_bihash_kv_24_8_t kv = {}, value;
                  kv.key[0] = key6.as_u64[0];
                  kv.key[1] = key6.as_u64[1];
                  kv.key[2] = key6.as_u64[2];

                  if (PREDICT_FALSE (clib_bihash_search_24_8 (
                        &ugm->tunnel_by_fteid6, &kv, &value)))
                    {
                      _upf_send_gtpu_error_ind (vm, b, is_ip4);
                      error = UPF_GTPU_ERROR_NO_SUCH_TUNNEL;
                      next = UPF_GTPU_INPUT_NEXT_DROP;
                      goto _trace;
                    }

                  gtpu_tunnel_lookup_value_unpack (
                    value.value, &session_id, &session_generation0,
                    &session_thread, &gtpu_ep_lid, &is_session_ep_activated);
                  last_key6 = key6;
                }
            }

          if (session_thread != thread_index)
            {
              upf_buffer_opaque (b)->handoff.thread_id = session_thread;
              error = UPF_GTPU_ERROR_HANDOFF;
              next = UPF_GTPU_INPUT_NEXT_HANDOFF;
              goto _trace;
            }

          if (PREDICT_FALSE (!is_session_ep_activated))
            {
              error = UPF_GTPU_ERROR_INACTIVE_SESSION;
              next = UPF_GTPU_INPUT_NEXT_DROP;
              goto _trace;
            }

          // Packet is local to thread. Can advance to outer ip header
          vlib_buffer_advance (b, -outer_ip_udp_len);

          upf_dp_session_t *dsx =
            upf_wk_get_dp_session (thread_index, session_id);

          if (dsx->session_generation != session_generation0)
            {
              // ideally shouldn't happen, but CENNSO-3194
              error = UPF_GTPU_ERROR_OLD_SESSION;
              next = UPF_GTPU_INPUT_NEXT_DROP;
              goto _trace;
            }

          ASSERT (dsx->is_created && !dsx->is_removed);

          u16 gtpu_hdr_len;
          /* Manipulate gtpu header */
          if (PREDICT_FALSE ((gtpu->ver_flags & GTPU_E_S_PN_BIT) != 0))
            {
              gtpu_header_t *gtpu0_f = (gtpu_header_t *) gtpu;
              gtpu_hdr_len = sizeof (gtpu_header_t);

              if (PREDICT_FALSE ((gtpu->ver_flags & GTPU_E_BIT) != 0))
                {
                  gtpu_ext_header_t *ext = (void *) &gtpu0_f->next_ext_type;
                  u8 *end = vlib_buffer_get_tail (b);

                  while ((u8 *) ext < end && ext->type != 0)
                    {
                      if (PREDICT_FALSE (!ext->len))
                        {
                          error = UPF_GTPU_ERROR_LENGTH_ERROR;
                          next = UPF_GTPU_INPUT_NEXT_DROP;
                          goto _trace;
                        }

                      /* gtpu_ext_header_t is 4 bytes and the len is in units
                       * of 4 */
                      gtpu_hdr_len += ext->len * 4;
                      ext = (void *) (((u8 *) ext) + ext->len * 4);
                    }
                }
            }
          else
            {
              gtpu_hdr_len = sizeof (gtpu_header_tpdu_t);
            }

          // len of outer ip+udp+gtpu to get to inner ip
          u16 outer_hdr_len = outer_ip_udp_len + gtpu_hdr_len;

          upf_rules_t *rules = upf_wk_get_rules (thread_index, dsx->rules_id);
          rules_ep_gtpu_t *gtpu_ep =
            upf_rules_get_ep_gtpu (rules, gtpu_ep_lid);

          ip4_header_t *inner_ip = vlib_buffer_get_current (b) + outer_hdr_len;

          upf_debug ("gtpu lid %d pdr lid %d teid 0x%x outer_hdr_len %u",
                     gtpu_ep_lid, &gtpu_ep->pdr_lids,
                     clib_net_to_host_u32 (gtpu->teid), outer_hdr_len);
          upf_debug ("outer ip %U", format_ip_header, outer_ip,
                     b->current_length);
          upf_debug ("inner ip %U", format_ip_header, inner_ip,
                     b->current_length - outer_hdr_len);

          bool inner_ip_is4 =
            (inner_ip->ip_version_and_header_length & 0xF0) == 0x40;

          UPF_ENTER_SUBGRAPH (b, session_id, UPF_PACKET_SOURCE_GTPU,
                              gtpu_ep_lid, inner_ip_is4, gtpu_ep->is_uplink);
          upf_buffer_opaque (b)->gtpu.is_gtpu_v4 = is_ip4;
          upf_buffer_opaque (b)->gtpu.outer_hdr_len = outer_hdr_len;
          upf_buffer_opaque (b)->gtpu.gtpu_ext_hdr_len =
            gtpu_hdr_len - (sizeof (gtpu_header_tpdu_t));

          // with outer header
          u32 total_buffer_len = vlib_buffer_length_in_chain (vm, b);

          if (PREDICT_TRUE (inner_ip_is4))
            {
              if (PREDICT_FALSE (!ip4_header_checksum_is_valid (inner_ip)))
                {
                  error = UPF_GTPU_ERROR_INVALID_INNER_IP4_CSUM;
                  next = UPF_GTPU_INPUT_NEXT_DROP;
                  goto _trace;
                }
            }

          if (PREDICT_FALSE (
                (outer_hdr_len + (inner_ip_is4 ? sizeof (ip4_header_t) :
                                                 sizeof (ip6_header_t))) >=
                total_buffer_len))
            {
              error = UPF_GTPU_ERROR_LENGTH_ERROR;
              next = UPF_GTPU_INPUT_NEXT_DROP;
              goto _trace;
            }

          // keep all nodes pointing to inner packet
          vlib_buffer_advance (b, upf_buffer_opaque (b)->gtpu.outer_hdr_len);

          upf_vnet_buffer_l3l4_hdr_offset_current_ip (b, inner_ip_is4);

          vlib_increment_combined_counter (&upf_stats_main.wk.gtpu_endpoint_rx,
                                           thread_index, gtpu_ep->gtpu_ep_id,
                                           1, total_buffer_len);

          if (PREDICT_FALSE (rules->want_netcap))
            {
              next = inner_ip_is4 ? UPF_GTPU_INPUT_NEXT_IP4_NETCAP :
                                    UPF_GTPU_INPUT_NEXT_IP6_NETCAP;
            }
          else if (dsx->flow_mode == UPF_SESSION_FLOW_MODE_DISABLED)
            {
              next = inner_ip_is4 ? UPF_GTPU_INPUT_NEXT_IP4_FLOWLESS :
                                    UPF_GTPU_INPUT_NEXT_IP6_FLOWLESS;
            }
          else
            {
              next = inner_ip_is4 ? UPF_GTPU_INPUT_NEXT_IP4_FLOW_PROCESS :
                                    UPF_GTPU_INPUT_NEXT_IP6_FLOW_PROCESS;
            }

        _trace:
          if (next == UPF_GTPU_INPUT_NEXT_DROP)
            b->error = node->errors[error];

          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              gtpu_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
              tr->session_index = session_id;
              tr->teid = clib_net_to_host_u32 (gtpu->teid);
              tr->gtpu_ep_lid = gtpu_ep_lid;
              tr->error = error;
              tr->next = next;
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi, next);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_gtpu4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_gtpu_input (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_REGISTER_NODE (upf_gtpu4_input_node) = {
  .name = "upf-gtpu4-input",
  .vector_size = sizeof (u32),
  .n_errors = UPF_GTPU_N_ERROR,
  .error_strings = upf_gtpu_error_strings,
  .n_next_nodes = UPF_GTPU_INPUT_N_NEXT,
  .next_nodes = {
    [UPF_GTPU_INPUT_NEXT_DROP]             = "error-drop",
    [UPF_GTPU_INPUT_NEXT_HANDOFF]          = "upf-gtp-ip4-handoff",
    [UPF_GTPU_INPUT_NEXT_IP4_FLOW_PROCESS] = "upf-ip4-flow-process",
    [UPF_GTPU_INPUT_NEXT_IP6_FLOW_PROCESS] = "upf-ip6-flow-process",
    [UPF_GTPU_INPUT_NEXT_IP4_FLOWLESS]     = "upf-ip4-flowless",
    [UPF_GTPU_INPUT_NEXT_IP6_FLOWLESS]     = "upf-ip6-flowless",
    [UPF_GTPU_INPUT_NEXT_IP4_NETCAP]       = "upf-netcap4",
    [UPF_GTPU_INPUT_NEXT_IP6_NETCAP]       = "upf-netcap6",
    [UPF_GTPU_INPUT_NEXT_ERROR_INDICATION] = "upf-gtp-error-indication",
    [UPF_GTPU_INPUT_NEXT_ECHO_REQUEST]     = "upf-gtp-ip4-echo-request",
  },
  .format_trace = format_gtpu_rx_trace,
};

VLIB_NODE_FN (upf_gtpu6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_gtpu_input (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_gtpu6_input_node) = {
  .name = "upf-gtpu6-input",
  .vector_size = sizeof (u32),
  .n_errors = UPF_GTPU_N_ERROR,
  .error_strings = upf_gtpu_error_strings,
  .n_next_nodes = UPF_GTPU_INPUT_N_NEXT,
  .next_nodes = {
    [UPF_GTPU_INPUT_NEXT_DROP]             = "error-drop",
    [UPF_GTPU_INPUT_NEXT_HANDOFF]          = "upf-gtp-ip6-handoff",
    [UPF_GTPU_INPUT_NEXT_IP4_FLOW_PROCESS] = "upf-ip4-flow-process",
    [UPF_GTPU_INPUT_NEXT_IP6_FLOW_PROCESS] = "upf-ip6-flow-process",
    [UPF_GTPU_INPUT_NEXT_IP4_FLOWLESS]     = "upf-ip4-flowless",
    [UPF_GTPU_INPUT_NEXT_IP6_FLOWLESS]     = "upf-ip6-flowless",
    [UPF_GTPU_INPUT_NEXT_IP4_NETCAP]       = "upf-netcap4",
    [UPF_GTPU_INPUT_NEXT_IP6_NETCAP]       = "upf-netcap6",
    [UPF_GTPU_INPUT_NEXT_ERROR_INDICATION] = "upf-gtp-error-indication",
    [UPF_GTPU_INPUT_NEXT_ECHO_REQUEST]     = "upf-gtp-ip6-echo-request",
  },
  .format_trace = format_gtpu_rx_trace,
  .protocol_hint = VLIB_NODE_PROTO_HINT_IP4,
};

#include "upf/utils/upf_handoff_template.h"

VLIB_NODE_FN (upf_gtpu4_input_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  return upf_handoff_template_node (vm, node, from_frame,
                                    ugm->fq_gtpu4_handoff_index);
}

VLIB_REGISTER_NODE (upf_gtpu4_input_handoff_node) =
  UPF_HANDOFF_TEMPLATE_NODE_REGISTRATION ("upf-gtp-ip4-handoff");

VLIB_NODE_FN (upf_gtpu6_input_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  return upf_handoff_template_node (vm, node, from_frame,
                                    ugm->fq_gtpu6_handoff_index);
}

VLIB_REGISTER_NODE (upf_gtpu6_input_handoff_node) =
  UPF_HANDOFF_TEMPLATE_NODE_REGISTRATION ("upf-gtp-ip6-handoff");
