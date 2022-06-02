/*
 * Copyright (c) 2018 Travelping GmbH
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
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/upf_proxy.h>

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)				\
  do { } while (0)
#endif

typedef enum
{
  UPF_PROXY_INPUT_NEXT_DROP,
  UPF_PROXY_INPUT_NEXT_TCP_INPUT,
  UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP,
  UPF_PROXY_INPUT_NEXT_TCP_FORWARD,
  UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT,
  UPF_PROXY_INPUT_N_NEXT,
} upf_proxy_input_next_t;

/* Statistics (not all errors) */
#define foreach_upf_proxy_input_error				\
  _(LENGTH, "inconsistent ip/tcp lengths")			\
  _(NO_LISTENER, "no redirect server available")		\
  _(PROCESS, "good packets process")				\
  _(OPTIONS, "Could not parse options")				\
  _(CREATE_SESSION_FAIL, "Sessions couldn't be allocated")

static char *upf_proxy_input_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_proxy_input_error
#undef _
};

typedef enum
{
#define _(sym,str) UPF_PROXY_INPUT_ERROR_##sym,
  foreach_upf_proxy_input_error
#undef _
    UPF_PROXY_INPUT_N_ERROR,
} upf_proxy_input_error_t;

typedef struct
{
  u32 session_index;
  u64 cp_seid;
  u8 packet_data[64 - 1 * sizeof (u32)];
}
upf_proxy_input_trace_t;

static u8 *
format_upf_proxy_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_proxy_input_trace_t *t = va_arg (*args, upf_proxy_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session%d cp-seid 0x%016" PRIx64 "\n%U%U",
	      t->session_index, t->cp_seid,
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static u8
tcp_flow_is_valid (tcp_connection_t * tc, flow_entry_t * f,
		   flow_direction_t direction)
{
  flow_direction_t origin = direction ^ f->is_reverse;
  flow_direction_t reverse = direction ^ FT_REVERSE ^ f->is_reverse;

  if (!tc)
    return 1;

  if (!ip46_address_is_equal (&f->key.ip[origin], &tc->connection.rmt_ip))
    return 0;

  if (!ip46_address_is_equal (&f->key.ip[reverse], &tc->connection.lcl_ip))
    return 0;

  return (f->key.port[origin] == tc->connection.rmt_port) &&
    (f->key.port[reverse] == tc->connection.lcl_port);
}

static void
kill_connection_hard (tcp_connection_t * tc)
{
  session_lookup_del_connection (&tc->connection);

  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
  tcp_connection_del (tc);
}

static_always_inline u32
splice_tcp_connection (upf_main_t * gtm, flow_entry_t * flow,
		       flow_direction_t direction)
{
  flow_direction_t origin = FT_ORIGIN ^ direction;
  flow_direction_t reverse = FT_REVERSE ^ direction;
  flow_tc_t *rev = &flow_tc (flow, reverse);
  flow_tc_t *ftc = &flow_tc (flow, origin);
  transport_connection_t *tc;
  tcp_connection_t *tcpRx, *tcpTx;
  session_t *s;

  if (rev->conn_index == ~0)
    return UPF_PROXY_INPUT_NEXT_TCP_INPUT;

  if (flow->dont_splice)
    return UPF_PROXY_INPUT_NEXT_TCP_INPUT;

  // lookup connections
  tc =
    transport_get_connection (TRANSPORT_PROTO_TCP, ftc->conn_index,
			      ftc->thread_index);
  if (!tc)
    return UPF_PROXY_INPUT_NEXT_TCP_INPUT;

  s = session_get_if_valid (tc->s_index, tc->thread_index);
  if (!s)
    return UPF_PROXY_INPUT_NEXT_TCP_INPUT;

  tcpRx = tcp_get_connection_from_transport
    (transport_get_connection
     (TRANSPORT_PROTO_TCP, ftc->conn_index, ftc->thread_index));
  tcpTx =
    tcp_get_connection_from_transport (transport_get_connection
				       (TRANSPORT_PROTO_TCP, rev->conn_index,
					rev->thread_index));

  ASSERT (tcp_flow_is_valid (tcpRx, flow, direction));
  ASSERT (tcp_flow_is_valid (tcpTx, flow, FT_REVERSE ^ direction));

  if (!tcpRx || !tcpTx)
    return UPF_PROXY_INPUT_NEXT_TCP_INPUT;

  /* check TCP connection properties */
  if ((tcpRx->snd_mss > tcpTx->rcv_opts.mss) ||
      (tcpTx->snd_mss > tcpRx->rcv_opts.mss))
    {
      upf_debug ("=============> DON'T SPLICE <=============");
      flow->dont_splice = 1;
      vlib_increment_simple_counter (&gtm->upf_simple_counters
				     [UPF_FLOWS_NOT_STITCHED_MSS_MISMATCH],
				     vlib_get_thread_index (), 0, 1);
      return UPF_PROXY_INPUT_NEXT_TCP_INPUT;
    }

  if (tcp_opts_tstamp (&tcpTx->rcv_opts) !=
      tcp_opts_tstamp (&tcpRx->rcv_opts))
    {
      upf_debug ("=============> DON'T SPLICE <=============");
      flow->dont_splice = 1;
      vlib_increment_simple_counter (&gtm->upf_simple_counters
				     [UPF_FLOWS_NOT_STITCHED_TCP_OPS_TIMESTAMP],
				     vlib_get_thread_index (), 0, 1);
      return UPF_PROXY_INPUT_NEXT_TCP_INPUT;
    }

  if (tcp_opts_sack_permitted (&tcpTx->rcv_opts) !=
      tcp_opts_sack_permitted (&tcpRx->rcv_opts))
    {
      upf_debug ("=============> DON'T SPLICE <=============");
      flow->dont_splice = 1;
      vlib_increment_simple_counter (&gtm->upf_simple_counters
				     [UPF_FLOWS_NOT_STITCHED_TCP_OPS_SACK_PERMIT],
				     vlib_get_thread_index (), 0, 1);
      return UPF_PROXY_INPUT_NEXT_TCP_INPUT;
    }

  if (flow_seq_offs (flow, origin) == 0)
    flow_seq_offs (flow, origin) = direction == FT_ORIGIN ?
      tcpTx->snd_nxt - tcpRx->rcv_nxt : tcpRx->rcv_nxt - tcpTx->snd_nxt;

  if (flow_seq_offs (flow, reverse) == 0)
    flow_seq_offs (flow, reverse) = direction == FT_ORIGIN ?
      tcpTx->rcv_nxt - tcpRx->snd_nxt : tcpRx->snd_nxt - tcpTx->rcv_nxt;

  /* check fifo, proxy Tx/Rx are connected... */
  if (svm_fifo_max_dequeue (s->rx_fifo) != 0 ||
      svm_fifo_max_dequeue (s->tx_fifo) != 0)
    {
      flow->spliced_dirty = 1;
      vlib_increment_simple_counter (&gtm->upf_simple_counters
				     [UPF_FLOWS_STITCHED_DIRTY_FIFOS],
				     vlib_get_thread_index (), 0, 1);
    }

  /* kill the TCP connections, session and proxy session */
  kill_connection_hard (tcpRx);
  kill_connection_hard (tcpTx);

  /* switch to direct spliceing */
  flow->is_spliced = 1;

  vlib_increment_simple_counter (&gtm->upf_simple_counters
				 [UPF_FLOWS_STITCHED],
				 vlib_get_thread_index (), 0, 1);

  return UPF_PROXY_INPUT_NEXT_TCP_FORWARD;
}

static_always_inline int
upf_vnet_load_tcp_hdr_offset (vlib_buffer_t * b)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (b);
  tcp_header_t *tcp;

  if ((ip4->ip_version_and_header_length & 0xF0) == 0x40)
    {
      int ip_hdr_bytes = ip4_header_bytes (ip4);
      if (PREDICT_FALSE (b->current_length < ip_hdr_bytes + sizeof (*tcp)))
	return -1;

      tcp = ip4_next_header (ip4);
      vnet_buffer (b)->tcp.hdr_offset = (u8 *) tcp - (u8 *) ip4;
    }
  else if ((ip4->ip_version_and_header_length & 0xF0) == 0x60)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      if (PREDICT_FALSE (b->current_length < sizeof (*ip6) + sizeof (*tcp)))
	return -1;

      tcp = ip6_next_header (ip6);
      vnet_buffer (b)->tcp.hdr_offset = (u8 *) tcp - (u8 *) ip6;
    }
  else
    return -1;

  return 0;
}

static_always_inline void
load_tstamp_offset (vlib_buffer_t * b, flow_direction_t direction,
		    flow_entry_t * flow, u32 thread_index)
{
  tcp_header_t *tcp;
  tcp_options_t opts;

  if (flow_tsval_offs (flow, direction) != 0)
    return;

  if (upf_vnet_load_tcp_hdr_offset (b))
    return;

  tcp = tcp_buffer_hdr (b);
  memset (&opts, 0, sizeof (opts));
  if (tcp_options_parse (tcp, &opts, 1))
    return;

  if (!tcp_opts_tstamp (&opts))
    return;

  flow_tsval_offs (flow, direction) =
    opts.tsval - tcp_time_tstamp (thread_index);
}

static uword
upf_proxy_input (vlib_main_t * vm, vlib_node_runtime_t * node,
		 const char *node_name, vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *gtm = &upf_main;
  vnet_main_t *vnm = gtm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  flowtable_main_t *fm = &flowtable_main;
  timestamp_nsec_t timestamp;
  u32 current_time = (u32) vlib_time_now (vm);

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 sw_if_index = 0;
  u32 next = 0;
  u32 len;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;
  unix_time_now_nsec_fraction (&timestamp.sec, &timestamp.nsec);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      u32 error;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  upf_session_t *sess = NULL;
	  flow_direction_t direction;
	  flow_entry_t *flow = NULL;
	  upf_pdr_t *pdr = NULL;
	  upf_far_t *far = NULL;
	  struct rules *active;
	  flow_tc_t *ftc;

	  bi = from[0];
	  to_next[0] = bi;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);
	  UPF_CHECK_INNER_NODE (b);

	  error = 0;
	  next = UPF_FORWARD_NEXT_DROP;

	  ASSERT (upf_buffer_opaque (b)->gtpu.flow_id != ~0);

	  /* Outer Header Removal */
	  switch (upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK)
	    {
	    case BUFFER_GTP_UDP_IP4:	/* GTP-U/UDP/IPv4 */
	      vlib_buffer_advance (b,
				   upf_buffer_opaque (b)->gtpu.data_offset);
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;

	    case BUFFER_GTP_UDP_IP6:	/* GTP-U/UDP/IPv6 */
	      vlib_buffer_advance (b,
				   upf_buffer_opaque (b)->gtpu.data_offset);
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;

	    case BUFFER_UDP_IP4:	/* UDP/IPv4 */
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      vlib_buffer_advance (b,
				   sizeof (ip4_header_t) +
				   sizeof (udp_header_t));
	      break;

	    case BUFFER_UDP_IP6:	/* UDP/IPv6 */
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      vlib_buffer_advance (b,
				   sizeof (ip6_header_t) +
				   sizeof (udp_header_t));
	      break;

	    default:
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;
	    }

	  upf_debug ("flow: %p (0x%08x): %U\n",
		     fm->flows + upf_buffer_opaque (b)->gtpu.flow_id,
		     upf_buffer_opaque (b)->gtpu.flow_id,
		     format_flow_key,
		     &(fm->flows + upf_buffer_opaque (b)->gtpu.flow_id)->key);

	  flow =
	    pool_elt_at_index (fm->flows,
			       upf_buffer_opaque (b)->gtpu.flow_id);
	  ASSERT (flow);

	  direction =
	    (flow->is_reverse ==
	     upf_buffer_opaque (b)->gtpu.is_reverse) ? FT_ORIGIN : FT_REVERSE;

	  upf_debug ("direction: %u, buffer: %u, flow: %u", direction,
		     upf_buffer_opaque (b)->gtpu.is_reverse,
		     flow->is_reverse);

	  vnet_buffer (b)->ip.rx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

	  ftc = &flow_tc (flow, direction);

	  if (flow->is_spliced)
	    {
	      /* bypass TCP connection handling */
	      upf_debug ("TCP_FORWARD");
	      next = UPF_PROXY_INPUT_NEXT_TCP_FORWARD;
	    }
	  else if (ftc->conn_index != ~0)
	    {
	      ASSERT (ftc->thread_index == thread_index);

	      upf_debug ("existing connection 0x%08x", ftc->conn_index);
	      vnet_buffer (b)->tcp.connection_index = ftc->conn_index;

	      /* transport connection already setup */
	      next = splice_tcp_connection (gtm, flow, direction);
	    }
	  else
	    {
	      /* ftc->conn_index == ~0 */

	      if (ftc->thread_index != ~0)
		{
		  /* the flow already had a serving session, but that session was closed
		     signaled by conn_index == ~0 && thread_index != ~0 */
		  upf_debug ("LATE TCP FRAGMENT");
		  next = UPF_FORWARD_NEXT_DROP;
		}
	      else if (direction == FT_ORIGIN)
		{
		  upf_debug ("PROXY_ACCEPT");
		  load_tstamp_offset (b, direction, flow, thread_index);
		  next = UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT;
		}
	      else if (direction == FT_REVERSE)
		{
		  upf_debug ("INPUT_LOOKUP");
		  load_tstamp_offset (b, direction, flow, thread_index);
		  next = UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP;
		}
	      else
		goto stats;
	    }

	  // FT_REVERSE direction (DL) and stitched traffic (upf-ip[46]-tcp-forward)
	  // is accounted for on the upf-ip[46]-forward node
	  if (direction == FT_ORIGIN
	      && next != UPF_PROXY_INPUT_NEXT_TCP_FORWARD)
	    {
	      /* Get next node index and adj index from tunnel next_dpo */
	      sess = pool_elt_at_index (gtm->sessions, flow->session_index);
	      active = pfcp_get_rules (sess, PFCP_ACTIVE);
	      pdr =
		pfcp_get_pdr_by_id (active, flow_pdr_id (flow, direction));
	      far = pdr ? pfcp_get_far_by_id (active, pdr->far_id) : NULL;

	      if (PREDICT_FALSE (!pdr) || PREDICT_FALSE (!far))
		{
		  next = UPF_FORWARD_NEXT_DROP;
		  goto stats;
		}

#define IS_DL(_pdr, _far)						\
              ((_pdr)->pdi.src_intf == SRC_INTF_CORE || (_far)->forward.dst_intf == DST_INTF_ACCESS)
#define IS_UL(_pdr, _far)						\
              ((_pdr)->pdi.src_intf == SRC_INTF_ACCESS || (_far)->forward.dst_intf == DST_INTF_CORE)

	      upf_debug ("pdr: %d, far: %d\n", pdr->id, far->id);
	      next = process_qers (vm, sess, active, pdr, b,
				   IS_DL (pdr, far), IS_UL (pdr, far), next);
	      next = process_urrs (vm, sess, node_name, active, pdr, b,
				   IS_DL (pdr, far), IS_UL (pdr, far), next);
	      flow_update_stats (vm, b, flow, is_ip4,
				 timestamp, current_time);

#undef IS_DL
#undef IS_UL
	    }

	stats:
	  len = vlib_buffer_length_in_chain (vm, b);
	  stats_n_packets += 1;
	  stats_n_bytes += len;

	  /* Batch stats increment on the same gtpu tunnel so counter is not
	     incremented per packet. Note stats are still incremented for deleted
	     and admin-down tunnel where packets are dropped. It is not worthwhile
	     to check for this rare case and affect normal path performance. */
	  if (PREDICT_FALSE (sw_if_index != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len;
	      stats_sw_if_index = sw_if_index;
	    }

	  b->error = error ? node->errors[error] : 0;

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_session_t *sess = NULL;
	      u32 sidx = 0;
	      upf_proxy_input_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));

	      /* Get next node index and adj index from tunnel next_dpo */
	      sidx = upf_buffer_opaque (b)->gtpu.session_index;
	      sess = pool_elt_at_index (gtm->sessions, sidx);
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
			   sizeof (tr->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi, next);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_proxy_input_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return upf_proxy_input (vm, node, "upf-ip4-proxy-input", from_frame,
			  /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_proxy_input_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return upf_proxy_input (vm, node, "upf-ip6-proxy-input", from_frame,
			  /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip4_proxy_input_node) = {
  .name = "upf-ip4-proxy-input",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_proxy_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_input_error_strings),
  .error_strings = upf_proxy_input_error_strings,
  .n_next_nodes = UPF_PROXY_INPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_INPUT_NEXT_DROP]             = "error-drop",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT]        = "tcp4-input-nolookup",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP] = "tcp4-input",
    [UPF_PROXY_INPUT_NEXT_TCP_FORWARD]      = "upf-tcp4-forward",
    [UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT]     = "upf-ip4-proxy-accept",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip6_proxy_input_node) = {
  .name = "upf-ip6-proxy-input",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_proxy_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_input_error_strings),
  .error_strings = upf_proxy_input_error_strings,
  .n_next_nodes = UPF_PROXY_INPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_INPUT_NEXT_DROP]             = "error-drop",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT]        = "tcp6-input-nolookup",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP] = "tcp6-input",
    [UPF_PROXY_INPUT_NEXT_TCP_FORWARD]      = "upf-tcp6-forward",
    [UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT]     = "upf-ip6-proxy-accept",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
