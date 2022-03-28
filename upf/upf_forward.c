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
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_path_list.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/upf_proxy.h>

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)				\
  do { } while (0)
#endif

/* Statistics (not all errors) */
#define foreach_upf_forward_error				\
  _(LENGTH, "inconsistent ip/tcp lengths")			\
  _(NO_LISTENER, "no redirect server available")		\
  _(FORWARD, "good packets forward")				\
  _(OPTIONS, "Could not parse options")				\
  _(CREATE_SESSION_FAIL, "Sessions couldn't be allocated")

static char *upf_forward_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_forward_error
#undef _
};

typedef enum
{
#define _(sym,str) UPF_FORWARD_ERROR_##sym,
  foreach_upf_forward_error
#undef _
    UPF_FORWARD_N_ERROR,
} upf_forward_error_t;

typedef struct
{
  u32 session_index;
  u64 cp_seid;
  u32 pdr_id;
  u32 far_id;
  u8 packet_data[64 - 1 * sizeof (u32)];
}
upf_forward_trace_t;

static u8 *
format_upf_forward_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_forward_trace_t *t = va_arg (*args, upf_forward_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session%d cp-seid 0x%016" PRIx64 " pdr %d far %d\n%U%U",
	      t->session_index, t->cp_seid, t->pdr_id, t->far_id,
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static uword
upf_forward (vlib_main_t * vm, vlib_node_runtime_t * node,
	     const char *node_name, vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *gtm = &upf_main;
  vnet_main_t *vnm = gtm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  timestamp_nsec_t timestamp;
  u32 current_time = (u32) vlib_time_now (vm);
  flowtable_main_t *fm = &flowtable_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 sw_if_index = 0;
  u32 next = 0;
  upf_session_t *sess = NULL;
  u32 sidx = 0;
  u32 len;
  struct rules *active;

  upf_forwarding_policy_t *fp_entry;

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
      flow_entry_t *flow;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  upf_pdr_t *pdr = NULL;
	  upf_far_t *far = NULL;

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

	  error = 0;
	  next = UPF_FORWARD_NEXT_DROP;
	  active = pfcp_get_rules (sess, PFCP_ACTIVE);

	  if (PREDICT_TRUE (upf_buffer_opaque (b)->gtpu.pdr_idx != ~0))
	    {
	      pdr =
		vec_elt_at_index (active->pdr,
				  upf_buffer_opaque (b)->gtpu.pdr_idx);
	      far = pfcp_get_far_by_id (active, pdr->far_id);
	    }

	  if (is_ip4)
	    {
	      upf_debug ("IP hdr: %U", format_ip4_header,
			 vlib_buffer_get_current (b), b->current_length);
	    }
	  else
	    {
	      upf_debug ("IP hdr: %U", format_ip6_header,
			 vlib_buffer_get_current (b), b->current_length);
	    }

	  if (PREDICT_FALSE (!pdr) || PREDICT_FALSE (!far))
	    goto stats;

	  upf_debug ("PDR: %u, FAR: %u", pdr->id, far->id);

	  if (PREDICT_TRUE (far->apply_action & FAR_FORWARD))
	    {
	      if (far->forward.flags & FAR_F_OUTER_HEADER_CREATION)
		{
		  upf_debug ("OUTER HEADER CREATION");
		  if (far->forward.outer_header_creation.description
		      & OUTER_HEADER_CREATION_GTP_IP4)
		    {
		      next = UPF_FORWARD_NEXT_GTP_IP4_ENCAP;
		    }
		  else if (far->forward.outer_header_creation.description
			   & OUTER_HEADER_CREATION_GTP_IP6)
		    {
		      next = UPF_FORWARD_NEXT_GTP_IP6_ENCAP;
		    }
		  else if (far->forward.outer_header_creation.description
			   & OUTER_HEADER_CREATION_UDP_IP4)
		    {
		      next = UPF_FORWARD_NEXT_DROP;
		      // error = UPF_FORWARD_ERROR_NOT_YET;
		      goto trace;
		    }
		  else if (far->forward.outer_header_creation.description
			   & OUTER_HEADER_CREATION_UDP_IP6)
		    {
		      next = UPF_FORWARD_NEXT_DROP;
		      // error = UPF_FORWARD_ERROR_NOT_YET;
		      goto trace;
		    }
		}
	      else
		{
		  if (is_ip4)
		    {
		      b->flags &= ~(VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
				    VNET_BUFFER_OFFLOAD_F_UDP_CKSUM |
				    VNET_BUFFER_OFFLOAD_F_IP_CKSUM);
		      upf_nwi_if_and_fib_index
			(gtm, FIB_PROTOCOL_IP4, far->forward.nwi_index,
			 &vnet_buffer (b)->sw_if_index[VLIB_RX],
			 &vnet_buffer (b)->sw_if_index[VLIB_TX]);
		    }
		  else
		    {
		      b->flags &= ~(VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
				    VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
		      upf_nwi_if_and_fib_index
			(gtm, FIB_PROTOCOL_IP6, far->forward.nwi_index,
			 &vnet_buffer (b)->sw_if_index[VLIB_RX],
			 &vnet_buffer (b)->sw_if_index[VLIB_TX]);
		    }
		  next = UPF_FORWARD_NEXT_IP_INPUT;

		  /*
		   * Forwarding Policy can override the normal FAR processing from above
		   */

		  if (far->forward.flags & FAR_F_FORWARDING_POLICY)
		    {
		      fib_route_path_t *rpath;

		      /* Getting dpio_index */
		      fp_entry =
			pool_elt_at_index (gtm->upf_forwarding_policies,
					   far->forward.fp_pool_index);

		      /*
		       * the Forwarding Policy might not contain an entry
		       * for the IP version of the buffer. In that case, the
		       * loop will just not alter already resent normal FAR
		       * settings.
		       */
		      vec_foreach (rpath, fp_entry->rpaths)
		      {
			if (rpath->frp_proto ==
			    (is_ip4 ? DPO_PROTO_IP4 : DPO_PROTO_IP6))
			  {
			    vnet_buffer (b)->sw_if_index[VLIB_TX] =
			      rpath->frp_fib_index;
			    next = UPF_FORWARD_NEXT_IP_LOOKUP;
			    upf_debug
			      ("###### Forwarding policy with id %v is applied ######",
			       far->forward.forwarding_policy.identifier);
			    break;
			  }
		      }
		    }
		}
	    }
	  else if (far->apply_action & FAR_BUFFER)
	    {
	      next = UPF_FORWARD_NEXT_DROP;
	      // error = UPF_FORWARD_ERROR_NOT_YET;
	    }
	  else
	    {
	      next = UPF_FORWARD_NEXT_DROP;
	    }

#define IS_DL(_pdr, _far)						\
	  ((_pdr)->pdi.src_intf == SRC_INTF_CORE || (_far)->forward.dst_intf == DST_INTF_ACCESS)
#define IS_UL(_pdr, _far)						\
	  ((_pdr)->pdi.src_intf == SRC_INTF_ACCESS || (_far)->forward.dst_intf == DST_INTF_CORE)

	  if (!(upf_buffer_opaque (b)->gtpu.flags & BUFFER_FAR_ONLY))
	    {
	      upf_debug ("pdr: %d, far: %d\n", pdr->id, far->id);
	      next = process_qers (vm, sess, active, pdr, b,
				   IS_DL (pdr, far), IS_UL (pdr, far), next);
	      next = process_urrs (vm, sess, node_name, active, pdr, b,
				   IS_DL (pdr, far), IS_UL (pdr, far), next);
	      flow =
		pool_elt_at_index (fm->flows,
				   upf_buffer_opaque (b)->gtpu.flow_id);
	      flow_update_stats (vm, b, flow, is_ip4,
				 timestamp, current_time);
	    }

#undef IS_DL
#undef IS_UL

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

	trace:
	  b->error = error ? node->errors[error] : 0;

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_forward_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
	      tr->pdr_id = pdr ? pdr->id : ~0;
	      tr->far_id = far ? far->id : ~0;
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

VLIB_NODE_FN (upf_ip4_forward_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  return upf_forward (vm, node, "upf-ip4-forward", from_frame,	/* is_ip4 */
		      1);
}

VLIB_NODE_FN (upf_ip6_forward_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  return upf_forward (vm, node, "upf-ip6-forward", from_frame,	/* is_ip4 */
		      0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip4_forward_node) = {
  .name = "upf-ip4-forward",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_forward_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_forward_error_strings),
  .error_strings = upf_forward_error_strings,
  .n_next_nodes = UPF_FORWARD_N_NEXT,
  .next_nodes = {
    [UPF_FORWARD_NEXT_DROP]          = "error-drop",
    [UPF_FORWARD_NEXT_GTP_IP4_ENCAP] = "upf4-encap",
    [UPF_FORWARD_NEXT_GTP_IP6_ENCAP] = "upf6-encap",
    [UPF_FORWARD_NEXT_IP_INPUT]      = "ip4-input",
    [UPF_FORWARD_NEXT_IP_REWRITE]    = "ip4-rewrite",
    [UPF_FORWARD_NEXT_IP_LOOKUP]     = "ip4-lookup"
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip6_forward_node) = {
  .name = "upf-ip6-forward",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_forward_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_forward_error_strings),
  .error_strings = upf_forward_error_strings,
  .n_next_nodes = UPF_FORWARD_N_NEXT,
  .next_nodes = {
    [UPF_FORWARD_NEXT_DROP]          = "error-drop",
    [UPF_FORWARD_NEXT_GTP_IP4_ENCAP] = "upf4-encap",
    [UPF_FORWARD_NEXT_GTP_IP6_ENCAP] = "upf6-encap",
    [UPF_FORWARD_NEXT_IP_INPUT]      = "ip6-input",
    [UPF_FORWARD_NEXT_IP_REWRITE]    = "ip6-rewrite",
    [UPF_FORWARD_NEXT_IP_LOOKUP]     = "ip6-lookup"
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
