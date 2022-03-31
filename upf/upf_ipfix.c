/*
 * Copyright (c) 2017-2022 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Based on the VPP flowprobe plugin */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/crc32.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/error.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_local.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <upf/upf.api_enum.h>
#include <upf/upf.api_types.h>

#include "upf.h"
#include "upf_ipfix.h"

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...) \
  do { } while (0)
#endif

upf_ipfix_main_t upf_ipfix_main;
uword upf_ipfix_walker_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
				vlib_frame_t * f);

/**
 * @brief Create an IPFIX template packet rewrite string
 * @param frm flow_report_main_t *
 * @param fr flow_report_t *
 * @param collector_address ip4_address_t * the IPFIX collector address
 * @param src_address ip4_address_t * the source address we should use
 * @param collector_port u16 the collector port we should use, host byte order
 * @returns u8 * vector containing the indicated IPFIX template packet
 */
static inline u8 *
upf_ipfix_template_rewrite_inline (ipfix_exporter_t *exp, flow_report_t *fr,
				   u16 collector_port,
				   bool ip6)
{
  ip4_header_t *ip;
  udp_header_t *udp;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s;
  ipfix_template_header_t *t;
  ipfix_field_specifier_t *f;
  ipfix_field_specifier_t *first_field;
  u8 *rewrite = 0;
  ip4_ipfix_template_packet_t *tp;
  u32 field_count = 0;
  flow_report_stream_t *stream;
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  upf_ipfix_policy_t policy = (upf_ipfix_policy_t)fr->opaque.as_uword;
  upf_ipfix_template_t * template = upf_ipfix_templates + policy;
  upf_ipfix_protocol_context_t * context = upf_ipfix_context(fm, ip6, policy);

  ASSERT (template->field_count);

  stream = &exp->streams[fr->stream_index];

  field_count += template->field_count;

  /* allocate rewrite space */

  vec_validate_aligned
    (rewrite, sizeof (ip4_ipfix_template_packet_t)
     + field_count * sizeof (ipfix_field_specifier_t) - 1,
     CLIB_CACHE_LINE_BYTES);

  tp = (ip4_ipfix_template_packet_t *) rewrite;
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);
  t = (ipfix_template_header_t *) (s + 1);
  first_field = f = (ipfix_field_specifier_t *) (t + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = exp->src_address.ip.ip4.as_u32;
  ip->dst_address.as_u32 = exp->ipfix_collector.ip.ip4.as_u32;
  udp->src_port = clib_host_to_net_u16 (stream->src_port);
  udp->dst_port = clib_host_to_net_u16 (collector_port);

  /* FIXUP: message header export_time */
  /* FIXUP: message header sequence_number */
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  /* Add TLVs to the template */
  f = ip6 ? template->add_ip6_fields (f) : template->add_ip4_fields (f);

  /* Back to the template packet... */
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);

  ASSERT (f - first_field);
  /* Field count in this template */
  t->id_count = ipfix_id_count (fr->template_id, f - first_field);

  context->rec_size = (u8 *) f - (u8 *) s;

  /* set length in octets */
  s->set_id_length =
    ipfix_set_id_length (2 /* set_id */ , (u8 *) f - (u8 *) s);

  /* message length in octets */
  h->version_length = version_length ((u8 *) f - (u8 *) h);

  ip->length = clib_host_to_net_u16 ((u8 *) f - (u8 *) ip);
  upf_debug ("field bytes %u, vec_len %u", (u8 *) f - (u8 *) ip, vec_len (rewrite));
  upf_debug ("n of fields: %u, hdr size %u, part hdr size %u, "
	     "single field spec len %u",
	       field_count, sizeof (ip4_ipfix_template_packet_t),
	       sizeof (ipfix_template_packet_t),
	       sizeof (ipfix_field_specifier_t));
  ASSERT ((u8 *) f - (u8 *) ip == vec_len (rewrite));
  /* FIXME (actually, overwritten in send_template_packet() */
  udp->length = clib_host_to_net_u16 (((u8 *) f - (u8 *) ip) - sizeof (*ip));
  ip->checksum = ip4_header_checksum (ip);

  upf_debug ("rewrite: IPFIX IP hdr: %U", format_ip4_header, ip);

  return rewrite;
}

static u8 *
upf_ipfix_template_rewrite_ip6 (ipfix_exporter_t *exp, flow_report_t *fr,
				u16 collector_port,
				ipfix_report_element_t *elts, u32 n_elts,
				u32 *stream_index)
{
  return upf_ipfix_template_rewrite_inline (exp, fr, collector_port, true);
}

static u8 *
upf_ipfix_template_rewrite_ip4 (ipfix_exporter_t *exp, flow_report_t *fr,
				u16 collector_port,
				ipfix_report_element_t *elts, u32 n_elts,
				u32 *stream_index)
{
  return upf_ipfix_template_rewrite_inline (exp, fr, collector_port, false);
}

static vlib_buffer_t *
upf_ipfix_get_buffer (vlib_main_t * vm, bool ip6, upf_ipfix_policy_t policy);

static void
upf_ipfix_export_send (vlib_main_t * vm, vlib_buffer_t * b0,
		       bool ip6, upf_ipfix_policy_t policy,
		       u32 now);

static inline void
flush_record (bool ip6, u32 now)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *b;
  upf_ipfix_policy_t policy;

  for (policy = UPF_IPFIX_POLICY_NONE + 1; policy < UPF_IPFIX_N_POLICIES; policy++)
    {
      b = upf_ipfix_get_buffer (vm, ip6, policy);
      if (b)
	upf_ipfix_export_send (vm, b, ip6, policy, now);
    }
}

void
upf_ipfix_flush_callback_ip4 (u32 now)
{
  flush_record (false, now);
}

void
upf_ipfix_flush_callback_ip6 (u32 now)
{
  flush_record (true, now);
}

/**
 * @brief Flush accumulated data
 * @param frm flow_report_main_t *
 * @param fr flow_report_t *
 * @param f vlib_frame_t *
 *
 * <em>Notes:</em>
 * This function must simply return the incoming frame, or no template packets
 * will be sent.
 */
vlib_frame_t *
upf_ipfix_data_callback_ip4 (flow_report_main_t *frm, ipfix_exporter_t *exp,
			     flow_report_t *fr, vlib_frame_t *f, u32 *to_next,
			     u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 now = (u32) vlib_time_now (vm);
  upf_ipfix_flush_callback_ip4 (now);
  return f;
}

vlib_frame_t *
upf_ipfix_data_callback_ip6 (flow_report_main_t *frm, ipfix_exporter_t *exp,
			     flow_report_t *fr, vlib_frame_t *f, u32 *to_next,
			     u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 now = (u32) vlib_time_now (vm);
  upf_ipfix_flush_callback_ip6 (now);
  return f;
}

static int
upf_ipfix_template_add_del (u32 domain_id, u16 src_port,
			    upf_ipfix_policy_t policy,
			    vnet_flow_data_callback_t * flow_data_callback,
			    vnet_flow_rewrite_callback_t * rewrite_callback,
			    bool is_add, u16 * template_id)
{
  ipfix_exporter_t *exp = &flow_report_main.exporters[0];
  vnet_flow_report_add_del_args_t a = {
    .rewrite_callback = rewrite_callback,
    .flow_data_callback = flow_data_callback,
    .is_add = is_add,
    .domain_id = domain_id,
    .src_port = src_port,
    .opaque.as_uword = policy,
  };
  return vnet_flow_report_add_del (exp, &a, template_id);
}

static void upf_ipfix_export_entry (vlib_main_t * vm, flow_entry_t * f, flow_direction_t direction, u32 now);

/* TBD: add trace */

static u16
upf_ipfix_get_headersize (void)
{
  return sizeof (ip4_header_t) + sizeof (udp_header_t) +
    sizeof (ipfix_message_header_t) + sizeof (ipfix_set_header_t);
}

static void
upf_ipfix_export_send (vlib_main_t * vm, vlib_buffer_t * b0,
		       bool ip6, upf_ipfix_policy_t policy,
		       u32 now)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  flow_report_main_t *frm = &flow_report_main;
  ipfix_exporter_t *exp = pool_elt_at_index (frm->exporters, 0);
  vlib_frame_t *f;
  ip4_ipfix_template_packet_t *tp;
  ipfix_set_header_t *s;
  ipfix_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  u32 my_cpu_number = vm->thread_index;
  upf_ipfix_protocol_context_t * context = upf_ipfix_context(fm, ip6, policy);

  /* Fill in header */
  flow_report_stream_t *stream;

  /* Nothing to send */
  if (context->next_record_offset_per_worker[my_cpu_number] <=
      upf_ipfix_get_headersize ())
    return;

  upf_debug ("export send [%s], policy %u",
	     ip6 ? "ip6" : "ip4",
	     policy);

  u32 i, index = vec_len (exp->streams);
  for (i = 0; i < index; i++)
    if (exp->streams[i].domain_id == 1)
      {
	index = i;
	break;
      }
  if (i == vec_len (exp->streams))
    {
      vec_validate (exp->streams, index);
      exp->streams[index].domain_id = 1;
    }
  stream = &exp->streams[index];

  tp = vlib_buffer_get_current (b0);
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->flags_and_fragment_offset = 0;
  ip->src_address.as_u32 = exp->src_address.ip.ip4.as_u32;
  ip->dst_address.as_u32 = exp->ipfix_collector.ip.ip4.as_u32;
  udp->src_port = clib_host_to_net_u16 (stream->src_port);
  udp->dst_port = clib_host_to_net_u16 (exp->collector_port);
  udp->checksum = 0;

  /* FIXUP: message header export_time */
  h->export_time = now - frm->vlib_time_0;
  h->export_time = clib_host_to_net_u32 (h->export_time + frm->unix_time_0);
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  /* FIXUP: message header sequence_number */
  h->sequence_number = stream->sequence_number++;
  h->sequence_number = clib_host_to_net_u32 (h->sequence_number);

  s->set_id_length = ipfix_set_id_length (context->template_id,
					  b0->current_length -
					  (sizeof (*ip) + sizeof (*udp) +
					   sizeof (*h)));
  h->version_length = version_length (b0->current_length -
				      (sizeof (*ip) + sizeof (*udp)));

  ip->length = clib_host_to_net_u16 (b0->current_length);

  ip->checksum = ip4_header_checksum (ip);
  udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

  if (exp->udp_checksum)
    {
      /* RFC 7011 section 10.3.2. */
      udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
      if (udp->checksum == 0)
	udp->checksum = 0xffff;
    }

  ASSERT (ip4_header_checksum_is_valid (ip));

  /* Find or allocate a frame */
  f = context->frames_per_worker[my_cpu_number];
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      context->frames_per_worker[my_cpu_number] = f;
      u32 bi0 = vlib_get_buffer_index (vm, b0);

      /* Enqueue the buffer */
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  upf_debug ("sending: IP hdr: %U", format_ip4_header,
	     vlib_buffer_get_current (b0), b0->current_length);

  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

  context->frames_per_worker[my_cpu_number] = 0;
  context->buffers_per_worker[my_cpu_number] = 0;
  context->next_record_offset_per_worker[my_cpu_number] =
    upf_ipfix_get_headersize ();
}

static vlib_buffer_t *
upf_ipfix_get_buffer (vlib_main_t * vm, bool ip6, upf_ipfix_policy_t policy)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  ipfix_exporter_t *exp = pool_elt_at_index (flow_report_main.exporters, 0);
  vlib_buffer_t *b0;
  u32 bi0;
  u32 my_cpu_number = vm->thread_index;
  upf_ipfix_protocol_context_t * context = upf_ipfix_context(fm, ip6, policy);

  /* Find or allocate a buffer */
  b0 = context->buffers_per_worker[my_cpu_number];

  /* Need to allocate a buffer? */
  if (PREDICT_FALSE (b0 == 0))
    {
      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	  return 0;

      /* Initialize the buffer */
      b0 = context->buffers_per_worker[my_cpu_number] =
	vlib_get_buffer (vm, bi0);

      b0->current_data = 0;
      b0->current_length = upf_ipfix_get_headersize ();
      b0->flags |=
	(VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_FLOW_REPORT);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = exp->fib_index;
      context->next_record_offset_per_worker[my_cpu_number] =
	b0->current_length;
    }

  return b0;
}

static void
upf_ipfix_export_entry (vlib_main_t * vm, flow_entry_t * f, flow_direction_t direction, u32 now)
{
  u32 my_cpu_number = vm->thread_index;
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  /* ipfix_exporter_t *exp = pool_elt_at_index (flow_report_main.exporters, 0); */
  vlib_buffer_t *b0;
  bool ip6 = !ip46_address_is_ip4 (&f->key.ip[FT_ORIGIN]);
  upf_main_t *gtm = &upf_main;
  upf_ipfix_policy_t policy = f->ipfix_policy;
  upf_ipfix_protocol_context_t * context;
  u16 offset;
  upf_ipfix_template_t * template;
  upf_session_t *sx;

  /* FIXME: need to process IPFIX during session deletion */
  if (policy == UPF_IPFIX_POLICY_NONE ||
      pool_is_free_index (gtm->sessions, f->session_index))
    return;

  context = upf_ipfix_context (fm, ip6, policy);
  offset = context->next_record_offset_per_worker[my_cpu_number];
  template = upf_ipfix_templates + policy;
  sx = pool_elt_at_index (gtm->sessions, f->session_index);

  upf_debug ("export entry [%s], policy %u",
	     ip6 ? "ip6" : "ip4",
	     policy);
  if (offset < upf_ipfix_get_headersize ())
    offset = upf_ipfix_get_headersize ();

  b0 = upf_ipfix_get_buffer (vm, ip6, policy);
  /* No available buffer, what to do... */
  if (b0 == 0)
    {
      upf_debug ("no buffer");
      return;
    }

  if (ip6)
    offset += template->add_ip6_values (b0, f, direction, offset, sx);
  else
    offset += template->add_ip4_values (b0, f, direction, offset, sx);

  /* Reset per flow-export counters */
  // TBD: reset delta stats
  /* e->packetcount = 0; */
  /* e->octetcount = 0; */
  flow_last_exported(f, direction) = now;

  b0->current_length = offset;

  context->next_record_offset_per_worker[my_cpu_number] = offset;
  /* Time to flush the buffer? */
  /* TODO uncomment! also: force upon removal */
  /* if (offset + context->rec_size > exp->path_mtu) */
  upf_ipfix_export_send (vm, b0, ip6, policy, now);
}

#define vec_neg_search(v,E)			\
  ({						\
    word _v(i) = 0;				\
    while (_v(i) < vec_len(v) && v[_v(i)] == E)	\
      {						\
	_v(i)++;				\
      }						\
    if (_v(i) == vec_len(v))			\
      _v(i) = ~0;				\
    _v(i);					\
  })

static int upf_ipfix_template_register (upf_ipfix_main_t *fm, upf_ipfix_policy_t policy)
{
  int rv = 0;
  u16 template_id_ip4 = 0, template_id_ip6 = 0;

  rv = upf_ipfix_template_add_del (1, UDP_DST_PORT_ipfix,
				   policy,
				   upf_ipfix_data_callback_ip4,
				   upf_ipfix_template_rewrite_ip4,
				   1 /* is_add */, &template_id_ip4);
  if (!rv)
    rv = upf_ipfix_template_add_del (1, UDP_DST_PORT_ipfix,
				     policy,
				     upf_ipfix_data_callback_ip6,
				     upf_ipfix_template_rewrite_ip6,
				     1 /* is_add */, &template_id_ip6);
  if (rv && rv != VNET_API_ERROR_VALUE_EXIST)
    {
      clib_warning ("vnet_flow_report_add_del returned %d", rv);
      return -1;
    }

  fm->runtime_templates[policy].context_ip4.template_id = template_id_ip4;
  fm->runtime_templates[policy].context_ip6.template_id = template_id_ip6;

  return 0;
}

void upf_ipfix_flow_update_hook (flow_entry_t * f, flow_direction_t direction, u32 now)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  vlib_main_t *vm = fm->vlib_main;

  if (fm->disabled)
      return;

  if (fm->active_timer == 0
      || (now > flow_last_exported(f, direction) + fm->active_timer))
    upf_ipfix_export_entry (vm, f, direction, now);
}

void upf_ipfix_flow_removal_hook (flow_entry_t * f, u32 now)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  vlib_main_t *vm = fm->vlib_main;

  if (fm->disabled)
    return;

  upf_ipfix_export_entry (vm, f, FT_ORIGIN, now);
  upf_ipfix_export_entry (vm, f, FT_REVERSE, now);
}

/**
 * @brief Set up the API message handling tables
 * @param vm vlib_main_t * vlib main data structure pointer
 * @returns 0 to indicate all is well, or a clib_error_t
 */
clib_error_t *
upf_ipfix_init (vlib_main_t * vm)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  vlib_thread_main_t *tm = &vlib_thread_main;
  clib_error_t *error = 0;
  u32 num_threads;
  upf_ipfix_policy_t policy;

  fm->vnet_main = vnet_get_main ();
  fm->vlib_main = vm; /* FIXME: shouldn't need that */

  /* Set up time reference pair */
  fm->vlib_time_0 = (u32)vlib_time_now (vm);

  clib_memset (fm->runtime_templates, 0, sizeof (fm->runtime_templates));

  /* Decide how many worker threads we have */
  num_threads = 1 /* main thread */  + tm->n_threads;

  /* Allocate per worker thread vectors per flavour */
  for (policy = UPF_IPFIX_POLICY_NONE+1; policy < UPF_IPFIX_N_POLICIES; policy++)
    {
      upf_ipfix_runtime_template_t * rt = fm->runtime_templates + policy;
      vec_validate (rt->context_ip4.buffers_per_worker, num_threads - 1);
      vec_validate (rt->context_ip4.frames_per_worker, num_threads - 1);
      vec_validate (rt->context_ip4.next_record_offset_per_worker,
		    num_threads - 1);
      vec_validate (rt->context_ip6.buffers_per_worker, num_threads - 1);
      vec_validate (rt->context_ip6.frames_per_worker, num_threads - 1);
      vec_validate (rt->context_ip6.next_record_offset_per_worker,
		    num_threads - 1);
      if (upf_ipfix_template_register (fm, policy) != 0)
	error = clib_error_return (0, "error adding IPFIX templates");
   }

  fm->active_timer = UPF_IPFIX_TIMER_ACTIVE;

  flow_update_hook = upf_ipfix_flow_update_hook;
  flow_removal_hook = upf_ipfix_flow_removal_hook;

  return error;
}

upf_ipfix_policy_t
upf_ipfix_lookup_policy (u8 * name, bool * ok)
{
  upf_ipfix_policy_t policy;
  u32 name_len = vec_len (name);

  if (ok)
    *ok = false;

  for (policy = UPF_IPFIX_POLICY_NONE+1; policy < UPF_IPFIX_N_POLICIES; policy++)
    {
      u32 l = strlen(upf_ipfix_templates[policy].name);
      if (l == name_len && !memcmp(name, upf_ipfix_templates[policy].name, l))
	{
	  if (ok)
	    *ok = true;
	  return policy;
	}
    }

  /* avoid silently ignoring the error */
  if (!ok)
    clib_warning("Bad IPFIX policy: %v", name);

  return UPF_IPFIX_POLICY_NONE;
}

uword unformat_ipfix_policy (unformat_input_t * i, va_list * args)
{
  bool ok;
  upf_ipfix_policy_t *policy = va_arg (*args, upf_ipfix_policy_t *);
  u8 * name;

  if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
    return 0;

  if (!unformat (i, "%_%v%_", &name))
    return 0;

  *policy = upf_ipfix_lookup_policy (name, &ok);
  if (!ok)
    return 0;

  return 1;
}

u8 *format_upf_ipfix_policy (u8 * s, va_list * args)
{
  upf_ipfix_policy_t policy = va_arg (*args, upf_ipfix_policy_t);
  return policy < UPF_IPFIX_N_POLICIES ?
    format (s, "%s", upf_ipfix_templates[policy].name) :
    format (s, "<unknown %u>", policy);
}
