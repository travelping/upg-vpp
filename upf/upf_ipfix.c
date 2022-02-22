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
// #include <vpp/app/version.h>
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
#define upf_debug(...)				\
  do { } while (0)
#endif

upf_ipfix_main_t upf_ipfix_main;
// static vlib_node_registration_t upf_ipfix_timer_node;
uword upf_ipfix_walker_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
				vlib_frame_t * f);

#define REPLY_MSG_ID_BASE fm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* Macro to finish up custom dump fns */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define FINISH                                  \
  vec_add1 (s, 0);				\
  vl_print (handle, (char *)s);			\
  vec_free (s);					\
  return handle;

static inline ipfix_field_specifier_t *
upf_ipfix_template_ip4_fields (ipfix_field_specifier_t * f)
{
#define upf_ipfix_template_ip4_field_count() 4
  /* sourceIpv4Address, TLV type 8, u32 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      sourceIPv4Address, 4);
  f++;
  /* destinationIPv4Address, TLV type 12, u32 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      destinationIPv4Address, 4);
  f++;
  /* protocolIdentifier, TLV type 4, u8 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      protocolIdentifier, 1);
  f++;
  /* octetTotalCount, TLV type 85, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      octetTotalCount, 8);
  f++;
  return f;
}

static inline ipfix_field_specifier_t *
upf_ipfix_template_ip6_fields (ipfix_field_specifier_t * f)
{
#define upf_ipfix_template_ip6_field_count() 4
  /* sourceIpv6Address, TLV type 27, 16 octets */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      sourceIPv6Address, 16);
  f++;
  /* destinationIPv6Address, TLV type 28, 16 octets */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      destinationIPv6Address, 16);
  f++;
  /* protocolIdentifier, TLV type 4, u8 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      protocolIdentifier, 1);
  f++;
  /* octetTotalCount, TLV type 85, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      octetTotalCount, 8);
  f++;
  return f;
}

/* static inline ipfix_field_specifier_t * */
/* upf_ipfix_template_l2_fields (ipfix_field_specifier_t * f) */
/* { */
/* #define upf_ipfix_template_l2_field_count() 3 */
/*   /\* sourceMacAddress, TLV type 56, u8[6] we hope *\/ */
/*   f->e_id_length = ipfix_e_id_length (0 /\* enterprise *\/ , */
/* 				      sourceMacAddress, 6); */
/*   f++; */
/*   /\* destinationMacAddress, TLV type 80, u8[6] we hope *\/ */
/*   f->e_id_length = ipfix_e_id_length (0 /\* enterprise *\/ , */
/* 				      destinationMacAddress, 6); */
/*   f++; */
/*   /\* ethernetType, TLV type 256, u16 *\/ */
/*   f->e_id_length = ipfix_e_id_length (0 /\* enterprise *\/ , */
/* 				      ethernetType, 2); */
/*   f++; */
/*   return f; */
/* } */

static inline ipfix_field_specifier_t *
upf_ipfix_template_common_fields (ipfix_field_specifier_t * f)
{
#define upf_ipfix_template_common_field_count() 4 // 6
  /* /\* ingressInterface, TLV type 10, u32 *\/ */
  /* f->e_id_length = ipfix_e_id_length (0 /\* enterprise *\/ , */
  /* 				      ingressInterface, 4); */
  /* f++; */

  /* /\* egressInterface, TLV type 14, u32 *\/ */
  /* f->e_id_length = ipfix_e_id_length (0 /\* enterprise *\/ , */
  /* 				      egressInterface, 4); */
  /* f++; */

  /* mobileIMSI, TLV type 455, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      455, 65535);
  f++;

  /* packetTotalCount, TLV type 86, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      packetTotalCount, 8);
  f++;

  /* flowStartNanoseconds, TLV type 156, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      flowStartNanoseconds, 8);
  f++;

  /* flowEndNanoseconds, TLV type 157, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      flowEndNanoseconds, 8);
  f++;

  return f;
}

static inline ipfix_field_specifier_t *
upf_ipfix_template_l4_fields (ipfix_field_specifier_t * f)
{
#define upf_ipfix_template_l4_field_count() 2 // 3
  /* sourceTransportPort, TLV type 7, u16 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      sourceTransportPort, 2);
  f++;
  /* destinationTransportPort, TLV type 11, u16 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      destinationTransportPort, 2);
  f++;
  /* /\* tcpControlBits, TLV type 6, u16 *\/ */
  /* f->e_id_length = ipfix_e_id_length (0 /\* enterprise *\/ , */
  /* 				      tcpControlBits, 2); */
  /* f++; */

  return f;
}

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
				   upf_ipfix_variant_t which)
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
  upf_ipfix_record_t flags = fr->opaque.as_uword;
  bool collect_ip4 = false, collect_ip6 = false;

  stream = &exp->streams[fr->stream_index];

  if (flags & FLOW_RECORD_L3)
    {
      collect_ip4 = which == FLOW_VARIANT_L2_IP4 || which == FLOW_VARIANT_IP4;
      collect_ip6 = which == FLOW_VARIANT_L2_IP6 || which == FLOW_VARIANT_IP6;
      if (which == FLOW_VARIANT_L2_IP4)
	flags |= FLOW_RECORD_L2_IP4;
      if (which == FLOW_VARIANT_L2_IP6)
	flags |= FLOW_RECORD_L2_IP6;
    }

  field_count += upf_ipfix_template_common_field_count ();
  /* if (flags & FLOW_RECORD_L2) */
  /*   field_count += upf_ipfix_template_l2_field_count (); */
  if (collect_ip4)
    field_count += upf_ipfix_template_ip4_field_count ();
  if (collect_ip6)
    field_count += upf_ipfix_template_ip6_field_count ();
  if (flags & FLOW_RECORD_L4)
    field_count += upf_ipfix_template_l4_field_count ();

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
  f = upf_ipfix_template_common_fields (f);

  /* if (flags & FLOW_RECORD_L2) */
  /*   f = upf_ipfix_template_l2_fields (f); */
  if (collect_ip4)
    f = upf_ipfix_template_ip4_fields (f);
  if (collect_ip6)
    f = upf_ipfix_template_ip6_fields (f);
  if (flags & FLOW_RECORD_L4)
    f = upf_ipfix_template_l4_fields (f);

  /* Back to the template packet... */
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);

  ASSERT (f - first_field);
  /* Field count in this template */
  t->id_count = ipfix_id_count (fr->template_id, f - first_field);

  fm->template_size[flags] = (u8 *) f - (u8 *) s;

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
  return upf_ipfix_template_rewrite_inline (exp, fr, collector_port,
					    FLOW_VARIANT_IP6);
}

static u8 *
upf_ipfix_template_rewrite_ip4 (ipfix_exporter_t *exp, flow_report_t *fr,
				u16 collector_port,
				ipfix_report_element_t *elts, u32 n_elts,
				u32 *stream_index)
{
  return upf_ipfix_template_rewrite_inline (exp, fr, collector_port,
					    FLOW_VARIANT_IP4);
}

/* static u8 * */
/* upf_ipfix_template_rewrite_l2 (ipfix_exporter_t *exp, flow_report_t *fr, */
/* 			       u16 collector_port, */
/* 			       ipfix_report_element_t *elts, u32 n_elts, */
/* 			       u32 *stream_index) */
/* { */
/*   return upf_ipfix_template_rewrite_inline (exp, fr, collector_port, */
/* 					    FLOW_VARIANT_L2); */
/* } */

/* static u8 * */
/* upf_ipfix_template_rewrite_l2_ip4 (ipfix_exporter_t *exp, flow_report_t *fr, */
/* 				   u16 collector_port, */
/* 				   ipfix_report_element_t *elts, u32 n_elts, */
/* 				   u32 *stream_index) */
/* { */
/*   return upf_ipfix_template_rewrite_inline (exp, fr, collector_port, */
/* 					    FLOW_VARIANT_L2_IP4); */
/* } */

/* static u8 * */
/* upf_ipfix_template_rewrite_l2_ip6 (ipfix_exporter_t *exp, flow_report_t *fr, */
/* 				   u16 collector_port, */
/* 				   ipfix_report_element_t *elts, u32 n_elts, */
/* 				   u32 *stream_index) */
/* { */
/*   return upf_ipfix_template_rewrite_inline (exp, fr, collector_port, */
/* 					    FLOW_VARIANT_L2_IP6); */
/* } */

static vlib_buffer_t *
upf_ipfix_get_buffer (vlib_main_t * vm, upf_ipfix_variant_t which);

static void
upf_ipfix_export_send (vlib_main_t * vm, vlib_buffer_t * b0,
		       upf_ipfix_variant_t which,
		       u32 now);

static inline void
flush_record (upf_ipfix_variant_t which, u32 now)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *b = upf_ipfix_get_buffer (vm, which);
  if (b)
    upf_ipfix_export_send (vm, b, which, now);
}

void
upf_ipfix_flush_callback_ip4 (u32 now)
{
  flush_record (FLOW_VARIANT_IP4, now);
}

void
upf_ipfix_flush_callback_ip6 (u32 now)
{
  flush_record (FLOW_VARIANT_IP6, now);
}

/* void */
/* upf_ipfix_flush_callback_l2 (void) */
/* { */
/*   flush_record (FLOW_VARIANT_L2); */
/*   flush_record (FLOW_VARIANT_L2_IP4); */
/*   flush_record (FLOW_VARIANT_L2_IP6); */
/* } */

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

/* vlib_frame_t * */
/* upf_ipfix_data_callback_l2 (flow_report_main_t *frm, ipfix_exporter_t *exp, */
/* 			    flow_report_t *fr, vlib_frame_t *f, u32 *to_next, */
/* 			    u32 node_index) */
/* { */
/*   upf_ipfix_flush_callback_l2 (); */
/*   return f; */
/* } */

static int
upf_ipfix_template_add_del (u32 domain_id, u16 src_port,
			    upf_ipfix_record_t flags,
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
    .opaque.as_uword = flags,
  };
  return vnet_flow_report_add_del (exp, &a, template_id);
}

static void upf_ipfix_export_entry (vlib_main_t * vm, flow_entry_t * f, flow_direction_t direction, u32 now);

/*
 * NTP rfc868 : 2 208 988 800 corresponds to 00:00  1 Jan 1970 GMT
 */
#define NTP_TIMESTAMP 2208988800LU

static inline u32
upf_ipfix_common_add (vlib_buffer_t * to_b, flow_entry_t * f, flow_direction_t direction,
		      u16 offset)
{
  u16 start = offset;
  upf_main_t *gtm = &upf_main;
  upf_session_t *sx = pool_elt_at_index (gtm->sessions, f->session_index);

  /* mobileIMSI */
  /* the value can't be 255 or more due to limitations of pfcp.c, */
  /* thus we use simpler encoding */
  to_b->data[offset] = sx->imsi_len;
  clib_memcpy_fast (to_b->data + offset + 1, sx->imsi, sx->imsi_len);
  offset += sx->imsi_len + 1;

  /* packet total count */
  u64 total_packets = clib_host_to_net_u64 (flow_stats(f, direction).pkts);
  clib_memcpy_fast (to_b->data + offset, &total_packets, sizeof (u64));
  offset += sizeof (u64);

  /* flowStartNanoseconds */
  u32 t = clib_host_to_net_u32 (f->flow_start.sec + NTP_TIMESTAMP);
  clib_memcpy_fast (to_b->data + offset, &t, sizeof (u32));
  offset += sizeof (u32);
  t = clib_host_to_net_u32 (f->flow_start.nsec);
  clib_memcpy_fast (to_b->data + offset, &t, sizeof (u32));
  offset += sizeof (u32);

  /* flowEndNanoseconds */
  t = clib_host_to_net_u32 (f->flow_end.sec + NTP_TIMESTAMP);
  clib_memcpy_fast (to_b->data + offset, &t, sizeof (u32));
  offset += sizeof (u32);
  t = clib_host_to_net_u32 (f->flow_end.nsec);
  clib_memcpy_fast (to_b->data + offset, &t, sizeof (u32));
  offset += sizeof (u32);

  return offset - start;
}

static inline u32
upf_ipfix_l3_ip6_add (vlib_buffer_t * to_b, flow_entry_t * f, flow_direction_t direction, u16 offset)
{
  u16 start = offset;

  /* ip6 src address */
  clib_memcpy_fast (to_b->data + offset, &f->key.ip[FT_ORIGIN ^ f->is_reverse ^ direction].ip6,
		    sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* ip6 dst address */
  clib_memcpy_fast (to_b->data + offset, &f->key.ip[FT_REVERSE ^ f->is_reverse ^ direction].ip6,
		    sizeof (ip6_address_t));
  offset += sizeof (ip6_address_t);

  /* Protocol */
  to_b->data[offset++] = f->key.proto;

  /* octetTotalCount */
  u64 total_octets = clib_host_to_net_u64 (flow_stats(f, direction).bytes);
  clib_memcpy_fast (to_b->data + offset, &total_octets, sizeof (u64));
  offset += sizeof (u64);

  return offset - start;
}

static inline u32
upf_ipfix_l3_ip4_add (vlib_buffer_t * to_b, flow_entry_t * f, flow_direction_t direction, u16 offset)
{
  u16 start = offset;

  /* ip4 src address */
  clib_memcpy_fast (to_b->data + offset, &f->key.ip[FT_ORIGIN ^ f->is_reverse ^ direction].ip4,
		    sizeof (ip4_address_t));
  offset += sizeof (ip4_address_t);

  /* ip4 dst address */
  clib_memcpy_fast (to_b->data + offset, &f->key.ip[FT_REVERSE ^ f->is_reverse ^ direction].ip4,
		    sizeof (ip4_address_t));
  offset += sizeof (ip4_address_t);

  /* Protocol */
  to_b->data[offset++] = f->key.proto;

  /* octetTotalCount */
  u64 total_octets = clib_host_to_net_u64 (flow_stats(f, direction).bytes);
  clib_memcpy_fast (to_b->data + offset, &total_octets, sizeof (u64));
  offset += sizeof (u64);

  return offset - start;
}

static inline u32
upf_ipfix_l4_add (vlib_buffer_t * to_b, flow_entry_t * f, flow_direction_t direction, u16 offset)
{
  u16 start = offset;

  /* src port */
  clib_memcpy_fast (to_b->data + offset, &f->key.port[FT_ORIGIN ^ f->is_reverse ^ direction], 2);
  offset += 2;

  /* dst port */
  clib_memcpy_fast (to_b->data + offset, &f->key.port[FT_REVERSE ^ f->is_reverse ^ direction], 2);
  offset += 2;

  /* /\* tcp control bits *\/ */
  /* u16 control_bits = htons (e->prot.tcp.flags); */
  /* clib_memcpy_fast (to_b->data + offset, &control_bits, 2); */
  /* offset += 2; */

  return offset - start;
}

/* TBD: add trace */

static u16
upf_ipfix_get_headersize (void)
{
  return sizeof (ip4_header_t) + sizeof (udp_header_t) +
    sizeof (ipfix_message_header_t) + sizeof (ipfix_set_header_t);
}

static void
upf_ipfix_export_send (vlib_main_t * vm, vlib_buffer_t * b0,
		       upf_ipfix_variant_t which,
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
  upf_ipfix_record_t flags = fm->context[which].flags;
  u32 my_cpu_number = vm->thread_index;

  /* Fill in header */
  flow_report_stream_t *stream;

  /* Nothing to send */
  if (fm->context[which].next_record_offset_per_worker[my_cpu_number] <=
      upf_ipfix_get_headersize ())
    return;

  upf_debug ("export send, flow variant %s",
	     which == FLOW_VARIANT_IP4 ? "ip4" :
	     which == FLOW_VARIANT_IP6 ? "ip6" : "...");

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

  s->set_id_length = ipfix_set_id_length (fm->template_reports[flags],
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
  f = fm->context[which].frames_per_worker[my_cpu_number];
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      fm->context[which].frames_per_worker[my_cpu_number] = f;
      u32 bi0 = vlib_get_buffer_index (vm, b0);

      /* Enqueue the buffer */
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  upf_debug ("sending: IP hdr: %U", format_ip4_header,
	     vlib_buffer_get_current (b0), b0->current_length);

  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
  /* vlib_node_increment_counter (vm, upf_ipfix_l2_node.index, */
  /* 			       UPF_IPFIX_ERROR_EXPORTED_PACKETS, 1); */

  fm->context[which].frames_per_worker[my_cpu_number] = 0;
  fm->context[which].buffers_per_worker[my_cpu_number] = 0;
  fm->context[which].next_record_offset_per_worker[my_cpu_number] =
    upf_ipfix_get_headersize ();
}

static vlib_buffer_t *
upf_ipfix_get_buffer (vlib_main_t * vm, upf_ipfix_variant_t which)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  ipfix_exporter_t *exp = pool_elt_at_index (flow_report_main.exporters, 0);
  vlib_buffer_t *b0;
  u32 bi0;
  u32 my_cpu_number = vm->thread_index;

  /* Find or allocate a buffer */
  b0 = fm->context[which].buffers_per_worker[my_cpu_number];

  /* Need to allocate a buffer? */
  if (PREDICT_FALSE (b0 == 0))
    {
      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  /* vlib_node_increment_counter (vm, upf_ipfix_l2_node.index, */
	  /* 			       UPF_IPFIX_ERROR_BUFFER, 1); */
	  return 0;
	}

      /* Initialize the buffer */
      b0 = fm->context[which].buffers_per_worker[my_cpu_number] =
	vlib_get_buffer (vm, bi0);

      b0->current_data = 0;
      b0->current_length = upf_ipfix_get_headersize ();
      b0->flags |=
	(VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_FLOW_REPORT);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = exp->fib_index;
      fm->context[which].next_record_offset_per_worker[my_cpu_number] =
	b0->current_length;
    }

  return b0;
}

static void
upf_ipfix_export_entry (vlib_main_t * vm, flow_entry_t * f, flow_direction_t direction, u32 now)
{
  u32 my_cpu_number = vm->thread_index;
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  ipfix_exporter_t *exp = pool_elt_at_index (flow_report_main.exporters, 0);
  vlib_buffer_t *b0;
  bool collect_ip4 = false, collect_ip6 = false;
  upf_ipfix_variant_t which = ip46_address_is_ip4 (&f->key.ip[FT_ORIGIN]) ?
    FLOW_VARIANT_IP4 : FLOW_VARIANT_IP6; /* TODO: per-flow template selection */
  upf_ipfix_record_t flags = fm->context[which].flags;
  u16 offset =
    fm->context[which].next_record_offset_per_worker[my_cpu_number];

  upf_debug ("export entry, flow variant %s",
	     which == FLOW_VARIANT_IP4 ? "ip4" :
	     which == FLOW_VARIANT_IP6 ? "ip6" : "...");
  if (offset < upf_ipfix_get_headersize ())
    offset = upf_ipfix_get_headersize ();

  b0 = upf_ipfix_get_buffer (vm, which);
  /* No available buffer, what to do... */
  if (b0 == 0)
    {
      upf_debug ("no buffer");
      return;
    }

  if (flags & FLOW_RECORD_L3)
    {
      collect_ip4 = which == FLOW_VARIANT_L2_IP4 || which == FLOW_VARIANT_IP4;
      collect_ip6 = which == FLOW_VARIANT_L2_IP6 || which == FLOW_VARIANT_IP6;
    }

  offset += upf_ipfix_common_add (b0, f, direction, offset);

  /* if (flags & FLOW_RECORD_L2) */
  /*   offset += upf_ipfix_l2_add (b0, f, direction, offset); */
  if (collect_ip6)
    offset += upf_ipfix_l3_ip6_add (b0, f, direction, offset);
  if (collect_ip4)
    offset += upf_ipfix_l3_ip4_add (b0, f, direction, offset);
  if (flags & FLOW_RECORD_L4)
    offset += upf_ipfix_l4_add (b0, f, direction, offset);

  /* Reset per flow-export counters */
  // TBD: reset delta stats
  /* e->packetcount = 0; */
  /* e->octetcount = 0; */
  flow_last_exported(f, direction) = now;

  b0->current_length = offset;

  fm->context[which].next_record_offset_per_worker[my_cpu_number] = offset;
  /* Time to flush the buffer? */
  /* TODO uncomment! also: force upon removal */
  /* if (offset + fm->template_size[flags] > exp->path_mtu) */
  upf_ipfix_export_send (vm, b0, which, now);
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

static int
upf_ipfix_params (upf_ipfix_main_t * fm, /* u8 record_l2, */
		  u8 record_l3, u8 record_l4)
{
  upf_ipfix_record_t flags = 0;

  if (vec_neg_search (fm->flow_per_interface, (u8) ~ 0) != ~0)
    return ~0;

  /* if (record_l2) */
  /*   flags |= FLOW_RECORD_L2; */
  if (record_l3)
    flags |= FLOW_RECORD_L3;
  if (record_l4)
    flags |= FLOW_RECORD_L4;

  fm->record = flags;

  /*
   * Timers: ~0 is default, 0 is off
   */
  /* fm->active_timer = */
  /*   (active_timer == (u32) ~ 0 ? UPF_IPFIX_TIMER_ACTIVE : active_timer); */
  /* fm->passive_timer = */
  /*   (passive_timer == (u32) ~ 0 ? UPF_IPFIX_TIMER_PASSIVE : passive_timer); */

  return 0;
}

static int upf_ipfix_templates_add_del (upf_ipfix_main_t *fm, u8 which, int is_add)
{
  int rv = 0;
  u16 template_id = 0;
  upf_ipfix_record_t flags = fm->record;

  fm->template_per_flow[which] += (is_add) ? 1 : -1;
  if (is_add && fm->template_per_flow[which] > 1)
    template_id = fm->template_reports[flags];

  if ((is_add && fm->template_per_flow[which] == 1) ||
      (!is_add && fm->template_per_flow[which] == 0))
    {
      if (which == FLOW_VARIANT_IP4)
	rv = upf_ipfix_template_add_del (1, UDP_DST_PORT_ipfix, flags,
					 upf_ipfix_data_callback_ip4,
					 upf_ipfix_template_rewrite_ip4,
					 is_add, &template_id);
      else if (which == FLOW_VARIANT_IP6)
	rv = upf_ipfix_template_add_del (1, UDP_DST_PORT_ipfix, flags,
					 upf_ipfix_data_callback_ip6,
					 upf_ipfix_template_rewrite_ip6,
					 is_add, &template_id);
    }
  if (rv && rv != VNET_API_ERROR_VALUE_EXIST)
    {
      clib_warning ("vnet_flow_report_add_del returned %d", rv);
      return -1;
    }

  if (which != (u8) ~ 0)
    {
      fm->context[which].flags = fm->record;
      fm->template_reports[flags] = (is_add) ? template_id : 0;
    }

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
  int i;

  fm->vnet_main = vnet_get_main ();
  fm->vlib_main = vm; /* FIXME: shouldn't need that */

  /* Set up time reference pair */
  fm->vlib_time_0 = (u32)vlib_time_now (vm);

  clib_memset (fm->template_reports, 0, sizeof (fm->template_reports));
  clib_memset (fm->template_size, 0, sizeof (fm->template_size));
  clib_memset (fm->template_per_flow, 0, sizeof (fm->template_per_flow));

  /* Decide how many worker threads we have */
  num_threads = 1 /* main thread */  + tm->n_threads;

  /* Allocate per worker thread vectors per flavour */
  for (i = 0; i < FLOW_N_VARIANTS; i++)
    {
      vec_validate (fm->context[i].buffers_per_worker, num_threads - 1);
      vec_validate (fm->context[i].frames_per_worker, num_threads - 1);
      vec_validate (fm->context[i].next_record_offset_per_worker,
		    num_threads - 1);
    }

  fm->active_timer = UPF_IPFIX_TIMER_ACTIVE;
  /* fm->passive_timer = UPF_IPFIX_TIMER_PASSIVE; */

  flow_update_hook = upf_ipfix_flow_update_hook;
  flow_removal_hook = upf_ipfix_flow_removal_hook;

  /* FIXME */
  upf_ipfix_params(fm, 1, 1);

  /* FIXME: ipv6 causes problems */
  /* if (upf_ipfix_templates_add_del (fm, FLOW_VARIANT_IP4, 1) != 0 || */
  /*     upf_ipfix_templates_add_del (fm, FLOW_VARIANT_IP6, 1) != 0) */
  /*   error = clib_error_return (0, "error adding IPFIX templates"); */
  if (upf_ipfix_templates_add_del (fm, FLOW_VARIANT_IP4, 1) != 0)
    error = clib_error_return (0, "error adding IPFIX templates");

  return error;
}
