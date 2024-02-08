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
#include "upf_pfcp.h"
#include "upf_ipfix.h"

#define UPF_IPFIX_MAPPING_BUCKETS     64
#define UPF_IPFIX_MAPPING_MEMORY_SIZE 16384

// #define CLIB_DEBUG 111
#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)                                                        \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

upf_ipfix_main_t upf_ipfix_main;
uword upf_ipfix_walker_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
                                vlib_frame_t *f);

static inline ipfix_exporter_t *
upf_ipfix_get_exporter (upf_ipfix_protocol_context_t *context)
{
  flow_report_main_t *frm = &flow_report_main;
  ipfix_exporter_t *exp;
  bool use_default = ip46_address_is_zero (&context->key.collector_ip);

  if (context->exporter_index != (u32) ~0 &&
      !pool_is_free_index (frm->exporters, context->exporter_index))
    {
      /* Check if the exporter got replaced */
      exp = pool_elt_at_index (frm->exporters, context->exporter_index);
      if (use_default ||
          ip46_address_cmp (&context->key.collector_ip,
                            &ip_addr_46 (&exp->ipfix_collector)) == 0)
        return exp;
    }

  if (use_default)
    {
      context->exporter_index = 0;
      return &frm->exporters[0];
    }

  ip_address_t addr;
  ip_address_from_46 (&context->key.collector_ip,
                      ip46_address_is_ip4 (&context->key.collector_ip) ?
                        FIB_PROTOCOL_IP4 :
                        FIB_PROTOCOL_IP6,
                      &addr);
  exp = vnet_ipfix_exporter_lookup (&addr);
  context->exporter_index = exp ? exp - frm->exporters : (u32) ~0;

  return exp;
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
upf_ipfix_template_rewrite (ipfix_exporter_t *exp, flow_report_t *fr,
                            u16 collector_port, ipfix_report_element_t *elts,
                            u32 n_elts, u32 *stream_index)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
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
  upf_ipfix_protocol_context_t *context =
    pool_elt_at_index (fm->proto_contexts, fr->opaque.as_uword);
  upf_ipfix_template_t *template = upf_ipfix_templates + context->key.policy;

  ASSERT (context);
  field_count = context->key.is_ip4 ? template->field_count_ipv4 :
                                      template->field_count_ipv6;
  ASSERT (field_count);

  stream = &exp->streams[fr->stream_index];

  /* allocate rewrite space */

  vec_validate_aligned (rewrite,
                        sizeof (ip4_ipfix_template_packet_t) +
                          field_count * sizeof (ipfix_field_specifier_t) - 1,
                        CLIB_CACHE_LINE_BYTES);

  tp = (ip4_ipfix_template_packet_t *) rewrite;
  ip = (ip4_header_t *) &tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);
  t = (ipfix_template_header_t *) (s + 1);
  first_field = f = (ipfix_field_specifier_t *) (t + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = ip_addr_v4 (&exp->src_address).as_u32;
  ip->dst_address.as_u32 = ip_addr_v4 (&exp->ipfix_collector).as_u32;
  udp->src_port = clib_host_to_net_u16 (stream->src_port);
  udp->dst_port = clib_host_to_net_u16 (collector_port);

  /* FIXUP: message header export_time */
  /* FIXUP: message header sequence_number */
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  /* Add TLVs to the template */
  f = context->key.is_ip4 ? template->add_ip4_fields (f) :
                            template->add_ip6_fields (f);

  /* Back to the template packet... */
  ip = (ip4_header_t *) &tp->ip4;
  udp = (udp_header_t *) (ip + 1);

  ASSERT (f - first_field);
  /* Field count in this template */
  t->id_count = ipfix_id_count (fr->template_id, f - first_field);

  context->rec_size = (u8 *) f - (u8 *) s;

  /* set length in octets */
  s->set_id_length = ipfix_set_id_length (2 /* set_id */, (u8 *) f - (u8 *) s);

  /* message length in octets */
  h->version_length = version_length ((u8 *) f - (u8 *) h);

  ip->length = clib_host_to_net_u16 ((u8 *) f - (u8 *) ip);
  upf_debug ("field bytes %u, vec_len %u", (u8 *) f - (u8 *) ip,
             vec_len (rewrite));
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

static vlib_buffer_t *
upf_ipfix_get_buffer (vlib_main_t *vm, upf_ipfix_protocol_context_t *context);

static void upf_ipfix_export_send (vlib_main_t *vm, vlib_buffer_t *b0,
                                   upf_ipfix_protocol_context_t *context,
                                   u32 now);

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
upf_ipfix_data_callback (flow_report_main_t *frm, ipfix_exporter_t *exp,
                         flow_report_t *fr, vlib_frame_t *f, u32 *to_next,
                         u32 node_index)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 now = (u32) vlib_time_now (vm);
  upf_ipfix_protocol_context_t *context =
    pool_elt_at_index (fm->proto_contexts, fr->opaque.as_uword);
  vlib_buffer_t *b = upf_ipfix_get_buffer (vm, context);
  if (b)
    upf_ipfix_export_send (vm, b, context, now);

  return f;
}

static int
upf_ipfix_report_add_del (upf_ipfix_main_t *fm, u32 domain_id,
                          u32 context_index, u16 *template_id, bool is_ip4,
                          bool is_add)
{
  upf_ipfix_protocol_context_t *context = fm->proto_contexts + context_index;
  ipfix_exporter_t *exp = upf_ipfix_get_exporter (context);
  if (!exp)
    return VNET_API_ERROR_INVALID_VALUE;
  vnet_flow_report_add_del_args_t a = {
    .rewrite_callback = upf_ipfix_template_rewrite,
    .flow_data_callback = upf_ipfix_data_callback,
    .is_add = is_add,
    .domain_id = domain_id,
    .src_port = UDP_DST_PORT_ipfix, /* FIXME */
    .opaque.as_uword = context_index,
  };
  return vnet_flow_report_add_del (exp, &a, template_id);
}

static void upf_ipfix_export_entry (vlib_main_t *vm, flow_entry_t *f, u32 now,
                                    bool last);

/* TBD: add trace */

static u16
upf_ipfix_get_headersize (void)
{
  return sizeof (ip4_header_t) + sizeof (udp_header_t) +
         sizeof (ipfix_message_header_t) + sizeof (ipfix_set_header_t);
}

static void
upf_ipfix_export_send (vlib_main_t *vm, vlib_buffer_t *b0,
                       upf_ipfix_protocol_context_t *context, u32 now)
{
  flow_report_main_t *frm = &flow_report_main;
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  ipfix_exporter_t *exp = upf_ipfix_get_exporter (context);
  vlib_frame_t *f;
  ip4_ipfix_template_packet_t *tp;
  ipfix_set_header_t *s;
  ipfix_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  u32 my_cpu_number = vm->thread_index;

  /* Fill in header */
  flow_report_stream_t *stream;

  /* Nothing to send */
  if (context->next_record_offset_per_worker[my_cpu_number] <=
      upf_ipfix_get_headersize ())
    return;

  upf_debug ("export send, context %u", context - fm->proto_contexts);

  u32 i, index = vec_len (exp->streams);
  for (i = 0; i < index; i++)
    if (exp->streams[i].domain_id == context->key.observation_domain_id)
      {
        index = i;
        break;
      }
  if (i == vec_len (exp->streams))
    {
      vec_validate (exp->streams, index);
      exp->streams[index].domain_id = context->key.observation_domain_id;
    }
  stream = &exp->streams[index];

  tp = vlib_buffer_get_current (b0);
  ip = (ip4_header_t *) &tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->flags_and_fragment_offset = 0;
  ip->src_address.as_u32 = ip_addr_v4 (&exp->src_address).as_u32;
  ip->dst_address.as_u32 = ip_addr_v4 (&exp->ipfix_collector).as_u32;
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

  s->set_id_length = ipfix_set_id_length (
    context->template_id,
    b0->current_length - (sizeof (*ip) + sizeof (*udp) + sizeof (*h)));
  h->version_length =
    version_length (b0->current_length - (sizeof (*ip) + sizeof (*udp)));

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
upf_ipfix_get_buffer (vlib_main_t *vm, upf_ipfix_protocol_context_t *context)
{
  ipfix_exporter_t *exp = upf_ipfix_get_exporter (context);
  vlib_buffer_t *b0;
  u32 bi0;
  u32 my_cpu_number = vm->thread_index;

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

// return bool if initialized
static bool
upf_ipfix_flow_init (flow_entry_t *f)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  upf_main_t *gtm = &upf_main;
  upf_session_t *sx;
  struct rules *active;
  upf_pdr_t *up_pdr;
  upf_far_t *up_far;
  upf_nwi_t *up_dst_nwi;
  u32 up_forwarding_policy_index;
  upf_ipfix_policy_t ipfix_policy;

  if (f->uplink_direction == FLOW_ENTRY_UPLINK_DIRECTION_UNDEFINED)
    return false;

  sx = pool_elt_at_index (gtm->sessions, f->session_index);
  active = pfcp_get_rules (sx, PFCP_ACTIVE);

  up_pdr = flow_pdr (f, FTK_EL_SRC ^ f->uplink_direction, active);
  if (!up_pdr)
    return false;

  clib_warning ("IPFIX FLOW UP PDR MATCHES ON %v",
                pool_elt_at_index (gtm->nwis, up_pdr->pdi.nwi_index)->name);

  if (up_pdr->ipfix_cached_context_id == (u16) ~0)
    return false;

  upf_ipfix_context_t *cached_ctx =
    pool_elt_at_index (fm->cached_contexts, up_pdr->ipfix_cached_context_id);

  up_far = pfcp_get_far_by_id (active, up_pdr->far_id);
  if (!up_far)
    return false;

  if (pool_is_free_index (gtm->nwis, up_far->forward.nwi_index))
    return false;

  up_dst_nwi = pool_elt_at_index (gtm->nwis, up_far->forward.nwi_index);

  clib_warning ("IPFIX FLOW UP PDR FORWARDED TO %v", up_dst_nwi->name);

  bool is_ip4 = f->key.is_ip4 != 0;
  fib_protocol_t fproto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;

  if (up_far->forward.flags & FAR_F_FORWARDING_POLICY)
    up_forwarding_policy_index = up_far->forward.fp_pool_index;
  else
    up_forwarding_policy_index = ~0;

  u32 up_sw_if_index;
  u32 up_fib_index = up_dst_nwi->fib_index[fproto];
  if ((up_far->forward.flags & FAR_F_OUTER_HEADER_CREATION))
    {
      up_sw_if_index = up_far->forward.dst_sw_if_index;
    }
  else
    {
      if (up_forwarding_policy_index != ~0)
        {
          fib_route_path_t *rpath;
          upf_forwarding_policy_t *fp_entry = pool_elt_at_index (
            gtm->upf_forwarding_policies, up_forwarding_policy_index);
          vec_foreach (rpath, fp_entry->rpaths)
            {
              if (rpath->frp_proto == (is_ip4 ? DPO_PROTO_IP4 : DPO_PROTO_IP6))
                {
                  up_fib_index = rpath->frp_fib_index;
                  break;
                }
            }
        }

      up_sw_if_index = upf_ip46_get_resolving_interface (
        up_fib_index, &f->key.ip[FTK_EL_DST ^ f->uplink_direction], is_ip4);
    }

  f->ipfix.forwarding_policy_index = up_forwarding_policy_index;
  f->ipfix.up_dst_nwi_index = up_dst_nwi - gtm->nwis;
  f->ipfix.up_dst_sw_if_index = up_sw_if_index;
  f->ipfix.up_dst_fib_index = up_fib_index;

  f->ipfix.context_index = cached_ctx->protocol_context_id[fproto];
  if (f->ipfix.context_index != (u16) ~0)
    {
      upf_ipfix_protocol_context_t *context =
        pool_elt_at_index (fm->proto_contexts, f->ipfix.context_index);

      ASSERT (!ip46_address_cmp (&context->key.collector_ip,
                                 &up_dst_nwi->ipfix_collector_ip.ip));
      ASSERT (context->key.observation_domain_id ==
              up_dst_nwi->observation_domain_id);
      ASSERT (context->key.is_ip4 == is_ip4);

      upf_ref_ipfix_proto_context_by_index (f->ipfix.context_index);
      return true;
    }

  return false;
}

static void
upf_ipfix_export_entry (vlib_main_t *vm, flow_entry_t *f, u32 now, bool last)
{
  u32 my_cpu_number = vm->thread_index;
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  vlib_buffer_t *b0;
  upf_main_t *gtm = &upf_main;
  upf_ipfix_protocol_context_t *context;
  u16 offset;
  upf_ipfix_template_t *template;
  vnet_main_t *vnm = vnet_get_main ();

  if (f->ipfix.context_index == (u16) ~0)
    if (!upf_ipfix_flow_init (f))
      return;

  context = pool_elt_at_index (fm->proto_contexts, f->ipfix.context_index);
  offset = context->next_record_offset_per_worker[my_cpu_number];
  template = upf_ipfix_templates + context->key.policy;

  upf_debug ("export entry [%s], policy %u",
             context->key.is_ip4 ? "ip4" : "ip6", context->key.policy);
  if (offset < upf_ipfix_get_headersize ())
    offset = upf_ipfix_get_headersize ();

  b0 = upf_ipfix_get_buffer (vm, context);
  /* No available buffer, what to do... */
  if (b0 == 0)
    {
      upf_debug ("no buffer");
      return;
    }

  ASSERT (f->key.is_ip4 == context->key.is_ip4);

  bool is_ip4 = f->key.is_ip4;
  fib_protocol_t fproto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;

  upf_session_t *sx = pool_elt_at_index (gtm->sessions, f->session_index);
  upf_nwi_t *nwi =
    pool_elt_at_index (upf_main.nwis, f->ipfix.up_dst_nwi_index);
  fib_table_t *up_table = fib_table_get (f->ipfix.up_dst_fib_index, fproto);

  upf_ipfix_report_info_t info;
  if (f->ipfix.forwarding_policy_index != (u16) ~0)
    {
      upf_forwarding_policy_t *fp_entry = pool_elt_at_index (
        gtm->upf_forwarding_policies, f->ipfix.forwarding_policy_index);
      info.vrf_name = fp_entry->policy_id;
    }
  else
    info.vrf_name = up_table->ft_desc;

  info.sw_if_name = NULL;
  {
    vnet_sw_interface_t *si =
      vnet_get_sw_interface_or_null (vnm, f->ipfix.up_dst_sw_if_index);
    if (si)
      {
        vnet_sw_interface_t *si_sup =
          vnet_get_sup_sw_interface (vnm, si->sw_if_index);
        vnet_hw_interface_t *hi_sup =
          vnet_get_hw_interface (vnm, si_sup->hw_if_index);
        info.sw_if_name = hi_sup->name;
      }
  }

  // for (upf_direction_t dir = 0; dir < 2; dir++)
  //  {
  //    flow_side_stats_t *stats = &flow_side (f, dir)->stats;
  //    clib_warning ("IPFIX reporting sats (%d): pkts %d (%d) bytes %d (%d)",
  //                  dir, stats->pkts_unreported, stats->pkts,
  //                  stats->bytes_unreported, stats->bytes);
  //  }

  if (context->key.is_ip4)
    offset += template->add_ip4_values (b0, offset, sx, f, f->uplink_direction,
                                        nwi, &info, last);
  else
    offset += template->add_ip6_values (b0, offset, sx, f, f->uplink_direction,
                                        nwi, &info, last);

  /* Reset per flow-export counters */
  f->ipfix.last_exported = now;
  f->exported = 1;

  b0->current_length = offset;

  context->next_record_offset_per_worker[my_cpu_number] = offset;
  /* Time to flush the buffer? */
  /* TODO uncomment! also: force upon removal */
  /* if (offset + context->rec_size > exp->path_mtu) */
  upf_ipfix_export_send (vm, b0, context, now);
}

void
upf_ipfix_flow_stats_update_handler (flow_entry_t *f, u32 now)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  vlib_main_t *vm = fm->vlib_main;

  if (fm->disabled)
    return;

  if (PREDICT_FALSE (now > f->ipfix.last_exported))
    upf_ipfix_export_entry (vm, f, now, false);

  return;
}

static void
upf_ipfix_free_flow (flow_entry_t *f)
{
  if (f->ipfix.context_index != (u16) ~0)
    upf_unref_ipfix_proto_context_by_index (f->ipfix.context_index);
}

void
upf_ipfix_flow_remove_handler (flow_entry_t *f, u32 now)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  vlib_main_t *vm = fm->vlib_main;

  if (fm->disabled)
    return;

  upf_ipfix_export_entry (vm, f, now, true);
  upf_ipfix_free_flow (f);
}

u32
upf_ref_ipfix_cached_context (const upf_ipfix_context_key_t *key)
{
  clib_bihash_kv_24_8_t kv, value;
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  upf_ipfix_context_t *cached_ctx;

  upf_ipfix_context_key_t key_copy = *key;
  key_copy.is_ip4 = ~0;

  clib_memcpy_fast (&kv.key, &key_copy, sizeof (kv.key));

  clib_warning ("REFFING NEW CACHED CONTEXT %x %x %x", kv.key[0], kv.key[1],
                kv.key[2]);

  if (PREDICT_TRUE (
        !clib_bihash_search_24_8 (&fm->cached_context_by_key, &kv, &value)))
    {
      cached_ctx = pool_elt_at_index (fm->cached_contexts, value.value);
      clib_atomic_add_fetch (&cached_ctx->refcnt, 1);
      return value.value;
    }

  pool_get_zero (fm->cached_contexts, cached_ctx);
  u32 idx = cached_ctx - fm->cached_contexts;
  cached_ctx->refcnt = 1;
  key_copy.is_ip4 = 1;
  cached_ctx->protocol_context_id[FIB_PROTOCOL_IP4] =
    upf_ref_ipfix_proto_context (&key_copy);

  key_copy.is_ip4 = 0;
  cached_ctx->protocol_context_id[FIB_PROTOCOL_IP6] =
    upf_ref_ipfix_proto_context (&key_copy);

  clib_memcpy_fast (&cached_ctx->key, &kv.key, sizeof (cached_ctx->key));

  kv.value = idx;
  clib_bihash_add_del_24_8 (&fm->cached_context_by_key, &kv, 1);
  return idx;
}

void
upf_unref_ipfix_cached_context_by_index (u32 idx)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  clib_bihash_kv_24_8_t kv;
  upf_ipfix_context_t *cached_ctx;

  cached_ctx = pool_elt_at_index (fm->cached_contexts, idx);
  if (clib_atomic_sub_fetch (&cached_ctx->refcnt, 1))
    return;

  clib_warning ("REMOVING IPFIX CACHED CONTEXT SINCE UNREFED BY EVERYONE");

  clib_memcpy_fast (&kv.key, &cached_ctx->key, sizeof (kv.key));
  clib_bihash_add_del_24_8 (&fm->cached_context_by_key, &kv, 0 /* is_add */);

  if (cached_ctx->protocol_context_id[FIB_PROTOCOL_IP4] != ~0)
    upf_unref_ipfix_proto_context_by_index (
      cached_ctx->protocol_context_id[FIB_PROTOCOL_IP4]);

  if (cached_ctx->protocol_context_id[FIB_PROTOCOL_IP6] != ~0)
    upf_unref_ipfix_proto_context_by_index (
      cached_ctx->protocol_context_id[FIB_PROTOCOL_IP6]);

  pool_put (fm->cached_contexts, cached_ctx);
}

u32
upf_ref_ipfix_proto_context (const upf_ipfix_context_key_t *key)
{
  int rv;
  vlib_thread_main_t *tm = &vlib_thread_main;
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  clib_bihash_kv_24_8_t kv, value;
  upf_ipfix_protocol_context_t *context;
  /* Decide how many worker threads we have */
  u32 num_threads = 1 /* main thread */ + tm->n_threads;
  u32 idx = ~0;

  clib_memcpy_fast (&kv.key, key, sizeof (kv.key));

  clib_warning ("REFFING NEW CONTEXT %x %x %x", kv.key[0], kv.key[1],
                kv.key[2]);

  if (PREDICT_TRUE (
        !clib_bihash_search_24_8 (&fm->proto_context_by_key, &kv, &value)))
    {
      context = pool_elt_at_index (fm->proto_contexts, value.value);
      clib_atomic_add_fetch (&context->refcnt, 1);
      return value.value;
    }

  pool_get_zero (fm->proto_contexts, context);

  vec_validate (context->buffers_per_worker, num_threads - 1);
  vec_validate (context->frames_per_worker, num_threads - 1);
  vec_validate (context->next_record_offset_per_worker, num_threads - 1);

  clib_memcpy_fast (&context->key, key, sizeof (context->key));

  /* lookup the exporter a bit later */
  context->exporter_index = (u32) ~0;
  context->refcnt = 1;

  idx = context - fm->proto_contexts;
  rv = upf_ipfix_report_add_del (fm, key->observation_domain_id, idx,
                                 &context->template_id, key->is_ip4, true);
  if (rv)
    {
      clib_warning ("couldn't add IPFIX report, perhaps "
                    "the exporter has been deleted?");
      pool_put (fm->proto_contexts, context);
      return ~0;
    }

  kv.value = idx;
  clib_bihash_add_del_24_8 (&fm->proto_context_by_key, &kv, 1);

  return idx;
}

void
upf_ref_ipfix_proto_context_by_index (u32 cidx)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  upf_ipfix_protocol_context_t *context;

  context = pool_elt_at_index (fm->proto_contexts, cidx);
  clib_atomic_add_fetch (&context->refcnt, 1);
}

void
upf_unref_ipfix_proto_context_by_index (u32 cidx)
{
  int rv;
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  clib_bihash_kv_24_8_t kv;
  upf_ipfix_protocol_context_t *context;

  context = pool_elt_at_index (fm->proto_contexts, cidx);

  clib_atomic_sub_fetch (&context->refcnt, 1);
  // Do not remove context since it will use different FlowSet Id on
  // possible future recreation.
  return;

  if (clib_atomic_sub_fetch (&context->refcnt, 1))
    return;

  clib_warning ("REMOVING IPFIX CONTEXT SINCE UNREFED BY EVERYONE");

  clib_memcpy_fast (&kv.key, &context->key, sizeof (kv.key));
  clib_bihash_add_del_24_8 (&fm->proto_context_by_key, &kv, 0 /* is_add */);

  rv = upf_ipfix_report_add_del (fm, context->key.observation_domain_id, cidx,
                                 &context->template_id, context->key.is_ip4,
                                 false);
  if (rv)
    clib_warning ("couldn't remove IPFIX report, perhaps "
                  "the exporter has been deleted?");

  vec_free (context->buffers_per_worker);
  vec_free (context->frames_per_worker);
  vec_free (context->next_record_offset_per_worker);
  pool_put (fm->proto_contexts, context);
}

/**
 * @brief Set up the API message handling tables
 * @param vm vlib_main_t * vlib main data structure pointer
 * @returns 0 to indicate all is well, or a clib_error_t
 */
clib_error_t *
upf_ipfix_init (vlib_main_t *vm)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  clib_error_t *error = 0;

  clib_spinlock_init (&fm->lock);

  fm->vnet_main = vnet_get_main ();
  fm->vlib_main = vm; /* FIXME: shouldn't need that */

  /* Set up time reference pair */
  fm->vlib_time_0 = (u32) vlib_time_now (vm);

  /* initialize the IP/TEID hash's */
  clib_bihash_init_24_8 (&fm->proto_context_by_key, "proto_context_by_key",
                         UPF_IPFIX_MAPPING_BUCKETS,
                         UPF_IPFIX_MAPPING_MEMORY_SIZE);
  /* clib_bihash_set_kvp_format_fn_24_8 (&fm->context_by_key, */
  /* 				      format_ipfix_context_key); */

  clib_bihash_init_24_8 (&fm->cached_context_by_key, "cached_context_by_key",
                         UPF_IPFIX_MAPPING_BUCKETS,
                         UPF_IPFIX_MAPPING_MEMORY_SIZE);

  clib_bihash_init_24_8 (&fm->info_by_key, "info_by_key",
                         UPF_IPFIX_MAPPING_BUCKETS,
                         UPF_IPFIX_MAPPING_MEMORY_SIZE);
  /* clib_bihash_set_kvp_format_fn_24_8 (&fm->info_by_key, */
  /* 				      format_ipfix_info_key); */

  return error;
}

upf_ipfix_policy_t
upf_ipfix_lookup_policy (u8 *name, bool *ok)
{
  upf_ipfix_policy_t policy;
  u32 name_len = vec_len (name);

  if (!name_len)
    {
      if (ok)
        *ok = true;
      return UPF_IPFIX_POLICY_NONE;
    }
  else if (ok)
    *ok = false;

  for (policy = UPF_IPFIX_POLICY_NONE; policy < UPF_IPFIX_N_POLICIES; policy++)
    {
      u32 l = strlen (upf_ipfix_templates[policy].name);
      if (l == name_len && !memcmp (name, upf_ipfix_templates[policy].name, l))
        {
          if (ok)
            *ok = true;
          return policy;
        }
    }

  /* avoid silently ignoring the error */
  if (!ok)
    clib_warning ("Bad IPFIX policy: %v", name);

  return UPF_IPFIX_POLICY_NONE;
}

uword
unformat_ipfix_policy (unformat_input_t *i, va_list *args)
{
  bool ok;
  upf_ipfix_policy_t *policy = va_arg (*args, upf_ipfix_policy_t *);
  u8 *name;

  if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
    return 0;

  if (!unformat (i, "%_%v%_", &name))
    return 0;

  *policy = upf_ipfix_lookup_policy (name, &ok);
  if (!ok)
    return 0;

  return 1;
}

u8 *
format_upf_ipfix_policy (u8 *s, va_list *args)
{
  upf_ipfix_policy_t policy = va_arg (*args, int);
  return policy < UPF_IPFIX_N_POLICIES ?
           format (s, "%s", upf_ipfix_templates[policy].name) :
           format (s, "<unknown %u>", policy);
}
