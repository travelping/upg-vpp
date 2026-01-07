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

/* Based on the VPP flowprobe plugin */

#include <vlib/vlib.h>
#include <vppinfra/crc32.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_local.h>

#include "upf/upf.h"
#include "upf/upf_stats.h"
#include "upf/utils/upf_mt.h"
#include "upf/integrations/upf_ipfix.h"
#include "upf/utils/ip_helpers.h"

#define UPF_IPFIX_MAPPING_BUCKETS     64
#define UPF_IPFIX_MAPPING_MEMORY_SIZE 16384

#define UPF_DEBUG_ENABLE 0

upf_ipfix_main_t upf_ipfix_main;

static ipfix_exporter_t *
upf_ipfix_get_exporter (upf_ipfix_context_t *context)
{
  flow_report_main_t *frm = &flow_report_main;
  ipfix_exporter_t *exp;

  bool use_default = ip_address_is_zero (&context->key.collector_ip);
  if (use_default)
    {
      // Index 0 is always populated according to comment in flow_report_main_t
      // structure definition
      context->exporter_index = 0;
      return pool_elt_at_index (frm->exporters, 0);
    }

  // Here we try to avoid lookup
  if (!is_valid_id (context->exporter_index))
    goto _do_lookup;

  // Check that exporter was not removed
  if (pool_is_free_index (frm->exporters, context->exporter_index))
    goto _do_lookup;

  // Check that exporter was not modified
  ipfix_exporter_t *old_exp =
    pool_elt_at_index (frm->exporters, context->exporter_index);
  if (!ip_address_cmp (&context->key.collector_ip, &old_exp->ipfix_collector))
    return old_exp;

_do_lookup:
  upf_debug ("DOING IPFIX LOOKUP");
  clib_warning ("changing ipfix exporter can cause UPF crashes");

  exp = vnet_ipfix_exporter_lookup (&context->key.collector_ip);
  context->exporter_index = exp ? (exp - frm->exporters) : ~0;
  return exp;
}

/* from src/vnet/ip/ping.c */
static_always_inline fib_node_index_t
upf_ip46_fib_table_lookup_host (u32 fib_index, ip46_address_t *pa46,
                                int is_ip4)
{
  fib_node_index_t fib_entry_index =
    is_ip4 ? ip4_fib_table_lookup (ip4_fib_get (fib_index), &pa46->ip4, 32) :
             ip6_fib_table_lookup (fib_index, &pa46->ip6, 128);
  return fib_entry_index;
}

/* from src/vnet/ip/ping.c */
static_always_inline u32
upf_ip46_get_resolving_interface (u32 fib_index, ip46_address_t *pa46,
                                  int is_ip4)
{
  fib_node_index_t fib_entry_index;

  ASSERT (~0 != fib_index);

  fib_entry_index = upf_ip46_fib_table_lookup_host (fib_index, pa46, is_ip4);
  return fib_entry_get_resolving_interface (fib_entry_index);
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
  ip4_ipfix_template_packet_t *tp;

  u8 *rewrite = 0;

  flow_report_stream_t *stream = &exp->streams[fr->stream_index];
  upf_ipfix_context_t *context =
    pool_elt_at_index (fm->contexts, fr->opaque.as_uword);

  fib_protocol_t fproto =
    context->key.is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  upf_ipfix_template_t *template = &upf_ipfix_templates[context->key.policy];
  upf_ipfix_template_proto_t *template_proto = &template->per_ip[fproto];

  ASSERT (template_proto->field_count);

  /* allocate rewrite space */

  vec_validate_aligned (
    rewrite,
    sizeof (ip4_ipfix_template_packet_t) +
      template_proto->field_count * sizeof (ipfix_field_specifier_t) - 1,
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
  h->sequence_number =
    clib_host_to_net_u32 (clib_atomic_load_relax_n (&stream->sequence_number));
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  /* Add TLVs to the template */
  f = template_proto->add_fields (f);

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
             template_proto->field_count, sizeof (ip4_ipfix_template_packet_t),
             sizeof (ipfix_template_packet_t),
             sizeof (ipfix_field_specifier_t));
  ASSERT ((u8 *) f - (u8 *) ip == vec_len (rewrite));
  /* FIXME (actually, overwritten in send_template_packet() */
  udp->length = clib_host_to_net_u16 (((u8 *) f - (u8 *) ip) - sizeof (*ip));
  ip->checksum = ip4_header_checksum (ip);

  upf_debug ("rewrite: IPFIX IP hdr: %U", format_ip_header, ip,
             vec_len (rewrite));

  return rewrite;
}

static vlib_buffer_t *
upf_ipfix_context_ensure_buffer (vlib_main_t *vm,
                                 upf_ipfix_context_t *context);

static void upf_ipfix_export_send (vlib_main_t *vm, vlib_buffer_t *b0,
                                   upf_ipfix_context_t *context, u32 now);

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

  u32 vlib_now = (u32) vlib_time_now (vm);

  upf_ipfix_context_t *context =
    pool_elt_at_index (fm->contexts, fr->opaque.as_uword);

  upf_debug ("[t%d] called at %u for context %u", vm->thread_index, vlib_now,
             fr->opaque.as_uword);

  vlib_buffer_t *b = upf_ipfix_context_ensure_buffer (vm, context);
  if (b)
    upf_ipfix_export_send (vm, b, context, vlib_now);

  return f;
}

static int
upf_ipfix_report_add_del (upf_ipfix_main_t *fm, u32 domain_id,
                          u32 context_index, u16 *template_id, bool is_ip4,
                          bool is_add, u32 *p_flow_report_index)
{
  upf_ipfix_context_t *context =
    pool_elt_at_index (fm->contexts, context_index);
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
    .flow_report_index = ~0,
  };
  int rv = vnet_flow_report_add_del (exp, &a, template_id);
  *p_flow_report_index = a.flow_report_index;
  return rv;
}

static void upf_ipfix_export_entry (flow_entry_t *f, u32 now, bool last);

/* TBD: add trace */

static u16
upf_ipfix_get_headers_size (void)
{
  return sizeof (ip4_header_t) + sizeof (udp_header_t) +
         sizeof (ipfix_message_header_t) + sizeof (ipfix_set_header_t);
}

static void
upf_ipfix_export_send (vlib_main_t *vm, vlib_buffer_t *b0,
                       upf_ipfix_context_t *context, u32 vlib_time)
{
  flow_report_main_t *frm = &flow_report_main;
  upf_ipfix_main_t *uim = &upf_ipfix_main;
  ipfix_exporter_t *exp = upf_ipfix_get_exporter (context);
  vlib_frame_t *f;
  ip4_ipfix_template_packet_t *tp;
  ipfix_set_header_t *s;
  ipfix_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  u32 thread_id = vm->thread_index;

  upf_ipfix_wk_context_t *wk_context =
    vec_elt_at_index (context->per_worker, thread_id);

  /* Nothing to send */
  if (wk_context->next_record_offset <= upf_ipfix_get_headers_size ())
    {
      upf_debug (
        "[t%d] nothing to send: next record offset %u <= headersize %u",
        thread_id, wk_context->next_record_offset,
        upf_ipfix_get_headers_size ());
      return;
    }

  upf_debug (
    "[t%d] ipfix export send, context %u, next_rec_off %u, headersize %u",
    thread_id, context - uim->contexts, wk_context->next_record_offset,
    upf_ipfix_get_headers_size ());

  flow_report_t *fr =
    vec_elt_at_index (exp->reports, context->flow_report_index);
  flow_report_stream_t *stream =
    vec_elt_at_index (exp->streams, fr->stream_index);

  /* Fill in header */
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
  h->export_time = vlib_time - frm->vlib_time_0;
  h->export_time = clib_host_to_net_u32 (h->export_time + frm->unix_time_0);
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  /* FIXUP: message header sequence_number */
  h->sequence_number = clib_atomic_fetch_add (&stream->sequence_number,
                                              wk_context->n_data_records);
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
  f = wk_context->frames;
  if (PREDICT_FALSE (f == NULL))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      wk_context->frames = f;
      u32 bi0 = vlib_get_buffer_index (vm, b0);

      /* Enqueue the buffer */
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  upf_debug ("[t%d] sending: IP hdr: %U", thread_id, format_ip4_header,
             vlib_buffer_get_current (b0), b0->current_length);

  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

  wk_context->frames = NULL;
  wk_context->buffers = NULL;
  wk_context->n_data_records = 0;
  wk_context->next_record_offset = upf_ipfix_get_headers_size ();

  upf_stats_get_wk_generic (thread_id)->ipfix_messages_sent += 1;
}

static vlib_buffer_t *
upf_ipfix_context_ensure_buffer (vlib_main_t *vm, upf_ipfix_context_t *context)
{
  ipfix_exporter_t *exp = upf_ipfix_get_exporter (context);
  vlib_buffer_t *b0;
  u32 bi0;

  /* Find or allocate a buffer */
  upf_ipfix_wk_context_t *wk_context =
    vec_elt_at_index (context->per_worker, vm->thread_index);

  b0 = wk_context->buffers;

  /* Need to allocate a buffer? */
  if (PREDICT_FALSE (b0 == NULL))
    {
      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
        {
          upf_debug ("can't allocate ipfix data buffer");
          return 0;
        }

      /* Initialize the buffer */
      b0 = wk_context->buffers = vlib_get_buffer (vm, bi0);

      b0->current_data = 0;
      b0->current_length = upf_ipfix_get_headers_size ();
      b0->flags |=
        (VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_FLOW_REPORT);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = exp->fib_index;
      wk_context->next_record_offset = b0->current_length;
    }

  return b0;
}

// return bool if initialized
static bool
upf_ipfix_flow_init (u16 thread_id, flow_entry_t *f)
{
  upf_ipfix_main_t *ifm = &upf_ipfix_main;
  upf_main_t *um = &upf_main;

  upf_dp_session_t *dsx = upf_wk_get_dp_session (thread_id, f->session_id);
  upf_rules_t *rules = upf_wk_get_rules (thread_id, dsx->rules_id);

  upf_pdr_lid_t up_pdr_lid = f->pdr_lids[UPF_DIR_UL];
  if (!is_valid_id (up_pdr_lid))
    return false;

  /* Get uplink PDR,FAR and output NWI */
  rules_pdr_t *up_pdr = upf_rules_get_pdr (rules, up_pdr_lid);

  ASSERT (up_pdr->is_uplink);

  if (!is_valid_id (up_pdr->far_lid))
    return false;

  rules_far_t *up_far = upf_rules_get_far (rules, up_pdr->far_lid);

  if (up_far->forward.do_nat && !is_valid_id (f->nat_flow_id))
    return false;

  if (up_far->apply_action != UPF_FAR_ACTION_FORWARD)
    return false; // nwi_id is undefined

  upf_nwi_t *up_dst_nwi = pool_elt_at_index (um->nwis, up_far->forward.nwi_id);
  upf_interface_t *up_dst_nwif = pool_elt_at_index (
    um->nwi_interfaces, up_dst_nwi->interfaces_ids[up_far->forward.dst_intf]);

  /* Detect IPFIX policy for this flow */

  // FAR has priority for policy
  upf_ipfix_policy_t ipfix_policy = up_far->ipfix_policy_used;
  ASSERT (ipfix_policy != UPF_IPFIX_POLICY_UNSPECIFIED);

  if (ipfix_policy == UPF_IPFIX_POLICY_NONE)
    {
      f->ipfix_disabled = 1;
      return false;
    }

  bool is_ip4 = f->is_ip4;
  u16 ipfix_context_index =
    is_ip4 ? up_far->ipfix_context4_id : up_far->ipfix_context6_id;

  if (!is_valid_id (ipfix_context_index))
    return false;

  fib_protocol_t fproto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;

  /* Determine forwarding policy index */

  u16 up_forwarding_policy_id;
  if (up_far->forward.has_forwarding_policy)
    up_forwarding_policy_id = up_far->forward.forwarding_policy_id;
  else
    up_forwarding_policy_id = ~0;

  /* Determine output interface */
  u32 up_sw_if_index = ~0;
  u32 up_fib_index = up_dst_nwif->tx_fib_index[fproto];
  if (!up_far->forward.has_outer_header_creation)
    {
      if (is_valid_id (up_forwarding_policy_id))
        {
          upf_forwarding_policy_t *up_fp = pool_elt_at_index (
            um->forwarding_policies, up_forwarding_policy_id);
          u32 policy_fib_id = is_ip4 ? up_fp->ip4_fib_id : up_fp->ip6_fib_id;
          if (is_valid_id (policy_fib_id))
            up_fib_index = policy_fib_id;
        }

      up_sw_if_index = upf_ip46_get_resolving_interface (
        up_fib_index, &f->ip[UPF_EL_UL_DST], is_ip4);
    }

  /* Cache detected ipfix values in flow */
  f->ipfix.forwarding_policy_id = up_forwarding_policy_id;
  f->ipfix.up_dst_nwif_index = up_dst_nwif - um->nwi_interfaces;

  f->ipfix.context_index = ipfix_context_index;
  f->ipfix.up_dst_sw_if_index = up_sw_if_index;
  f->ipfix.up_dst_fib_index = up_fib_index;

  upf_ipfix_context_t *context =
    pool_elt_at_index (ifm->contexts, ipfix_context_index);
  ASSERT (context->key.is_ip4 == is_ip4);
  ASSERT (context->key.policy == ipfix_policy);

  return true;
}

static void
upf_ipfix_export_entry (flow_entry_t *f, u32 now, bool last)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  upf_main_t *um = &upf_main;

  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();

  if (!is_valid_id (f->ipfix.context_index))
    if (!upf_ipfix_flow_init (vm->thread_index, f))
      {
        // more info needed, or ipfix is not needed for this flow
        return;
      }

  upf_ipfix_context_t *context =
    pool_elt_at_index (fm->contexts, f->ipfix.context_index);
  upf_ipfix_wk_context_t *wk_context =
    vec_elt_at_index (context->per_worker, vm->thread_index);

  u16 offset = wk_context->next_record_offset;
  upf_ipfix_template_t *template = &upf_ipfix_templates[context->key.policy];

  upf_debug ("[t%d] export entry [%s], policy %u", vm->thread_index,
             context->key.is_ip4 ? "ip4" : "ip6", context->key.policy);
  if (offset < upf_ipfix_get_headers_size ())
    offset = upf_ipfix_get_headers_size ();

  vlib_buffer_t *b0 = upf_ipfix_context_ensure_buffer (vm, context);
  /* No available buffer, what to do... */
  if (b0 == NULL)
    {
      upf_debug ("no buffer");
      return;
    }

  bool is_ip4 = f->is_ip4;
  ASSERT (context->key.is_ip4 == is_ip4);

  fib_protocol_t fproto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;

  upf_interface_t *nif =
    pool_elt_at_index (um->nwi_interfaces, f->ipfix.up_dst_nwif_index);
  fib_table_t *up_table = fib_table_get (f->ipfix.up_dst_fib_index, fproto);

  upf_ipfix_report_info_t info;
  if (is_valid_id (f->ipfix.forwarding_policy_id))
    {
      upf_forwarding_policy_t *fp = pool_elt_at_index (
        um->forwarding_policies, f->ipfix.forwarding_policy_id);
      info.vrf_name = fp->policy_id;
    }
  else
    info.vrf_name = up_table->ft_desc;

  info.sw_if_name = NULL;
  if (is_valid_id (f->ipfix.up_dst_sw_if_index))
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

  offset += template->per_ip[fproto].add_values (
    vm->thread_index, b0, offset, f->session_id, f, nif, &info, last);

  /* Reset per flow-export counters */
  if (nif->ipfix.report_interval)
    f->ipfix.next_export_at = now + nif->ipfix.report_interval;
  else
    f->ipfix.next_export_at = 0;
  f->ipfix_exported = 1;

  b0->current_length = offset;
  wk_context->next_record_offset = offset;
  wk_context->n_data_records += 1;

  upf_stats_get_wk_generic (vlib_get_thread_index ())->ipfix_records_sent += 1;

  ipfix_exporter_t *exp = upf_ipfix_get_exporter (context);

  if (!exp)
    return;

  upf_debug ("[t%d] buf len %u, off %u + rec_size %u = %u, path_mtu %u",
             vm->thread_index, vlib_buffer_length_in_chain (vm, b0), offset,
             context->rec_size, offset + context->rec_size, exp->path_mtu);

  /* If we can't fit next records to buffer, then flush */
  if (offset + context->rec_size > exp->path_mtu)
    upf_ipfix_export_send (vm, b0, context, now);
}

void
upf_ipfix_flow_stats_update_handler (flow_entry_t *f, u32 now)
{
  if (f->ipfix_disabled)
    return;

  if (f->ipfix.next_export_at == 0)
    return;

  if (PREDICT_FALSE (now >= f->ipfix.next_export_at))
    upf_ipfix_export_entry (f, now, false);

  return;
}

void
upf_ipfix_flow_remove_handler (flow_entry_t *f, u32 now)
{
  if (f->ipfix_disabled)
    return;

  upf_ipfix_export_entry (f, now, true);
}

void
_upf_ipfix_ensure_timers_started ()
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  upf_mt_main_t *umm = &upf_mt_main;

  ASSERT_THREAD_MAIN ();

  if (fm->is_timers_started)
    return;

  fm->is_timers_started = 1;

  vec_validate (fm->timers_per_worker, vec_len (umm->workers) - 1);
  uword tid;
  vec_foreach_index (tid, fm->timers_per_worker)
    {
      // IPFIX callback called only on main thread. Call it manually on worker
      // threads
      fm->timers_per_worker[tid] =
        upf_timer_start_secs (tid, 0.5, UPF_TIMER_KIND_IPFIX, 0, 0);
    }
}

u16
upf_ipfix_ensure_context (const upf_ipfix_context_key_t *key)
{
  ASSERT_THREAD_MAIN ();

  vlib_main_t *vm = vlib_get_main ();
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  upf_mt_main_t *umm = &upf_mt_main;

  int rv;
  clib_bihash_kv_24_8_t kv = {}, value;
  upf_ipfix_context_t *context;

  u32 ctx_id = ~0;

  _upf_ipfix_ensure_timers_started ();

  clib_memcpy_fast (&kv.key, key, sizeof (kv.key));

  if (PREDICT_TRUE (
        !clib_bihash_search_24_8 (&fm->context_by_key, &kv, &value)))
    {
      context = pool_elt_at_index (fm->contexts, value.value);
      return value.value;
    }

  vlib_worker_thread_barrier_sync (vm);

  pool_get_zero (fm->contexts, context);

  clib_memcpy_fast (&context->key, key, sizeof (context->key));

  /* lookup the exporter a bit later */
  context->exporter_index = (u32) ~0;

  ctx_id = context - fm->contexts;
  u32 flow_report_index = ~0;
  rv = upf_ipfix_report_add_del (fm, key->observation_domain_id, ctx_id,
                                 &context->template_id, key->is_ip4, true,
                                 &flow_report_index);

  if (rv)
    {
      vlib_log_err (
        fm->log_failure_class,
        "IPFIX report add reason %U, exporter misconfigured or deleted",
        format_vnet_api_errno, rv);
      pool_put (fm->contexts, context);
      vlib_worker_thread_barrier_release (vm);
      return ~0;
    }

  vec_validate_init_empty (context->per_worker, vec_len (umm->workers) - 1,
                           (upf_ipfix_wk_context_t){});

  ASSERT (is_valid_id (flow_report_index));
  context->flow_report_index = flow_report_index;

  kv.value = ctx_id;
  clib_bihash_add_del_24_8 (&fm->context_by_key, &kv, 1);
  vlib_worker_thread_barrier_release (vm);

  return ctx_id;
}

static void
_upf_ipfix_timer_handler (u16 thread_id, upf_timer_kind_t kind, u32 opaque,
                          u16 opaque2)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  vlib_main_t *vm = vlib_get_main ();

  u32 vlib_now = (u32) vlib_time_now (vm);

  upf_timer_stop_safe (thread_id, &fm->timers_per_worker[thread_id]);

  upf_ipfix_context_t *context;
  pool_foreach (context, fm->contexts)
    {
      vlib_buffer_t *b = upf_ipfix_context_ensure_buffer (vm, context);
      if (b)
        upf_ipfix_export_send (vm, b, context, vlib_now);
    }

  fm->timers_per_worker[thread_id] =
    upf_timer_start_secs (thread_id, 0.5, UPF_TIMER_KIND_IPFIX, 0, 0);
}

clib_error_t *
upf_ipfix_init (vlib_main_t *vm)
{
  upf_ipfix_main_t *fm = &upf_ipfix_main;
  clib_error_t *error = 0;

  /* Set up time reference pair */
  fm->vlib_time_0 = (u32) vlib_time_now (vm);

  fm->log_failure_class =
    vlib_log_register_class_rate_limit ("ipfix", "failure", 1);

  /* initialize the IP/TEID hash's */
  clib_bihash_init_24_8 (&fm->context_by_key, "context_by_key",
                         UPF_IPFIX_MAPPING_BUCKETS,
                         UPF_IPFIX_MAPPING_MEMORY_SIZE);
  /* clib_bihash_set_kvp_format_fn_24_8 (&fm->context_by_key, */
  /* 				      format_ipfix_context_key); */

  fm->is_timers_started = 0;

  upf_timer_set_handler (UPF_TIMER_KIND_IPFIX, _upf_ipfix_timer_handler);

  return error;
}

static bool
compare_cstr_vec (const char *cstr, u8 *vstr)
{
  u32 cl = strlen (cstr);
  u32 vl = vec_len (vstr);

  if (cl == vl)
    if (0 == memcmp (cstr, vstr, cl))
      return true;
  return false;
}

upf_ipfix_policy_t
upf_ipfix_lookup_policy (u8 *name, bool *ok)
{
  upf_main_t *um = &upf_main;

  upf_ipfix_policy_t policy, result = UPF_IPFIX_POLICY_UNSPECIFIED;

  u32 name_len = vec_len (name);
  if (!name_len)
    {
      result = UPF_IPFIX_POLICY_NONE;
      goto _return;
    }

  for (policy = UPF_IPFIX_POLICY_NONE; policy < UPF_IPFIX_N_POLICIES; policy++)
    {
      if (compare_cstr_vec (upf_ipfix_templates[policy].name, name))
        {
          result = policy;
          goto _return;
        }

      if (upf_ipfix_templates[policy].alt_name)
        if (compare_cstr_vec (upf_ipfix_templates[policy].alt_name, name))
          {
            result = policy;
            goto _return;
          }
    }

_return:
  if (result == UPF_IPFIX_POLICY_UNSPECIFIED)
    {
      if (ok)
        *ok = false;

      /* avoid silently ignoring the error */
      vlib_log_err (um->log_class, "Bad IPFIX policy: %v", name);
      return UPF_IPFIX_POLICY_NONE;
    }
  else
    {
      if (ok)
        *ok = true;

      return result;
    }
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
           format (s, "<unknown %d>", policy);
}
