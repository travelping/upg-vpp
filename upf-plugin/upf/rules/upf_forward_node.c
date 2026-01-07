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

#include "upf/upf.h"
#include "upf/upf_stats.h"
#include "upf/nat/nat.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/flow/flowtable_inlines.h"
#include "upf/utils/upf_mt.h"
#include "upf/utils/ip_helpers.h"

#define UPF_DEBUG_ENABLE 0

typedef enum
{
  UPF_FORWARD_NEXT_DROP,
  UPF_FORWARD_NEXT_GTP_IP4_ENCAP,
  UPF_FORWARD_NEXT_GTP_IP6_ENCAP,
  UPF_FORWARD_NEXT_IP_LOOKUP,
  UPF_FORWARD_NEXT_NAT,
  UPF_FORWARD_NEXT_PROXY,
  UPF_FORWARD_N_NEXT,
} upf_forward_next_t;

/* Statistics (not all errors) */
#define foreach_upf_forward_error                                             \
  _ (NO_ERROR, "no error")                                                    \
  _ (FAR_DROP, "FAR action drop")                                             \
  _ (QER_MBR_DROP, "dropped because of QER MBR")                              \
  _ (QER_GATE_DROP, "dropped because of QER Gate")                            \
  _ (URR_DROP, "dropped because of URR")                                      \
  _ (PDR_NO_FAR, "no FAR for PDR")                                            \
  _ (NO_MATCHING_PDR, "no matching PDR")                                      \
  _ (OUTER_HEADER_CREATION_NOT_YET, "OuterHeaderCreation not supported")      \
  _ (OUTER_HEADER_REMOVAL_NOT_YET, "OuterHeaderRemoval not supported")        \
  _ (REDIRECT_NOT_YET, "Redirect not supported")                              \
  _ (NAT_NO_BINDING, "NAT no binding")                                        \
  _ (NAT_UNSUPORTED_IP_PROTO, "NAT unsupported IP proto")                     \
  _ (NAT_OUT_OF_PORTS, "NAT out of ports")

static char *upf_forward_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_forward_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_FORWARD_ERROR_##sym,
  foreach_upf_forward_error
#undef _
    UPF_FORWARD_N_ERROR,
} upf_forward_error_t;

typedef struct
{
  u32 session_index;
  u32 pdr_id;
  u32 far_id;
  upf_forward_next_t next;
} upf_forward_trace_t;

static u8 *
_format_upf_forward_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_forward_trace_t *t = va_arg (*args, upf_forward_trace_t *);

  s = format (s, "upf_session=%d pdr_id=%d far_id=%d next=%d",
              t->session_index, t->pdr_id, t->far_id, t->next);
  return s;
}

always_inline bool
_upf_forward_nat (bool is_ip4, u32 thread_index, vlib_buffer_t *b,
                  flow_entry_t *flow, upf_rules_t *rules,
                  upf_forward_error_t *error)
{
  flowtable_main_t *fm = &flowtable_main;
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, thread_index);

  ASSERT (flow);
  ASSERT (is_valid_id (rules->nat_binding_id));
  ASSERT (is_ip4);

  if (!is_ip4 || !flow || !is_valid_id (rules->nat_binding_id))
    {
      *error = UPF_FORWARD_ERROR_NAT_NO_BINDING;
      return false;
    }

  if (PREDICT_TRUE (flow->proto == IP_PROTOCOL_TCP ||
                    flow->proto == IP_PROTOCOL_UDP))
    {
      /* Allocate NAT flow last moment before forwarding.
       * This way we do not create unneded flows (for drop
       * action), and prevent accounting for traffic for which
       * there is no NAT ports available. */
      if (PREDICT_FALSE (!is_valid_id (flow->nat_flow_id)))
        {
          ip4_header_t *ip = vlib_buffer_get_current (b);
          void *l4_hdr = ip4_next_header (ip);

          u32 nat_flow_id =
            upf_nat_flow_create (thread_index, rules->nat_binding_id, ip,
                                 l4_hdr, flow - fwk->flows);

          upf_debug ("NAT flow creation result: %d", nat_flow_id);
          if (!is_valid_id (nat_flow_id))
            {
              *error = UPF_FORWARD_ERROR_NAT_OUT_OF_PORTS;
              return false;
            }

          flow->nat_flow_id = nat_flow_id;
        }
    }
  else if (PREDICT_FALSE (flow->proto == IP_PROTOCOL_ICMP))
    {
      /*
        We can't track ICMP flows because of difference in ICMP
        keys. Instead it's managed by NAT system.
      */
    }
  else
    {
      *error = UPF_FORWARD_ERROR_NAT_UNSUPORTED_IP_PROTO;
      return false;
    }
  upf_debug ("using NAT flow: %d", flow->nat_flow_id);
  return true;
}

// avoid inlining this function, it's in cold path
static never_inline void
_urrs_create_reports (u16 thread_id, upf_dp_session_t *dsx, upf_rules_t *rules,
                      upf_time_t now)
{
  upf_main_t *um = &upf_main;
  upf_main_wk_t *uwk = vec_elt_at_index (um->workers, thread_id);
  upf_mt_event_t *events_vec = uwk->cached_events_vec;

  upf_usage_reports_trigger (thread_id, dsx, rules, now, &events_vec);

  if (!vec_len (events_vec))
    return;

  upf_mt_event_t ev = {
    .kind = UPF_MT_EVENT_W2M_SESSION_REPORT,
    .w2m_session_report =
      (upf_mt_session_report_t){
        .session_id = dsx - um->dp_sessions,
        .up_seid = dsx->up_seid,
        .report.type = PFCP_REPORT_TYPE_USAR,
        .report.usage_reports_count = vec_len (events_vec),
      },
  };

  vec_add1 (events_vec, ev);

  upf_mt_enqueue_to_main (thread_id, events_vec, vec_len (events_vec));
  vec_reset_length (events_vec);
  uwk->cached_events_vec = events_vec;

  upf_stats_get_wk_generic (thread_id)->session_reports_generated += 1;
}

static bool
_urs_has_enough_quota_for_packet (upf_dp_session_t *dsx, upf_rules_t *rules,
                                  upf_urr_lid_t urr_lid, uword packet_len,
                                  bool is_ul)
{
  rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);

  upf_debug ("urr [%d] pfcp_id %u", urr_lid, urr->pfcp_id);
#if UPF_DEBUG_ENABLE > 0
  {
    urr_counter_t *tl = &urr->vol.threshold_left;
    urr_counter_t *ts = &urr->vol.threshold_set;
    urr_counter_t *ql = &urr->vol.quota_left;
    urr_counter_t *qs = &urr->vol.quota_set;
    urr_counter_t *mb = &urr->vol.measure.bytes;
    urr_counter_t *mp = &urr->vol.measure.packets;

    upf_debug ("tl:%u (%u,%u) ts:%u (%u,%u)", tl->tot, tl->ul, tl->dl, ts->tot,
               ts->ul, ts->dl);
    upf_debug ("ql:%u (%u,%u) qs:%u (%u,%u)", ql->tot, ql->ul, ql->dl, qs->tot,
               qs->ul, qs->dl);
    upf_debug ("mb:%u (%u,%u) mp:%u (%u,%u)", mb->tot, mb->ul, mb->dl, mp->tot,
               mp->ul, mp->dl);
  }
#endif

  if (PREDICT_FALSE (urr->status.out_of_volume_quota))
    return false;

  if (PREDICT_FALSE (urr->status.out_of_time_quota))
    return false;

  urr_counter_t *q_left = &urr->vol.quota_left;
  urr_counter_t *meas = &urr->vol.measure.bytes;

  // check if current packet will trigger out of quota
  bool over_tot =
    urr->has_quota_tot && ((meas->tot + packet_len) > q_left->tot);

  bool over_uld;
  if (is_ul)
    over_uld = urr->has_quota_ul && ((meas->ul + packet_len) > q_left->ul);
  else
    over_uld = urr->has_quota_dl && ((meas->dl + packet_len) > q_left->dl);

  if (PREDICT_TRUE (!(over_tot || over_uld)))
    return true;

  upf_debug ("out of quota (total:%u, %s:%u) is_thresh_sent %d", over_tot,
             is_ul ? "ul" : "dl", over_uld,
             urr->status.did_sent_volume_threshold);

  // account time before marking out of quota
  upf_urr_time_measure_advance (urr, upf_time_now (vlib_get_thread_index ()));
  urr->status.out_of_volume_quota = true;

  if (!(urr->enabled_triggers & PFCP_REPORTING_TRIGGER_VOLUME_QUOTA))
    return false;

  // TODO: make it conditional like (um->pfcp_spec_version >= 16)
  // For now keep old behavior, since this requires CP testing
  bool is_release_15_or_older = false;

  if (is_release_15_or_older && urr->status.did_sent_volume_threshold)
    // threshold report already sent
    return false;

  urr->next_report_triggers |= PFCP_USAGE_REPORT_TRIGGER_VOLUME_QUOTA;
  upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);

  return false;
}

static bool
_urrs_has_enough_quota_for_packet (upf_dp_session_t *dsx, upf_rules_t *rules,
                                   rules_pdr_t *pdr, uword packet_len)
{
  bool is_ul = pdr->is_uplink;

  bool result_has_quota = true;

  upf_lidset_foreach (urr_lid, &pdr->volume_urr_lids)
    {
      bool urr_has_quota = _urs_has_enough_quota_for_packet (
        dsx, rules, urr_lid, packet_len, is_ul);

      if (!urr_has_quota)
        result_has_quota = false;
    }

  return result_has_quota;
}

static void
_urrs_consume_quota_for_packet (upf_dp_session_t *dsx, upf_rules_t *rules,
                                rules_pdr_t *pdr, uword packet_len,
                                upf_time_t now)
{
  bool is_ul = pdr->is_uplink;

  upf_debug ("urr lids: %U", format_upf_lidset, &pdr->volume_urr_lids);
  upf_lidset_foreach (urr_lid, &pdr->volume_urr_lids)
    {
      rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);

      ASSERT (!urr->status.out_of_volume_quota &&
              !urr->status.out_of_time_quota);

      // TODO: by spec time_of_X_packet should be after forwarding (with
      // quota/QoS), but previous versions of UPF reported before forwarding
      // (before quota/QoS). For now keep old behavior, check later
      if (PREDICT_FALSE (urr->timestamps.first_packet == 0))
        urr->timestamps.first_packet = now;
      urr->timestamps.last_packet = now;

      urr_counter_t *t_set = &urr->vol.threshold_set;
      urr_counter_t *t_left = &urr->vol.threshold_left;
      urr_counter_t *meas_bytes = &urr->vol.measure.bytes;
      urr_counter_t *meas_packets = &urr->vol.measure.packets;

      // Increase packets and bytes measurements
      meas_packets->tot += 1;
      meas_bytes->tot += packet_len;
      if (is_ul)
        {
          meas_packets->ul += 1;
          meas_bytes->ul += packet_len;
        }
      else
        {
          meas_packets->dl += 1;
          meas_bytes->dl += packet_len;
        }

      if (!(urr->enabled_triggers & PFCP_REPORTING_TRIGGER_VOLUME_THRESHOLD))
        continue;

      // check if we reached threshold
      bool hit_tot = t_set->tot && meas_bytes->tot >= t_left->tot;
      bool hit_dl = t_set->dl && meas_bytes->dl >= t_left->dl;
      bool hit_ul = t_set->ul && meas_bytes->ul >= t_left->ul;

      bool threshold_reached = hit_tot || hit_dl || hit_ul;
      if (PREDICT_TRUE (!threshold_reached))
        continue;

      // update time measure for report
      upf_urr_time_measure_advance (urr,
                                    upf_time_now (vlib_get_thread_index ()));

      urr->next_report_triggers |= PFCP_USAGE_REPORT_TRIGGER_VOLUME_THRESHOLD;
      upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);
      // threshold values will be reset during report
    }
}

static void
_urrs_handle_events_for_packet (upf_dp_session_t *dsx, upf_rules_t *rules,
                                rules_pdr_t *pdr, uword packet_len,
                                upf_time_t now, vlib_buffer_t *b, bool is_ip4)
{
  upf_main_t *um = &upf_main;

  upf_lidset_foreach (urr_lid, &pdr->urr_lids)
    {
      rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);

      if (!urr->measurement_method_event)
        continue;

      if ((urr->enabled_triggers & PFCP_REPORTING_TRIGGER_START_OF_TRAFFIC))
        {
          void *iph = b->data + vnet_buffer (b)->l3_hdr_offset;
          urr_start_of_traffic_ev_t sot = {
            .ue_ip = ip46_address_initializer,
            .nwi_id = pdr->nwi_id,
          };

          if (is_ip4)
            {
              ip4_header_t *ip4 = (ip4_header_t *) (is_ip4 ? iph : 0);
              ASSERT ((ip4->ip_version_and_header_length & 0xF0) == 0x40);

              if (pdr->is_uplink)
                ip46_address_set_ip4 (&sot.ue_ip, &ip4->src_address);
              else
                ip46_address_set_ip4 (&sot.ue_ip, &ip4->dst_address);
            }
          else
            {
              ip6_header_t *ip6 = (ip6_header_t *) (is_ip4 ? 0 : iph);
              ASSERT ((ip6->ip_version_traffic_class_and_flow_label & 0xF0) ==
                      0x60);

              if (pdr->is_uplink)
                ip46_address_set_ip6 (&sot.ue_ip, &ip6->src_address);
              else
                ip46_address_set_ip6 (&sot.ue_ip, &ip6->dst_address);
            }

          if (urr->mhash_traffic_by_ue == NULL)
            {
              urr->mhash_traffic_by_ue = clib_mem_alloc (sizeof (mhash_t));
              memset (urr->mhash_traffic_by_ue, 0,
                      sizeof (*urr->mhash_traffic_by_ue));
              mhash_init (urr->mhash_traffic_by_ue, sizeof (upf_time_t),
                          sizeof (urr_start_of_traffic_ev_t));
            }

          upf_time_t *p_last_sent =
            (upf_time_t *) mhash_get (urr->mhash_traffic_by_ue, &sot);
          if (p_last_sent)
            {
              upf_time_t last_sent = *p_last_sent;
              // Poors man rate limiting for single session
              if (now <= (last_sent + um->start_of_traffic_event_timeout_s))
                {
                  upf_debug ("rate limit last_sent: %U, ue_ip %U, nwi %u",
                             format_upf_time, p_last_sent, format_ip46_address,
                             &sot.ue_ip, IP46_TYPE_ANY, sot.nwi_id);
                  continue;
                }
            }

          if (!ratelimit_atomic_consume (&um->start_of_traffic_rate_limit,
                                         now))
            {
              // TODO: add warning via metric
              upf_debug ("rate limit start ev: %U, ue_ip %U, nwi %u",
                         format_upf_time, p_last_sent, format_ip46_address,
                         &sot.ue_ip, IP46_TYPE_ANY, sot.nwi_id);
              continue;
            }

          upf_debug ("sending last_sent: %U, ue_ip %U, nwi %u",
                     format_upf_time, p_last_sent, format_ip46_address,
                     &sot.ue_ip, IP46_TYPE_ANY, sot.nwi_id);

          if (pdr->is_tdf_unsolicited)
            upf_stats_get_wk_generic (dsx->thread_id)
              ->unsolicited_ip_reports += 1;

          mhash_set_mem (urr->mhash_traffic_by_ue, &sot, (uword *) &now, NULL);

          ASSERT ((p_last_sent = (upf_time_t *) mhash_get (
                     urr->mhash_traffic_by_ue, &sot)));
          ASSERT (p_last_sent && *p_last_sent == now);

          if (!is_valid_id (dsx->clear_traffic_by_ue_timer_id.as_u32))
            {
              dsx->clear_traffic_by_ue_timer_id = upf_timer_start_secs (
                dsx->thread_id, um->start_of_traffic_event_timeout_s,
                UPF_TIMER_KIND_UE_TRAFFIC_HASH_CLEANUP, dsx - um->dp_sessions,
                -1);
            }

          // do not set, instead it will be detected by vec_len of reports
          // urr->next_report_triggers |=
          //   PFCP_USAGE_REPORT_TRIGGER_START_OF_TRAFFIC;
          upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);

          vec_add1 (urr->events_start_of_traffic, sot);
        }
    }
}

/**
 * @brief Function to process URRs.
 *
 * @return true if the packet consumed the quota and is allowed to be forwarded
 */
static bool
_process_urrs (u16 thread_id, upf_dp_session_t *dsx, upf_rules_t *rules,
               rules_pdr_t *pdr, upf_time_t now, bool do_forward,
               uword packet_len, vlib_buffer_t *b, bool is_ip4)
{
  if (pdr->is_uplink)
    dsx->last_ul_traffic = now;
  else
    dsx->last_dl_traffic = now;

  // 3GPP TS 29.244
  // > Thresholds provisioned in a URR shall apply to the traffic usage after
  // any QoS enforcement.

  if (do_forward)
    do_forward =
      _urrs_has_enough_quota_for_packet (dsx, rules, pdr, packet_len);

  if (PREDICT_TRUE (do_forward))
    _urrs_consume_quota_for_packet (dsx, rules, pdr, packet_len, now);

  if (PREDICT_FALSE (pdr->has_event_urrs))
    _urrs_handle_events_for_packet (dsx, rules, pdr, packet_len, now, b,
                                    is_ip4);

  if (PREDICT_FALSE (
        !upf_lidset_is_empty (&dsx->scheduled_usage_reports_lids)))
    _urrs_create_reports (thread_id, dsx, rules, now);

  return do_forward;
}

static bool
_process_qers (upf_rules_t *rules, rules_pdr_t *pdr, f32 vlib_now,
               uword packet_len, upf_forward_error_t *error)
{
  if (upf_lidset_is_empty (&pdr->qer_lids))
    return true;

  bool is_ul = pdr->is_uplink;
  upf_dir_t dir = is_ul ? UPF_DIR_UL : UPF_DIR_DL;

  upf_debug ("qer lids: %U", format_upf_lidset, &pdr->qer_lids);
  upf_lidset_foreach (qer_lid, &pdr->qer_lids)
    {
      rules_qer_t *qer = upf_rules_get_qer (rules, qer_lid);

      if ((is_ul && qer->gate_closed_ul) || (!is_ul && qer->gate_closed_dl))
        {
          *error = UPF_FORWARD_ERROR_QER_GATE_DROP;
          return false;
        }

      if (PREDICT_TRUE (qer->has_mbr))
        {
          tokenbucket_refill (&qer->policer_bytes[dir], vlib_now);
          if (!tokenbucket_can_consume (&qer->policer_bytes[dir], packet_len))
            {
              *error = UPF_FORWARD_ERROR_QER_MBR_DROP;
              return false;
            }
        }
    }

  upf_debug ("QERs allowed forward (plen %d)", packet_len);

  // TODO: should be after URR?
  // now we can consume tokens
  upf_lidset_foreach (qer_lid, &pdr->qer_lids)
    {
      rules_qer_t *qer = upf_rules_get_qer (rules, qer_lid);

      if (PREDICT_TRUE (qer->has_mbr))
        tokenbucket_consume (&qer->policer_bytes[dir], packet_len);
    }

  return true;
}

static_always_inline void
_upf_forward_stat_count_packet (u32 thread_index, ip_protocol_t proto,
                                u32 packet_len, bool is_ul, bool is_ip4)
{
  upf_stat_wk_generic_counter_t counter_proto;
  upf_stat_wk_generic_counter_t counter_bytes;
  upf_stat_wk_generic_counter_t counter_sum;
  if (is_ul)
    {
      if (is_ip4)
        {
          counter_proto = UPF_STAT_WK_GENERIC_COUNTER_packet_proto_ip4_ul_tcp;
          counter_bytes = UPF_STAT_WK_GENERIC_COUNTER_packet_size_ip4_ul_64b;
          counter_sum =
            UPF_STAT_WK_GENERIC_COUNTER_packet_size_ip4_ul_sum_bytes;
        }
      else
        {
          counter_proto = UPF_STAT_WK_GENERIC_COUNTER_packet_proto_ip6_ul_tcp;
          counter_bytes = UPF_STAT_WK_GENERIC_COUNTER_packet_size_ip6_ul_64b;
          counter_sum =
            UPF_STAT_WK_GENERIC_COUNTER_packet_size_ip6_ul_sum_bytes;
        }
    }
  else
    {
      if (is_ip4)
        {
          counter_proto = UPF_STAT_WK_GENERIC_COUNTER_packet_proto_ip4_dl_tcp;
          counter_bytes = UPF_STAT_WK_GENERIC_COUNTER_packet_size_ip4_dl_64b;
          counter_sum =
            UPF_STAT_WK_GENERIC_COUNTER_packet_size_ip4_dl_sum_bytes;
        }
      else
        {
          counter_proto = UPF_STAT_WK_GENERIC_COUNTER_packet_proto_ip6_dl_tcp;
          counter_bytes = UPF_STAT_WK_GENERIC_COUNTER_packet_size_ip6_dl_64b;
          counter_sum =
            UPF_STAT_WK_GENERIC_COUNTER_packet_size_ip6_dl_sum_bytes;
        }
    }

  // select proto counter
  if (proto == IP_PROTOCOL_TCP)
    counter_proto += 0;
  else if (proto == IP_PROTOCOL_UDP)
    counter_proto += 1;
  else if (proto == IP_PROTOCOL_ICMP || proto == IP_PROTOCOL_ICMP6)
    counter_proto += 2;
  else
    counter_proto += 3; // unknown

  upf_stats_get_wk_generic (thread_index)->_counters[counter_proto] += 1;

  // do not consume more then single cache line, while keeping
  // size pow2 to be able to mask by it
  static __attribute__ ((aligned (CLIB_CACHE_LINE_BYTES)))
  u8 _target_bucket_lut[16] = {
    0, 0, 0, 0, 0, 0,
    1, // Index 6  (for packet_len=65..128) -> Bucket 1
    2, // Index 7  (for packet_len=129..256) -> Bucket 2
    3, // Index 8  (for packet_len=257..512) -> Bucket 3
    4, // Index 9  (for packet_len=513..1024) -> Bucket 4
    5, // Index 10+ (for packet_len>=1025) -> Bucket 5 (Infinity)
    5, 5, 5, 5, 5,
  };

  // Do -1, because buckets are less or equal to size, and we need to unset
  // highest bit for them. Example: (0b1000 - 1 = 0b0111)
  counter_bytes += _target_bucket_lut[min_log2 (packet_len - 1)] &
                   (ARRAY_LEN (_target_bucket_lut) - 1);

  upf_debug ("stat packet len: %d min log2: %d min log2(-1): %d", packet_len,
             min_log2 (packet_len), min_log2 (packet_len - 1));

  upf_stats_get_wk_generic (thread_index)->_counters[counter_bytes] += 1;
  upf_stats_get_wk_generic (thread_index)->_counters[counter_sum] +=
    packet_len;
}

static uword
_upf_forward (vlib_main_t *vm, vlib_node_runtime_t *node,
              vlib_frame_t *from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *um = &upf_main;

  flowtable_main_t *fm = &flowtable_main;

  u32 thread_index = vm->thread_index;
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, thread_index);

  f32 vlib_now_f32 = vlib_time_now (vm);
  upf_time_t unix_now = upf_time_now (thread_index);

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 next = 0;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      u32 error;
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

          error = UPF_FORWARD_ERROR_NO_ERROR;
          next = UPF_FORWARD_NEXT_DROP;

          b = vlib_get_buffer (vm, bi);
          UPF_CHECK_INNER_NODE (b);

          u32 session_id = upf_buffer_opaque (b)->gtpu.session_id;
          upf_dp_session_t *dsx =
            upf_wk_get_dp_session (thread_index, session_id);

          upf_rules_t *rules = upf_wk_get_rules (thread_index, dsx->rules_id);

          u32 flow_id = upf_buffer_opaque (b)->gtpu.flow_id;
          flow_entry_t *flow = NULL;
          if (is_valid_id (flow_id))
            flow = pool_elt_at_index (fwk->flows, flow_id);

          ASSERT (is_valid_id (upf_buffer_opaque (b)->gtpu.pdr_lid));

          upf_lid_t pdr_lid = upf_buffer_opaque (b)->gtpu.pdr_lid;
          if (!is_valid_id (pdr_lid))
            {
              error = UPF_FORWARD_ERROR_NO_MATCHING_PDR;
              next = UPF_FORWARD_NEXT_DROP;
              goto trace;
            }

          bool is_uplink = upf_buffer_opaque (b)->gtpu.is_uplink;
          rules_pdr_t *pdr = upf_rules_get_pdr (rules, pdr_lid);

          rules_far_t *far = NULL;
          if (is_valid_id (pdr->far_lid))
            far = upf_rules_get_far (rules, pdr->far_lid);

          upf_debug ("IP hdr: %U", format_ip_header,
                     vlib_buffer_get_current (b), b->current_length);
          upf_debug ("PDR %u FAR %u uplink %d pdr intf %U far intf %U",
                     pdr->pfcp_id, far ? far->pfcp_id : 0, is_uplink,
                     format_upf_interface_type, pdr->src_intf,
                     format_upf_interface_type,
                     far ? far->forward.dst_intf : -1);

          bool action_forward = false;
          bool is_proxy_skip_urr = false;

          if (far && far->apply_action == UPF_FAR_ACTION_FORWARD)
            {
              bool do_proxy_inject = false;
              if (flow && flow->is_tcp_proxy)
                {
                  bool is_proxied = upf_buffer_opaque (b)->gtpu.is_proxied;

                  if (!is_proxied)
                    // if proxy haven't been entered yet
                    do_proxy_inject = true;

                  if (is_uplink)
                    // account uplink packets before proxy
                    is_proxy_skip_urr = is_proxied;
                  else
                    // account downlink packets after proxy
                    is_proxy_skip_urr = !is_proxied;
                }

              if (do_proxy_inject)
                {
                  next = UPF_FORWARD_NEXT_PROXY;
                  action_forward = true;
                }
              else if (far->forward.has_outer_header_creation)
                {
                  upf_gtpu_main_t *ugm = &upf_gtpu_main;
                  upf_gtpu_endpoint_t *gtpu_ep = pool_elt_at_index (
                    ugm->endpoints, far->forward.ohc.src_gtpu_endpoint_id);

                  // TODO: implement "prefer_ipv6" argument for gtpu endpoint
                  // during creation to reverse order of this checks
                  if (far->forward.has_outer_addr4 && gtpu_ep->has_ip4)
                    {
                      next = UPF_FORWARD_NEXT_GTP_IP4_ENCAP;
                      action_forward = true;
                    }
                  else if (far->forward.has_outer_addr6 && gtpu_ep->has_ip6)
                    {
                      next = UPF_FORWARD_NEXT_GTP_IP6_ENCAP;
                      action_forward = true;
                    }
                  else
                    {
                      error = UPF_FORWARD_ERROR_OUTER_HEADER_CREATION_NOT_YET;
                      next = UPF_FORWARD_NEXT_DROP;
                      goto trace;
                    }
                }
              else if (flow && far->forward.do_nat)
                {
                  ASSERT (flow);
                  if (!_upf_forward_nat (is_ip4, thread_index, b, flow, rules,
                                         &error))
                    next = UPF_FORWARD_NEXT_DROP;
                  else
                    {
                      next = UPF_FORWARD_NEXT_NAT;
                      action_forward = true;
                    }
                }
              else // usual IP forwarding
                {
                  bool is_gtpu = (upf_buffer_opaque (b)->gtpu.packet_source ==
                                  UPF_PACKET_SOURCE_GTPU);
                  bool ohr = pdr->gtpu_outer_header_removal;

                  if (is_gtpu && ohr)
                    ; // already done by gtpu_decap
                  else if (!is_gtpu && !ohr)
                    ; // nothing to do
                  else if (is_gtpu && !ohr)
                    { // account and forward with outer header included
                      is_ip4 = upf_buffer_opaque (b)->gtpu.is_gtpu_v4;
                      vlib_buffer_advance (
                        b, -upf_buffer_opaque (b)->gtpu.outer_hdr_len);
                    }
                  else if (!is_gtpu && ohr)
                    {
                      bool was_in_tcp_stack =
                        upf_buffer_opaque (b)->gtpu.packet_source ==
                        UPF_PACKET_SOURCE_TCP_STACK;
                      rules_tep_t *tep =
                        upf_rules_get_tep (rules, pdr->traffic_ep_lid);
                      bool originally_gtpu = tep->is_gtpu;

                      if (was_in_tcp_stack && originally_gtpu)
                        {
                          // it's ok, header discared before entering tcp
                        }
                      else
                        {
                          ASSERT (0); // validated during rules creation
                          error =
                            UPF_FORWARD_ERROR_OUTER_HEADER_REMOVAL_NOT_YET;
                          next = UPF_FORWARD_NEXT_DROP;
                          goto trace;
                        }
                    }

                  next = UPF_FORWARD_NEXT_IP_LOOKUP;
                  action_forward = true;

                  upf_nwi_t *nwi =
                    pool_elt_at_index (um->nwis, far->forward.nwi_id);
                  upf_interface_t *nwif = pool_elt_at_index (
                    um->nwi_interfaces,
                    nwi->interfaces_ids[far->forward.dst_intf]);

                  if (is_ip4)
                    {
                      vnet_buffer_offload_flags_clear (
                        b, (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
                            VNET_BUFFER_OFFLOAD_F_UDP_CKSUM |
                            VNET_BUFFER_OFFLOAD_F_IP_CKSUM));

                      vnet_buffer (b)->sw_if_index[VLIB_TX] =
                        nwif->tx_fib_index[FIB_PROTOCOL_IP4];
                    }
                  else
                    {
                      vnet_buffer_offload_flags_clear (
                        b, (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
                            VNET_BUFFER_OFFLOAD_F_UDP_CKSUM));
                      vnet_buffer (b)->sw_if_index[VLIB_TX] =
                        nwif->tx_fib_index[FIB_PROTOCOL_IP6];
                    }

                  if (far->forward.has_forwarding_policy)
                    {
                      upf_forwarding_policy_t *fp =
                        pool_elt_at_index (um->forwarding_policies,
                                           far->forward.forwarding_policy_id);

                      if (!fp->is_removed)
                        {
                          u32 fp_fib_id =
                            is_ip4 ? fp->ip4_fib_id : fp->ip6_fib_id;

                          /*
                           * the Forwarding Policy might not contain an entry
                           * for the IP version of the buffer. In that case,
                           * just not alter already present normal FAR
                           * settings.
                           */
                          if (is_valid_id (fp_fib_id))
                            vnet_buffer (b)->sw_if_index[VLIB_TX] = fp_fib_id;
                        }
                    }
                }
            }
          else if (far)
            {
              ASSERT (far->apply_action == UPF_FAR_ACTION_DROP);

              if (pdr->is_tdf_unsolicited)
                upf_stats_get_wk_generic (thread_index)
                  ->unsolicited_packets_dropped += 1;

              error = UPF_FORWARD_ERROR_FAR_DROP;
              next = UPF_FORWARD_NEXT_DROP;
            }
          else
            {
              error = UPF_FORWARD_ERROR_PDR_NO_FAR;
              next = UPF_FORWARD_NEXT_DROP;
            }

          if (PREDICT_TRUE (!is_proxy_skip_urr))
            {
              uword packet_len = vlib_buffer_length_in_chain (vm, b);

              bool qer_forward = false;
              if (action_forward)
                {
                  qer_forward = _process_qers (rules, pdr, vlib_now_f32,
                                               packet_len, &error);
                }

              bool urr_forward =
                _process_urrs (thread_index, dsx, rules, pdr, unix_now,
                               qer_forward, packet_len, b, is_ip4);

              if (!urr_forward)
                {
                  next = UPF_FORWARD_NEXT_DROP;

                  if (qer_forward) // if before urr packet wasn't dropped
                    error = UPF_FORWARD_ERROR_URR_DROP;
                  else if (action_forward)
                    {
                      // filled by process_qers
                    }
                }
              else
                {
                  ip_protocol_t proto;
                  if (flow)
                    {
                      _flow_update_stats (vm, b, flow, is_ip4, unix_now,
                                          packet_len);
                      upf_ipfix_flow_stats_update_handler (flow,
                                                           (u32) vlib_now_f32);
                      proto = flow->proto;
                    }
                  else
                    {
                      void *l3hdr = b->data + vnet_buffer (b)->l3_hdr_offset;
                      if (is_ip4)
                        proto = ((ip4_header_t *) l3hdr)->protocol;
                      else
                        proto = ((ip6_header_t *) l3hdr)->protocol;
                    }
                  _upf_forward_stat_count_packet (
                    thread_index, proto, packet_len, pdr->is_uplink, is_ip4);
                }
            }

          if (next != UPF_FORWARD_NEXT_DROP)
            goto trace_no_error;

        trace:
          b->error = node->errors[error];

        trace_no_error:
          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_forward_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));
              tr->session_index = session_id;
              tr->pdr_id = pdr ? pdr->pfcp_id : ~0;
              tr->far_id = far ? far->pfcp_id : ~0;
              tr->next = next;
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi, next);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_forward_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_forward (vm, node, from_frame, /* is_ip4 */
                       1);
}

VLIB_NODE_FN (upf_ip6_forward_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_forward (vm, node, from_frame, /* is_ip4 */
                       0);
}

VLIB_REGISTER_NODE (upf_ip4_forward_node) = {
  .name = "upf-ip4-forward",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_forward_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_forward_error_strings),
  .error_strings = upf_forward_error_strings,
  .n_next_nodes = UPF_FORWARD_N_NEXT,
  .next_nodes = {
    [UPF_FORWARD_NEXT_DROP]          = "error-drop",
    [UPF_FORWARD_NEXT_GTP_IP4_ENCAP] = "upf-gtp-encap4",
    [UPF_FORWARD_NEXT_GTP_IP6_ENCAP] = "upf-gtp-encap6",
    [UPF_FORWARD_NEXT_IP_LOOKUP]     = "ip4-lookup",
    [UPF_FORWARD_NEXT_NAT]           = "upf-ip4-nat-forward",
    [UPF_FORWARD_NEXT_PROXY]         = "upf-ip4-proxy-input",
  },
};

VLIB_REGISTER_NODE (upf_ip6_forward_node) = {
  .name = "upf-ip6-forward",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_forward_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_forward_error_strings),
  .error_strings = upf_forward_error_strings,
  .n_next_nodes = UPF_FORWARD_N_NEXT,
  .next_nodes = {
    [UPF_FORWARD_NEXT_DROP]          = "error-drop",
    [UPF_FORWARD_NEXT_GTP_IP4_ENCAP] = "upf-gtp-encap4",
    [UPF_FORWARD_NEXT_GTP_IP6_ENCAP] = "upf-gtp-encap6",
    [UPF_FORWARD_NEXT_IP_LOOKUP]     = "ip6-lookup",
    [UPF_FORWARD_NEXT_NAT]           = "upf-ip4-nat-forward", // should not happen
    [UPF_FORWARD_NEXT_PROXY]         = "upf-ip6-proxy-input",
  },
};
