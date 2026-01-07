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

#ifndef UPF_FLOW_FLOWTABLE_INLINES_H_
#define UPF_FLOW_FLOWTABLE_INLINES_H_

#include "upf/flow/flowtable.h"
#include "upf/flow/flowtable_tcp.h"

#include "upf/utils/upf_timer.h"
#include "upf/core/upf_buffer_opaque.h"

static const flowtable_timeout_type_t _tcp_state_timeout[TCP_F_STATE_MAX] = {
  [TCP_F_STATE_START] = FT_TIMEOUT_TYPE_TCP_OPENING,
  [TCP_F_STATE_SYN] = FT_TIMEOUT_TYPE_TCP_OPENING,
  [TCP_F_STATE_SYNACK] = FT_TIMEOUT_TYPE_TCP_ESTABLISHED,
  [TCP_F_STATE_ESTABLISHED] = FT_TIMEOUT_TYPE_TCP_ESTABLISHED,
  [TCP_F_STATE_FIN] = FT_TIMEOUT_TYPE_TCP_CLOSING,
  [TCP_F_STATE_FINACK] = FT_TIMEOUT_TYPE_TCP_CLOSING,
  [TCP_F_STATE_RST] = FT_TIMEOUT_TYPE_TCP_CLOSING,
};

always_inline void
_flow_tcp_update_lifetime (flowtable_wk_t *fwk, flow_entry_t *f,
                           tcp_header_t *hdr)
{
  flowtable_main_t *fm = &flowtable_main;
  tcp_f_state_t old_state, new_state;

  ASSERT (f->tcp_state < TCP_F_STATE_MAX);

  old_state = f->tcp_state;
  new_state = tcp_trans[old_state][tcp_event (hdr)];

  if (new_state && old_state != new_state)
    {
      f->tcp_state = new_state;
      f->lifetime_ticks =
        fm->timer_lifetime_ticks[_tcp_state_timeout[new_state]];

      upf_timer_stop_safe (fwk - fm->workers, &f->timer_id);
      flowtable_entry_start_timer (fwk, f);
    }
}

// return true if flow is classified, otherwise requres classify
__clib_unused always_inline bool
_upf_opaque_set_flow_values (flowtable_wk_t *fwk, vlib_buffer_t *b,
                             flow_entry_t *flow, bool is_uplink)
{
  upf_buffer_opaque (b)->gtpu.is_uplink = is_uplink;
  upf_buffer_opaque (b)->gtpu.flow_id = flow - fwk->flows;

  upf_lid_t pdr_lid = flow->pdr_lids[is_uplink ? UPF_DIR_UL : UPF_DIR_DL];
  upf_buffer_opaque (b)->gtpu.pdr_lid = pdr_lid;
  return is_uplink ? flow->is_classified_ul : flow->is_classified_dl;
}

__clib_unused always_inline void
_flow_update (flowtable_wk_t *fwk, flow_entry_t *f, u8 *iph, void *l4hdr,
              u8 is_ip4, u16 len)
{
  upf_timer_main_t *utm = &upf_timer_main;

  u16 thread_id = fwk - flowtable_main.workers;
  upf_timer_wk_t *utw = vec_elt_at_index (utm->workers, thread_id);

  f->last_packet_tick = utw->now_tick;

  if (f->proto == IP_PROTOCOL_TCP &&
      PREDICT_TRUE (len >= sizeof (tcp_header_t)))
    _flow_tcp_update_lifetime (fwk, f, l4hdr);
}

__clib_unused always_inline void
_flow_update_stats (vlib_main_t *vm, vlib_buffer_t *b, flow_entry_t *f,
                    u8 is_ip4, upf_time_t unix_now, u16 packet_len)
{
  bool is_uplink = upf_buffer_opaque (b)->gtpu.is_uplink;

  flow_side_stats_t *stats = &f->stats[is_uplink ? UPF_DIR_UL : UPF_DIR_DL];
  stats->pkts++;
  stats->pkts_unreported++;
  stats->bytes += packet_len;
  stats->bytes_unreported += packet_len;

  f->unix_last_time = unix_now;
}

#endif // UPF_FLOW_FLOWTABLE_INLINES_H_