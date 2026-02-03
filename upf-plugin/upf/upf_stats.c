/*
 * Copyright (c) 2024-2025 Travelping GmbH
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

#include <vppinfra/vec.h>

#include "upf/upf_stats.h"
#include "upf/utils/common.h"

upf_stats_main_t upf_stats_main;

void
upf_stats_init ()
{
  upf_stats_main_t *usm = &upf_stats_main;

  // Ideally we should store vlib_stats_add_symlink result somewhere, but we
  // never cleanup symlinks, so ignore it

  usm->entries.generic_counters =
    vlib_stats_add_counter_vector ("/upf/counters");
  vlib_stats_validate (usm->entries.generic_counters, 0, UPF_STAT_N_GENERIC);
  upf_stats_clear_counter_vector (usm->entries.generic_counters, 0);
  usm->counters.generic =
    vec_elt ((counter_t **) vlib_stats_get_entry_data_pointer (
               usm->entries.generic_counters),
             0);
#define _(N, PATH)                                                            \
  vlib_stats_add_symlink (usm->entries.generic_counters,                      \
                          UPF_STAT_GENERIC_##N, "/upf/%s", PATH);
  foreach_upf_counter_generic
#undef _

    usm->entries.nat_pool_names =
    vlib_stats_add_string_vector ("/upf/nat/pool/name");
  usm->entries.nat_pool_nwi_names =
    vlib_stats_add_string_vector ("/upf/nat/pool/nwi_name");
  usm->entries.nat_pool_counters =
    vlib_stats_add_counter_vector ("/upf/nat/pool/counters");
#define _(N)                                                                  \
  vlib_stats_add_symlink (usm->entries.nat_pool_counters,                     \
                          UPF_STAT_NAT_POOL_##N, "/upf/nat/pool/%s", #N);
  foreach_upf_counter_per_nat_pool
#undef _

    usm->entries.gtpu_endpoint_nwi_names =
    vlib_stats_add_string_vector ("/upf/gtpu/endpoint/nwi_name");
  usm->entries.gtpu_endpoint_ip4 =
    vlib_stats_add_string_vector ("/upf/gtpu/endpoint/ip4");
  usm->entries.gtpu_endpoint_ip6 =
    vlib_stats_add_string_vector ("/upf/gtpu/endpoint/ip6");
  usm->entries.gtpu_counters =
    vlib_stats_add_counter_vector ("/upf/gtpu/endpoint/counters");
#define _(N)                                                                  \
  vlib_stats_add_symlink (usm->entries.gtpu_counters,                         \
                          UPF_STAT_GTPU_ENDPOINT_##N,                         \
                          "/upf/gtpu/endpoint/%s", #N);
  foreach_upf_counter_per_gtpu_endpoint
#undef _

    usm->entries.nwi_names = vlib_stats_add_string_vector ("/upf/nwi/name");
  usm->entries.nwi_counters =
    vlib_stats_add_counter_vector ("/upf/nwi/counters");
#define _(N)                                                                  \
  vlib_stats_add_symlink (usm->entries.nwi_counters, UPF_STAT_NWI_##N,        \
                          "/upf/nwi/%s", #N);
  foreach_upf_counter_per_nwi
#undef _

    usm->entries.thread_counters =
    vlib_stats_add_counter_vector ("/upf/thread/counters");
#define _(N)                                                                  \
  vlib_stats_add_symlink (usm->entries.thread_counters, UPF_STAT_THREAD_##N,  \
                          "/upf/thread/%s", #N);
  foreach_upf_counter_per_thread
#undef _

    usm->entries.pfcp_message_names =
    vlib_stats_add_string_vector ("/upf/pfcp/message/name");
  usm->entries.pfcp_message_counters =
    vlib_stats_add_counter_vector ("/upf/pfcp/message/counters");
#define _(N)                                                                  \
  vlib_stats_add_symlink (usm->entries.pfcp_message_counters,                 \
                          UPF_STAT_PFCP_MESSAGE_##N, "/upf/pfcp/message/%s",  \
                          #N);
  foreach_upf_counter_per_pfcp_message
#undef _

    usm->wk.generic.stat_segment_name = "/upf/wk/generic_counters";
  vlib_validate_simple_counter (&usm->wk.generic,
                                UPF_STAT_N_WK_GENERIC_COUNTER);
  vlib_clear_simple_counters (&usm->wk.generic);

#define _(N, PATH)                                                            \
  vlib_stats_add_symlink (usm->wk.generic.stats_entry_index,                  \
                          UPF_STAT_WK_GENERIC_COUNTER_##N, "/upf/wk/%s",      \
                          PATH);
  foreach_upf_wk_counter_generic
#undef _

    usm->wk.nat_pool_in2out.stat_segment_name = "/upf/nat/pool/in2out";
  usm->wk.nat_pool_out2in.stat_segment_name = "/upf/nat/pool/out2in";
  usm->wk.nat_pool_flows.stat_segment_name = "/upf/nat/pool/flows";
  usm->wk.nat_pool_icmp_flows.stat_segment_name = "/upf/nat/pool/icmp_flows";

  usm->wk.gtpu_endpoint_rx.stat_segment_name = "/upf/gtpu/endpoint/rx";
  usm->wk.gtpu_endpoint_tx.stat_segment_name = "/upf/gtpu/endpoint/tx";

  upf_stats_ensure_pfcp_message ();
}

void
upf_stats_ensure_thread (u32 n_threads)
{
  upf_stats_main_t *usm = &upf_stats_main;

  vlib_stats_validate (usm->entries.thread_counters, n_threads - 1,
                       UPF_STAT_N_THREAD - 1);
  upf_stats_clear_counter_vector (usm->entries.thread_counters, ~0);
  usm->counters.thread =
    vlib_stats_get_entry_data_pointer (usm->entries.thread_counters);

  ASSERT (vec_len (usm->counters.thread) == n_threads);
  ASSERT (vec_len (usm->counters.thread[0]) == UPF_STAT_N_THREAD);
}

void
upf_stats_ensure_nat_pool (u32 nat_pool_id, u8 *name, upf_nwi_name_t nwi_name)
{
  upf_stats_main_t *usm = &upf_stats_main;
  vlib_stats_segment_lock ();

  vlib_stats_validate (usm->entries.nat_pool_counters, nat_pool_id,
                       UPF_STAT_N_NAT_POOL);
  upf_stats_clear_counter_vector (usm->entries.nat_pool_counters, nat_pool_id);
  usm->counters.nat_pool =
    vlib_stats_get_entry_data_pointer (usm->entries.nat_pool_counters);

  vlib_stats_set_string_vector (&usm->entries.nat_pool_names, nat_pool_id,
                                "%v", name);
  vlib_stats_set_string_vector (&usm->entries.nat_pool_nwi_names, nat_pool_id,
                                "%U", format_upf_nwi_name, nwi_name);

  bool need_barrier = false;
  need_barrier |= vlib_validate_combined_counter_will_expand (
    &usm->wk.nat_pool_in2out, nat_pool_id);
  need_barrier |= vlib_validate_combined_counter_will_expand (
    &usm->wk.nat_pool_out2in, nat_pool_id);
  need_barrier |= upf_vlib_validate_simple_counter_will_expand (
    &usm->wk.nat_pool_flows, nat_pool_id);
  need_barrier |= upf_vlib_validate_simple_counter_will_expand (
    &usm->wk.nat_pool_icmp_flows, nat_pool_id);

  if (need_barrier)
    vlib_worker_thread_barrier_sync (vlib_get_main ());

  vlib_validate_combined_counter (&usm->wk.nat_pool_in2out, nat_pool_id);
  vlib_zero_combined_counter (&usm->wk.nat_pool_in2out, nat_pool_id);
  vlib_validate_combined_counter (&usm->wk.nat_pool_out2in, nat_pool_id);
  vlib_zero_combined_counter (&usm->wk.nat_pool_out2in, nat_pool_id);
  vlib_validate_simple_counter (&usm->wk.nat_pool_flows, nat_pool_id);
  vlib_zero_simple_counter (&usm->wk.nat_pool_flows, nat_pool_id);
  vlib_validate_simple_counter (&usm->wk.nat_pool_icmp_flows, nat_pool_id);
  vlib_zero_simple_counter (&usm->wk.nat_pool_icmp_flows, nat_pool_id);

  if (need_barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());

  vlib_stats_segment_unlock ();
}

void
upf_stats_ensure_nwi (u32 nwi_id, upf_nwi_name_t name)
{
  upf_stats_main_t *usm = &upf_stats_main;
  vlib_stats_segment_lock ();

  vlib_stats_validate (usm->entries.nwi_counters, nwi_id, UPF_STAT_N_NWI);
  upf_stats_clear_counter_vector (usm->entries.nwi_counters, nwi_id);
  usm->counters.nwi =
    vlib_stats_get_entry_data_pointer (usm->entries.nwi_counters);

  vlib_stats_set_string_vector (&usm->entries.nwi_names, nwi_id, "%U",
                                format_upf_nwi_name, name);

  vlib_stats_segment_unlock ();
}

void
upf_stats_ensure_gtpu_endpoint (u32 gtpu_endpoint_id, upf_nwi_name_t nwi_name,
                                ip4_address_t *ip4, ip6_address_t *ip6)
{
  upf_stats_main_t *usm = &upf_stats_main;
  vlib_stats_segment_lock ();

  vlib_stats_validate (usm->entries.gtpu_counters, gtpu_endpoint_id,
                       UPF_STAT_N_GTPU_ENDPOINT);
  upf_stats_clear_counter_vector (usm->entries.gtpu_counters,
                                  gtpu_endpoint_id);
  usm->counters.gtpu_endpoint =
    vlib_stats_get_entry_data_pointer (usm->entries.gtpu_counters);

  vlib_stats_set_string_vector (&usm->entries.gtpu_endpoint_nwi_names,
                                gtpu_endpoint_id, "%U", format_upf_nwi_name,
                                nwi_name);
  if (ip4)
    vlib_stats_set_string_vector (&usm->entries.gtpu_endpoint_ip4,
                                  gtpu_endpoint_id, "%U", format_ip4_address,
                                  ip4);
  else
    vlib_stats_set_string_vector (&usm->entries.gtpu_endpoint_ip4,
                                  gtpu_endpoint_id, "");

  if (ip6)
    vlib_stats_set_string_vector (&usm->entries.gtpu_endpoint_ip6,
                                  gtpu_endpoint_id, "%U", format_ip6_address,
                                  ip6);
  else
    vlib_stats_set_string_vector (&usm->entries.gtpu_endpoint_ip6,
                                  gtpu_endpoint_id, "");

  bool need_barrier = false;
  need_barrier |= vlib_validate_combined_counter_will_expand (
    &usm->wk.gtpu_endpoint_rx, gtpu_endpoint_id);
  need_barrier |= vlib_validate_combined_counter_will_expand (
    &usm->wk.gtpu_endpoint_tx, gtpu_endpoint_id);

  if (need_barrier)
    vlib_worker_thread_barrier_sync (vlib_get_main ());

  vlib_validate_combined_counter (&usm->wk.gtpu_endpoint_rx, gtpu_endpoint_id);
  vlib_zero_combined_counter (&usm->wk.gtpu_endpoint_rx, gtpu_endpoint_id);
  vlib_validate_combined_counter (&usm->wk.gtpu_endpoint_tx, gtpu_endpoint_id);
  vlib_zero_combined_counter (&usm->wk.gtpu_endpoint_tx, gtpu_endpoint_id);

  if (need_barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());

  vlib_stats_segment_unlock ();
}

void
upf_stats_ensure_pfcp_message ()
{
  upf_stats_main_t *usm = &upf_stats_main;
  vlib_stats_segment_lock ();

  vlib_stats_validate (usm->entries.pfcp_message_counters,
                       UPF_STATS_N_PFCP_MSG_TYPE - 1,
                       UPF_STAT_N_PFCP_MESSAGE - 1);
  upf_stats_clear_counter_vector (usm->entries.pfcp_message_counters, ~0);
  usm->counters.pfcp_message =
    vlib_stats_get_entry_data_pointer (usm->entries.pfcp_message_counters);

  vlib_stats_set_string_vector (&usm->entries.pfcp_message_names,
                                UPF_STATS_PFCP_MSG_TYPE_UNKNOWN, "unknown");
#define _(N, PFCP_ID, METRIC, STR)                                            \
  vlib_stats_set_string_vector (&usm->entries.pfcp_message_names,             \
                                UPF_STATS_PFCP_MSG_TYPE_##METRIC, #METRIC);
  foreach_pfcp_msg
#undef _

  vlib_stats_segment_unlock ();
}

void
upf_stats_clear_counter_vector (u32 entry_index, u32 index0)
{
  counter_t **counters = vlib_stats_get_entry_data_pointer (entry_index);
  if (vec_len (counters) == 0)
    {
      clib_warning ("nothing to clear");
      return;
    }

  u32 len0 = vec_len (counters);
  u32 len1 = vec_len (counters[0]);

  if (is_valid_id (index0))
    {
      ASSERT (index0 < len0);
      // zero array by second level index
      memset (counters[index0], 0, sizeof (counter_t) * len1);
    }
  else
    {
      // clear everything
      for (u32 i0 = 0; i0 < len0; i0++)
        memset (counters[i0], 0, sizeof (counter_t) * len1);
    }
}

// copy of vlib_validate_combined_counter_will_expand adjusted for simple
// counter
int
upf_vlib_validate_simple_counter_will_expand (vlib_simple_counter_main_t *cm,
                                              u32 index)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;
  void *oldheap = vlib_stats_set_heap ();

  /* Possibly once in recorded history */
  if (PREDICT_FALSE (vec_len (cm->counters) == 0))
    {
      clib_mem_set_heap (oldheap);
      return 1;
    }

  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      /* Trivially OK, and proves that index >= vec_len(...) */
      if (index < vec_len (cm->counters[i]))
        continue;
      if (vec_resize_will_expand (cm->counters[i],
                                  index - vec_len (cm->counters[i]) +
                                    1 /* length_increment */))
        {
          clib_mem_set_heap (oldheap);
          return 1;
        }
    }
  clib_mem_set_heap (oldheap);
  return 0;
}

upf_stats_pfcp_msg_type_t
upf_stats_pfcp_msg_type_from_pfcp_msg_type (pfcp_msg_type_t type)
{
  static upf_stats_pfcp_msg_type_t _msg_mapping[PFCP_N_MSG] = {
#define _(N, PFCP_ID, METRIC, STR)                                            \
  [PFCP_MSG_##N] = UPF_STATS_PFCP_MSG_TYPE_##METRIC,
    foreach_pfcp_msg
#undef _
  };

  if (type >= PFCP_N_MSG)
    return UPF_STATS_PFCP_MSG_TYPE_UNKNOWN;

  return _msg_mapping[type];
}
