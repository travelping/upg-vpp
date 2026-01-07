/*
 * Copyright (c) 2018-2025 Travelping GmbH
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

#include <inttypes.h>

#include "upf/upf.h"
#include "upf/rules/upf_rules.h"

/* clang-format off */
static const char *reporting_trigger_flag_names [] = {
  "PERIO", "VOLTH", "TIMTH", "QUHTI",
  "START", "STOPT", "DROTH", "LIUSA",
  "VOLQU", "TIMQU", "ENVCL", "MACAR",
  "EVETH", "EVEQU", "IPMJL", "QUVTI",
  "REEMR", "UPINT",
};
/* clang-format on */

u8 *
format_upf_rules_urr_lidset (u8 *s, va_list *args)
{
  upf_rules_t *rules = va_arg (*args, upf_rules_t *);
  upf_lidset_t *set = va_arg (*args, upf_lidset_t *);

  s = format (s, "#[");
  bool first = true;
  upf_lidset_foreach (lid, set)
    {
      rules_urr_t *urr = upf_rules_get_urr (rules, lid);
      if (!first)
        s = format (s, ",");
      first = false;
      s = format (s, "%u", urr->pfcp_id);
    }
  return format (s, "]");
}

u8 *
format_upf_rules_qer_lidset (u8 *s, va_list *args)
{
  upf_rules_t *rules = va_arg (*args, upf_rules_t *);
  upf_lidset_t *set = va_arg (*args, upf_lidset_t *);

  s = format (s, "#[");
  bool first = true;
  upf_lidset_foreach (lid, set)
    {
      rules_qer_t *qer = upf_rules_get_qer (rules, lid);
      if (!first)
        s = format (s, ",");
      first = false;
      s = format (s, "%u", qer->pfcp_id);
    }
  return format (s, "]");
}

u8 *
format_upf_pdr (u8 *s, va_list *args)
{
  rules_pdr_t *v = va_arg (*args, rules_pdr_t *);

  return format (
    s,
    "pfcp_id: %u precedence: %u nwi: %u intf: %U tep_lid: %u app_id: %u "
    "far_lid: %u urr_ids: %U",
    v->pfcp_id, v->precedence, v->nwi_id, format_upf_interface_type,
    v->src_intf, v->traffic_ep_lid, v->application_id, v->far_lid,
    format_upf_lidset, &v->urr_lids);
}

u8 *
format_upf_far (u8 *s, va_list *args)
{
  rules_far_t *v = va_arg (*args, rules_far_t *);
  return format (s, "action %d: nwi: %u intf: %U policy_id: %d do_nat: %u",
                 v->apply_action, v->forward.nwi_id, format_upf_interface_type,
                 v->forward.dst_intf, v->forward.forwarding_policy_id,
                 v->forward.do_nat);
}

u8 *
format_upf_urr (u8 *s, va_list *args)
{
  upf_rules_t *rules = va_arg (*args, upf_rules_t *);
  rules_urr_t *urr = va_arg (*args, rules_urr_t *);
  upf_lid_t urr_lid = va_arg (*args, u32);
  u32 thread_id = va_arg (*args, u32);

  s = format (s, "URR#%u[%u]: seq=%u [%s%s%s] next_timer=%U\n", urr->pfcp_id,
              urr_lid, urr->seq_no,
              urr->measurement_method_duration ? "duration," : "",
              urr->measurement_method_volume ? "volume," : "",
              urr->measurement_method_event ? "event" : "", format_upf_time,
              urr->next_timer_at);

  s = format (s, "    triggers: [");
  pfcp_ie_reporting_triggers_t _triggers = urr->enabled_triggers;
  while (_triggers)
    {
      u32 bit = count_trailing_zeros (_triggers);
      if (bit < ARRAY_LEN (reporting_trigger_flag_names) &&
          reporting_trigger_flag_names[bit])
        s = format (s, "%s,", reporting_trigger_flag_names[bit]);
      else
        s = format (s, "bit(%d),", (int) bit);
      _triggers ^= (1 << bit);
    }
  s = format (s, "]\n");

  s = format (s, "    status: [ ");
  if (urr->status.out_of_volume_quota)
    s = format (s, "OUT_OF_VOL ");
  if (urr->status.out_of_time_quota)
    s = format (s, "OUT_OF_TIME ");
  if (urr->status.did_sent_volume_threshold)
    s = format (s, "SENT_VOL_THRESHOLD ");
  if (urr->status.did_sent_time_threshold)
    s = format (s, "SENT_TIME_THRESHOLD ");
  if (urr->status.disarmed_monitoring_time)
    s = format (s, "DISARMED_MT ");
  if (urr->status.disarmed_quota_holding_time)
    s = format (s, "DISARMED_QHT ");
  if (urr->status.disarmed_quota_validity_time)
    s = format (s, "DISARMED_QVT ");
  s = format (s, "]\n");

  s = format (s, "    start: %U  first: %U  last: %U\n", format_upf_time,
              urr->timestamps.start, format_upf_time,
              urr->timestamps.first_packet, format_upf_time,
              urr->timestamps.last_packet);

  urr_measure_t *meas = &urr->vol.measure;
  s = format (s, "    bytes: total=%lu ul=%lu dl=%lu\n", meas->bytes.tot,
              meas->bytes.ul, meas->bytes.dl);
  s = format (s, "    packets: total=%lu ul=%lu dl=%lu\n", meas->packets.tot,
              meas->packets.ul, meas->packets.dl);
  s = format (s, "    duration: %us\n", urr->time.measure);

  if (urr->has_quota_tot || urr->has_quota_ul || urr->has_quota_dl)
    {
      s = format (s, "    vol_quota: total=%lu ul=%lu dl=%lu\n",
                  urr->vol.quota_set.tot, urr->vol.quota_set.ul,
                  urr->vol.quota_set.dl);
      s = format (s, "    vol_quota_left: total=%lu ul=%lu dl=%lu\n",
                  urr->vol.quota_left.tot, urr->vol.quota_left.ul,
                  urr->vol.quota_left.dl);
    }

  if (urr->vol.threshold_set.tot || urr->vol.threshold_set.ul ||
      urr->vol.threshold_set.dl)
    {
      s = format (s, "    vol_threshold: total=%lu ul=%lu dl=%lu\n",
                  urr->vol.threshold_set.tot, urr->vol.threshold_set.ul,
                  urr->vol.threshold_set.dl);
      s = format (s, "    vol_threshold_left: total=%lu ul=%lu dl=%lu\n",
                  urr->vol.threshold_left.tot, urr->vol.threshold_left.ul,
                  urr->vol.threshold_left.dl);
    }

  if (urr->has_quota_time)
    {
      s = format (s, "    time_quota: %us\n", urr->time.quota_set);
      s = format (s, "    time_quota_left: %us\n", urr->time.quota_left);
    }

  if (urr->time.threshold_set)
    {
      s = format (s, "    time_threshold: %us\n", urr->time.threshold_set);
      s =
        format (s, "    time_threshold_left: %us\n", urr->time.threshold_left);
    }

  if (urr->measurement_period.period)
    s = format (s, "    measurement_period: %us base=%U\n",
                urr->measurement_period.period, format_upf_time,
                urr->measurement_period.base);
  if (urr->quota_holding_time.period)
    s = format (s, "    quota_holding_time: %us base=%U%s\n",
                urr->quota_holding_time.period, format_upf_time,
                urr->quota_holding_time.base,
                urr->status.disarmed_quota_holding_time ? " (disarmed)" : "");
  if (urr->quota_validity_time.period)
    s = format (s, "    quota_validity_time: %us base=%U%s\n",
                urr->quota_validity_time.period, format_upf_time,
                urr->quota_validity_time.base,
                urr->status.disarmed_quota_validity_time ? " (disarmed)" : "");
  if (urr->monitoring_time)
    s = format (s, "    monitoring_time: %U%s\n", format_upf_time,
                urr->monitoring_time,
                urr->status.disarmed_monitoring_time ? " (disarmed)" : "");

  if (!upf_lidset_is_empty (&urr->liusa_urrs_lids))
    s = format (s, "    linked_urrs: %U\n", format_upf_rules_urr_lidset, rules,
                &urr->liusa_urrs_lids);

  if (is_valid_id (urr->montioring_split_measurement_id))
    {
      upf_main_t *um = &upf_main;
      upf_main_wk_t *uwk = vec_elt_at_index (um->workers, thread_id);
      urr_split_measurement_t *split = pool_elt_at_index (
        uwk->split_measurements, urr->montioring_split_measurement_id);

      s = format (s, "    split_measurement:\n");
      s = format (s, "      split_time: %U\n", format_upf_time,
                  split->split_time);
      s = format (s, "      first: %U  last: %U\n", format_upf_time,
                  split->first_packet, format_upf_time, split->last_packet);

      urr_measure_t *split_meas = &split->vol_measure;
      s = format (s, "      bytes: total=%lu ul=%lu dl=%lu\n",
                  split_meas->bytes.tot, split_meas->bytes.ul,
                  split_meas->bytes.dl);
      s = format (s, "      packets: total=%lu ul=%lu dl=%lu\n",
                  split_meas->packets.tot, split_meas->packets.ul,
                  split_meas->packets.dl);
      s = format (s, "      duration: %us\n", split->time_measure);
    }

  return s;
}
