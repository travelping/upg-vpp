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

#include "upf/sxu/upf_session_update.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/nat/nat.h"

u8 *
format_sxu_slot_state (u8 *s, va_list *args)
{
  sxu_slot_state_t *v = va_arg (*args, sxu_slot_state_t *);

  char c_op = '?';
  if (v->has_existed)
    c_op = v->will_exist ? '_' : 'R';
  else
    c_op = v->will_exist ? 'C' : '?';

  s = format (s, "refs:%u pfcp:%c op:%c", v->references,
              v->is_pfcp_action_taken ? 'T' : 'F', c_op);
  return s;
}

u8 *
format_upf_sxu_type (u8 *s, va_list *args)
{
  static const char *upf_sxu_type_str[UPF_SXU_N_TYPES] = {
#define _(name, plural) [UPF_SXU_TYPE_##name] = #name,
    foreach_sxu_type
#undef _
  };

  upf_sxu_type_t t = va_arg (*args, upf_sxu_type_t);
  return s = format (s, "%s", upf_sxu_type_str[t]);
}

static u8 *
_format_upf_sxu_internal (u8 *s, upf_sxu_t *sxu, bool with_value)
{
  s = format (s, "thread %d sx %d new_rules %d", sxu->thread_id,
              sxu->session_id, sxu->new_rules_id);

  if (sxu->has_error)
    s = format (s, "\nerror: %v", sxu->error.message);

  upf_sxu_conflict_t *p_ep_conflict;
  vec_foreach (p_ep_conflict, sxu->endpoint_conflicts)
    s = format (s, "\ncollided sid: %d %U[%d]",
                p_ep_conflict->conflicted_session_id, format_upf_sxu_type,
                p_ep_conflict->type, p_ep_conflict->xid);

  uword i;
#define _(name, plural)                                                       \
  s = format (s, "\n" #plural ": count %d", vec_len (sxu->plural));           \
  vec_foreach_index (i, sxu->plural)                                          \
    {                                                                         \
      sxu_slot_##name##_t *slot = vec_elt_at_index (sxu->plural, i);          \
      if (with_value)                                                         \
        s =                                                                   \
          format (s, "\n -[%d] s{%U} k{%U} v{%U}", i, format_sxu_slot_state,  \
                  &slot->state, format_sxu_##name##_key, &slot->key,          \
                  format_sxu_##name, &slot->val);                             \
      else                                                                    \
        s = format (s, "\n -[%d] s{%U} k{%U}", i, format_sxu_slot_state,      \
                    &slot->state, format_sxu_##name##_key, &slot->key);       \
    }
  foreach_sxu_type
#undef _

  return s;
}

u8 *
format_upf_sxu_keys (u8 *s, va_list *args)
{
  upf_sxu_t *sxu = va_arg (*args, upf_sxu_t *);
  return _format_upf_sxu_internal (s, sxu, false);
}

u8 *
format_upf_sxu (u8 *s, va_list *args)
{
  upf_sxu_t *sxu = va_arg (*args, upf_sxu_t *);

  return _format_upf_sxu_internal (s, sxu, true);
}

u8 *
format_sxu_pdr_key (u8 *s, va_list *args)
{
  sxu_pdr_key_t *v = va_arg (*args, sxu_pdr_key_t *);
  return format (s, "pfcp id %u", *v);
}

u8 *
format_sxu_pdr (u8 *s, va_list *args)
{
  sxu_pdr_t *v = va_arg (*args, sxu_pdr_t *);
  return format (s,
                 "precedence: %u nwi: %u intf: %U ref_tep: %u ref_app: %u "
                 "ref_far: %u ref_urrs: %U ref_qers: %U",
                 v->precedence, v->pdi.nwi_id, format_upf_interface_type,
                 v->pdi.source_interface, v->pdi.ref_traffic_ep_xid,
                 v->pdi.ref_application_xid, v->ref_far_xid, format_upf_lidset,
                 &v->refs_urr_xids, format_upf_lidset, &v->refs_qer_xids);
}

u8 *
format_sxu_far_key (u8 *s, va_list *args)
{
  sxu_far_key_t *v = va_arg (*args, sxu_far_key_t *);
  return format (s, "pfcp id %u", *v);
}

u8 *
format_sxu_far (u8 *s, va_list *args)
{
  sxu_far_t *v = va_arg (*args, sxu_far_t *);
  return format (
    s, "action %d: nwi: %u intf: %U policy_id: %d nat_binding: %u",
    v->apply_action, v->fp.nwi_id, format_upf_interface_type,
    v->fp.destination_interface, v->fp.policy_id, v->nat_binding_xid);
}

u8 *
format_sxu_urr_key (u8 *s, va_list *args)
{
  sxu_urr_key_t *v = va_arg (*args, sxu_urr_key_t *);
  return format (s, "pfcp id %u", *v);
}

u8 *
format_sxu_urr (u8 *s, va_list *args)
{
  sxu_urr_t *v = va_arg (*args, sxu_urr_t *);
  return format (s, "triggers: 0x%x ref_linked_urrs: %U",
                 v->reporting_triggers, format_upf_lidset,
                 &v->refs_linked_urr_xids);
}

u8 *
format_sxu_qer_key (u8 *s, va_list *args)
{
  sxu_qer_key_t *v = va_arg (*args, sxu_qer_key_t *);
  return format (s, "pfcp id %u", *v);
}

u8 *
format_sxu_qer (u8 *s, va_list *args)
{
  sxu_qer_t *v = va_arg (*args, sxu_qer_t *);
  return format (
    s,
    "gate_closed ul: %d dl: %d has_max_bitrate: %d max_bitrate ul: %d dl: %d",
    v->gate_closed_ul, v->gate_closed_dl, v->has_maximum_bitrate,
    v->maximum_bitrate[UPF_DIR_UL], v->maximum_bitrate[UPF_DIR_DL]);
}

u8 *
format_sxu_traffic_ep_key (u8 *s, va_list *args)
{
  sxu_traffic_ep_key_t *v = va_arg (*args, sxu_traffic_ep_key_t *);

  s = format (s, "%s,%c,%c,%s nwi %d teid %d gtpuep %d %U %U intf %U",
              v->is_gtpu ? "GTP" : "IP ", v->is_ip4 ? '4' : '_',
              v->is_ip6 ? '6' : '_', v->is_destination_ip ? "DST" : "SRC",
              (i16) v->nwi_id, (i8) v->ref_f_teid_allocation_xid,
              (i8) v->ref_gtpu_ep_xid, format_ip4_address, &v->ue_addr4,
              format_ip6_address, &v->ue_addr6, format_upf_interface_type,
              v->intf);
  return s;
}

u8 *
format_sxu_traffic_ep (u8 *s, va_list *args)
{
  sxu_traffic_ep_t *v = va_arg (*args, sxu_traffic_ep_t *);
  return format (s, "ref_ue_ip4: %d ref_ue_ip6: %d", v->ref_ue_ip4_xid,
                 v->ref_ue_ip6_xid);
}

u8 *
format_sxu_ue_ip_ep4_key (u8 *s, va_list *args)
{
  sxu_ue_ip_ep4_key_t *v = va_arg (*args, sxu_ue_ip_ep4_key_t *);
  s = format (s, "%s fib %d %U pad0 %x pad1 %x",
              v->is_source_matching ? "SRC" : "DST", (i32) v->fib_id,
              format_ip4_address, &v->addr, v->_pad0, v->_pad1[0]);
  return s;
}

u8 *
format_sxu_ue_ip_ep4 (u8 *s, va_list *args)
{
  sxu_ue_ip_ep4_t *v = va_arg (*args, sxu_ue_ip_ep4_t *);
  return format (s, "dpo_result_id: %d", v->dpo_result_id);
}

u8 *
format_sxu_ue_ip_ep6_key (u8 *s, va_list *args)
{
  sxu_ue_ip_ep6_key_t *v = va_arg (*args, sxu_ue_ip_ep6_key_t *);
  s = format (s, "%s fib %d %U", v->is_source_matching ? "SRC" : "DST",
              (i32) v->fib_id, format_ip6_address, &v->addr);
  return s;
}

u8 *
format_sxu_ue_ip_ep6 (u8 *s, va_list *args)
{
  sxu_ue_ip_ep6_t *v = va_arg (*args, sxu_ue_ip_ep6_t *);
  return format (s, "dpo_result_id: %d", v->dpo_result_id);
}

u8 *
format_sxu_f_teid_allocation_key (u8 *s, va_list *args)
{
  sxu_f_teid_allocation_key_t *v =
    va_arg (*args, sxu_f_teid_allocation_key_t *);
  s = format (s, "choose_id %d nwi %d %U", v->choose_id, (i16) v->nwi_id,
              format_upf_interface_type, v->intf);
  return s;
}

u8 *
format_sxu_f_teid_allocation (u8 *s, va_list *args)
{
  sxu_f_teid_allocation_t *v = va_arg (*args, sxu_f_teid_allocation_t *);
  return format (s, "ref_gtpu_ep: %d", v->ref_gtpu_ep_xid);
}

u8 *
format_sxu_gtpu_ep_key (u8 *s, va_list *args)
{
  sxu_gtpu_ep_key_t *v = va_arg (*args, sxu_gtpu_ep_key_t *);

  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  upf_gtpu_endpoint_t *ep = pool_elt_at_index (ugm->endpoints, v->gtpu_ep_id);

  s = format (s, "teid 0x%x gtpu_endpoint %d (%U %U)", v->teid,
              (i16) v->gtpu_ep_id, format_ip4_address, &ep->ip4,
              format_ip6_address, &ep->ip6);
  return s;
}

u8 *
format_sxu_gtpu_ep (u8 *s, va_list *args)
{
  sxu_gtpu_ep_t *v = va_arg (*args, sxu_gtpu_ep_t *);
  return format (s, "intf: %U", format_upf_interface_type, v->intf);
}

u8 *
format_sxu_nwi_stat_key (u8 *s, va_list *args)
{
  sxu_nwi_stat_key_t *v = va_arg (*args, sxu_nwi_stat_key_t *);
  s = format (s, "nwi id %d", v->nwi_id);
  return s;
}

u8 *
format_sxu_nwi_stat (u8 *s, va_list *args)
{
  return format (s, "");
}

u8 *
format_sxu_policy_ref_key (u8 *s, va_list *args)
{
  sxu_policy_ref_key_t *v = va_arg (*args, sxu_policy_ref_key_t *);
  s = format (s, "policy id %d", v->policy_id);
  return s;
}

u8 *
format_sxu_policy_ref (u8 *s, va_list *args)
{
  return format (s, "");
}

u8 *
format_sxu_gtpu_ep_stat_key (u8 *s, va_list *args)
{
  sxu_gtpu_ep_stat_key_t *v = va_arg (*args, sxu_gtpu_ep_stat_key_t *);
  s = format (s, "gtpu ep id %d", v->gtpu_ep_id);
  return s;
}

u8 *
format_sxu_gtpu_ep_stat (u8 *s, va_list *args)
{
  // sxu_gtpu_ep_stat_t *v = va_arg (*args, sxu_gtpu_ep_stat_t *);
  return format (s, "");
}

u8 *
format_sxu_adf_application_key (u8 *s, va_list *args)
{
  sxu_adf_application_key_t *v = va_arg (*args, sxu_adf_application_key_t *);
  s = format (s, "application id %d", v->application_id);
  return s;
}

u8 *
format_sxu_adf_application (u8 *s, va_list *args)
{
  // sxu_adf_application_t *v = va_arg (*args, sxu_adf_application_t *);
  return format (s, "");
}

u8 *
format_sxu_nat_binding_key (u8 *s, va_list *args)
{
  sxu_nat_binding_key_t *v = va_arg (*args, sxu_nat_binding_key_t *);

  upf_nat_main_t *unm = &upf_nat_main;

  upf_nat_pool_t *pool = pool_elt_at_index (unm->nat_pools, v->pool_id);

  s = format (s, "pool id %d (%v)", v->pool_id, pool->name);
  return s;
}

u8 *
format_sxu_nat_binding (u8 *s, va_list *args)
{
  sxu_nat_binding_t *v = va_arg (*args, sxu_nat_binding_t *);
  return format (s, "binding_id: %d", v->binding_id);
}

u8 *
format_sxu_imsi_capture_key (u8 *s, va_list *args)
{
  sxu_imsi_capture_key_t *v = va_arg (*args, sxu_imsi_capture_key_t *);
  return format (s, "imsi_capture_id: %d", v->imsi_capture_id);
}

u8 *
format_sxu_imsi_capture (u8 *s, va_list *args)
{
  // sxu_imsi_capture_t *v = va_arg (*args,sxu_imsi_capture_t *);
  return format (s, "");
}

u8 *
format_sxu_capture_set_key (u8 *s, va_list *args)
{
  sxu_capture_set_key_t *v = va_arg (*args, sxu_capture_set_key_t *);
  return format (s, "intf: %U nwi_id: %d", format_upf_interface_type, v->intf,
                 v->nwi_id);
}

u8 *
format_sxu_capture_set (u8 *s, va_list *args)
{
  sxu_capture_set_t *v = va_arg (*args, sxu_capture_set_t *);

  upf_xid_t capture_set_xid;
  vec_foreach_index (capture_set_xid, v->capture_streams)
    {
      s = format (s, "stream[%d]: %d ", capture_set_xid,
                  v->capture_streams[capture_set_xid]);
    }
  return s;
}
