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

#include "upf/rules/upf_classify.h"
#include "upf/rules/upf_classify_inlines.h"

#define UPF_DEBUG_ENABLE 0

static_always_inline void
_upf_classify_flow_set_info (upf_rules_t *rules, flow_entry_t *flow,
                             bool is_uplink, classify_result_t r,
                             upf_lid_t pdr_lid, u32 app_id)
{
  upf_dir_t direction = is_uplink ? UPF_DIR_UL : UPF_DIR_DL;
  if (r == CLASSIFY_FAIL)
    {
      flow->pdr_lids[direction] = ~0;
      return;
    }

  if (r == CLASSIFY_OK_NEED_DPI)
    {
      flow->is_tcp_dpi_needed = 1;
      flow->is_tcp_proxy = 1;
    }

  flow->pdr_lids[direction] = pdr_lid;
  if (is_valid_id (app_id))
    flow->application_idx = app_id;

  rules_pdr_t *pdr = upf_rules_get_pdr (rules, pdr_lid);
  if (pdr->need_http_redirect)
    // proxy node will use pdr to figure out redirect and values
    flow->is_tcp_proxy = 1;

  if (is_uplink)
    flow->is_classified_ul = 1;
  else
    flow->is_classified_dl = 1;
}

bool
upf_classify_flow4 (upf_rules_t *rules, flow_entry_t *flow,
                    upf_lidset_t pdr_lids, bool is_uplink,
                    upf_pdr_lid_t *result_pdr_lid)
{
  ASSERT (flow->is_ip4);
  u32 app_id = ~0;

  classify_result_t r = _upf_classify_internal (
    rules, &flow->ip[UPF_EL_UE].ip4, &flow->ip[UPF_EL_RMT].ip4, flow->proto,
    flow->port[UPF_EL_UL_SRC], flow->port[UPF_EL_UL_DST], pdr_lids, is_uplink,
    1 /* is_ip4 */, flow->is_tcp_dpi_done, flow->app_uri, result_pdr_lid,
    &app_id);

  _upf_classify_flow_set_info (rules, flow, is_uplink, r, *result_pdr_lid,
                               app_id);
  return r != CLASSIFY_FAIL;
}

bool
upf_classify_flow6 (upf_rules_t *rules, flow_entry_t *flow,
                    upf_lidset_t pdr_lids, bool is_uplink,
                    upf_pdr_lid_t *result_pdr_lid)
{
  ASSERT (!flow->is_ip4);
  u32 app_id = ~0;

  classify_result_t r = _upf_classify_internal (
    rules, &flow->ip[UPF_EL_UL_SRC].ip6, &flow->ip[UPF_EL_UL_DST].ip6,
    flow->proto, flow->port[UPF_EL_UL_SRC], flow->port[UPF_EL_UL_DST],
    pdr_lids, is_uplink, 0 /* is_ip4 */, flow->is_tcp_dpi_done, flow->app_uri,
    result_pdr_lid, &app_id);

  _upf_classify_flow_set_info (rules, flow, is_uplink, r, *result_pdr_lid,
                               app_id);
  return r != CLASSIFY_FAIL;
}
