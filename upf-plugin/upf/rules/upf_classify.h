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

#ifndef UPF_RULES_UPF_CLASSIFY_H_
#define UPF_RULES_UPF_CLASSIFY_H_

#include "upf/rules/upf_rules.h"
#include "upf/flow/flowtable.h"

typedef enum
{
  // matching PDR wasn't found
  CLASSIFY_FAIL,
  // matching PDR found
  CLASSIFY_OK,
  // matching PDR found, but result could be different with DPI info for
  // application detection
  CLASSIFY_OK_NEED_DPI,
} classify_result_t;

bool upf_classify_flow4 (upf_rules_t *rules, flow_entry_t *flow,
                         upf_lidset_t pdr_lids, bool is_uplink,
                         upf_pdr_lid_t *result_pdr_lid);
bool upf_classify_flow6 (upf_rules_t *rules, flow_entry_t *flow,
                         upf_lidset_t pdr_lids, bool is_uplink,
                         upf_pdr_lid_t *result_pdr_lid);

#endif // UPF_RULES_UPF_CLASSIFY_H_
