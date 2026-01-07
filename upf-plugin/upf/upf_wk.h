/*
 * Copyright (c) 2025 Travelping GmbH
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

#ifndef UPF_UPF_WK_H_
#define UPF_UPF_WK_H_

#include "upf/utils/upf_mt.h"
#include "upf/utils/pool_claim.h"
#include "upf/rules/upf_rules.h"

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  urr_split_measurement_t *split_measurements; // pool
  upf_mt_event_t *cached_events_vec;
  upf_pool_claim_t dp_session_claims;
  upf_pool_claim_t rule_claims;

  upf_timer_id_t periodic_stats_timer;
} upf_main_wk_t;

#endif // UPF_UPF_WK_H_
