/*
 * Copyright (c) 2017-2025 Travelping GmbH
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

#ifndef UPF_ADF_MATCHER_H_
#define UPF_ADF_MATCHER_H_

#include "upf/adf/adf.h"
#include "upf/flow/flowtable.h"

clib_error_t *upf_adf_ip_matcher_prepare (upf_adf_app_version_t *ver);

u8 upf_adf_ip_match (upf_adf_app_version_t *ver, flow_entry_t *flow,
                     ip46_address_t *assigned);

bool upf_adf_ip_match4 (upf_adf_app_version_t *ver, ip4_address_t *ue_addr4,
                        ip4_address_t *rmt_addr4, u16 ue_port, u16 rmt_port,
                        bool ue_addr_is_assigned);
bool upf_adf_ip_match6 (upf_adf_app_version_t *ver, ip6_address_t *ue_addr6,
                        ip6_address_t *rmt_addr6, u16 ue_port, u16 rmt_port,
                        bool ue_addr_is_assigned);

#endif // UPF_ADF_MATCHER_H_
