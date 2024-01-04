/*
 * upf_ip_rules.h - 3GPP TS 29.244 GTP-U UP plug-in header file
 *
 * Copyright (c) 2017-2019 Travelping GmbH
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
#ifndef __included_upf_ip_rules_h__
#define __included_upf_ip_rules_h__

#include "upf_app_db.h"

void upf_ensure_app_fib_if_needed (upf_adf_entry_t *appentry);

void upf_app_fib_cleanup (upf_adf_entry_t *appentry);

u8 upf_app_dpo_match (upf_adf_entry_t *appentry, flow_entry_t *flow,
                      ip46_address_t *assigned);

#endif /* __included_upf_ip_rules_h__ */
