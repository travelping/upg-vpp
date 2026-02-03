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

#ifndef UPF_NAT_NAT_DPO_H_
#define UPF_NAT_NAT_DPO_H_

#include <vnet/dpo/dpo.h>

void upf_nat_dpo_create (u32 pool_index, dpo_id_t *dpo);
format_function_t format_upf_nat_dpo;

extern dpo_type_t upf_nat_dpo_type;

#endif // UPF_NAT_NAT_DPO_H_
