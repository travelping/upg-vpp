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

#ifndef UPF_RULES_UPF_FORWARDING_POLICY_H_
#define UPF_RULES_UPF_FORWARDING_POLICY_H_

#include <stdbool.h>
#include <vppinfra/format.h>

typedef struct
{
  u8 *policy_id;
  u32 ip4_fib_id;
  u32 ip6_fib_id;
  u32 locks;
  u8 is_removed : 1;
} upf_forwarding_policy_t;

clib_error_t *upf_forwarding_policy_add_del (u8 *policy_id, u32 ip4_table_id,
                                             u32 ip6_table_id, u8 action);
upf_forwarding_policy_t *upf_forwarding_policy_get_by_name (u8 *policy_id);
void upf_forwarding_policy_ref (upf_forwarding_policy_t *fp);
void upf_forwarding_policy_unref (upf_forwarding_policy_t *fp);
u32 upf_forwarding_policy_get_table_id (upf_forwarding_policy_t *fp,
                                        bool is_ip4);

format_function_t format_upf_forwarding_policy;

#endif // UPF_RULES_UPF_FORWARDING_POLICY_H_
