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

#ifndef UPF_RULES_UPF_IPFILTER_H_
#define UPF_RULES_UPF_IPFILTER_H_

#include <vnet/ip/ip.h>

#include "upf/core/upf_types.h"

typedef struct __key_packed
{
  u16 min;
  u16 max;
} ipfilter_port_t;

// Structure of parsed ipfilter rule. Not supposed to be modified.
// IPFilterRule defined in RFC 6733, but not all fields used for UPF case.
// Reference to TS 29.212 clause 5.4.2.
// Internally we always store UE fields first for simplicity, because UE
// usually on left side. Default wildcard is: "permit out ip from any to any"
typedef struct __key_packed
{
  union
  {
    ip46_address_t addresses[UPF_N_EL];
    struct
    {
      ip46_address_t address_ue;
      ip46_address_t address_rmt;
    };
  };

  union
  {
    ipfilter_port_t ports[UPF_N_EL];
    struct
    {
      ipfilter_port_t port_ue;
      ipfilter_port_t port_rmt;
    };
  };

  union
  {
    u8 masks[UPF_N_EL];
    struct
    {
      u8 mask_ue;
      u8 mask_rmt;
    };
  };

  // both can be false in case of "any" or "assigned"
  u8 is_ip4 : 1;
  u8 is_ip6 : 1;

  u8 is_ue_any : 1;  // then ip and mask are zeroes
  u8 is_rmt_any : 1; // then ip and mask are zeroes

  u8 is_ue_assigned : 1; // then ip and mask are zero

  // Action "deny" is ignored, in UPF case we only "allow".
  // Idea: It is would be useful to implement rules like "match all except X"
  // by matching packet against "deny" set of rules after it was matched
  // succesfully against "allow" set.
  u8 action_deny : 1;
  // keep in case of formatting, since we always store uplink rule
  u8 direction_in : 1;

  u8 proto; // use reserved ip proto 0xff as wildcard match
} ipfilter_rule_t;

STATIC_ASSERT_SIZEOF (ipfilter_rule_t, 44); // optimized for size

unformat_function_t unformat_upf_ipfilter;
format_function_t format_upf_ipfilter;

void upf_ipfilter_vec_sort (ipfilter_rule_t *rules);

#endif // UPF_RULES_UPF_IPFILTER_H_
