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

#ifndef UPF_UTILS_IP_HELPER_H_
#define UPF_UTILS_IP_HELPER_H_

#include <vnet/ip/ip.h>

// ip4 helpers similar to ip6 helpers to have similar code for readability

__clib_unused always_inline void
ip4_address_mask (ip4_address_t *a, const ip4_address_t *mask)
{
  a->as_u32 &= mask->as_u32;
}

__clib_unused always_inline void
ip4_address_set_zero (ip4_address_t *a)
{
  a->as_u32 = 0;
}

__clib_unused always_inline uword
ip4_address_is_zero (const ip4_address_t *a)
{
  return a->as_u32 ? 0 : 1;
}

__clib_unused u8 *format_ip_header (u8 *s, va_list *args);

#endif // UPF_UTILS_IP_HELPER_H_
