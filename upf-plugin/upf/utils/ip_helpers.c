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

#include "upf/utils/ip_helpers.h"

u8 *
format_ip_header (u8 *s, va_list *args)
{
  void *iphdr = va_arg (*args, void *);
  u32 max_header_bytes = va_arg (*args, u32);

  bool is_ip4 = (((u8 *) iphdr)[0] & 0xF0) == 0x40;

  if (is_ip4)
    return format (s, "%U", format_ip4_header, iphdr, max_header_bytes);
  else
    return format (s, "%U", format_ip6_header, iphdr, max_header_bytes);
}
