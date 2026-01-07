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

#include "upf/utils/upf_localids.h"

u8 *
format_upf_lidset (u8 *s, va_list *args)
{
  upf_lidset_t *set = va_arg (*args, upf_lidset_t *);

  if (upf_lidset_is_empty (set))
    return format (s, "[empty]");

  bool first = true;
  upf_lidset_foreach (lid, set)
    {
      if (first)
        {
          first = false;
          s = format (s, "[%d", lid);
        }
      else
        s = format (s, ",%d", lid);
    }

  return format (s, "]");
}