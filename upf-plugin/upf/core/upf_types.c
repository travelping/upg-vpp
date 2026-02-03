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

#include <vppinfra/format.h>

#include "upf/core/upf_types.h"
#include "upf/pfcp/pfcp_proto.h"

uword
unformat_upf_imsi_key (unformat_input_t *i, va_list *args)
{
  upf_imsi_t *key = va_arg (*args, upf_imsi_t *);
  u8 *s = 0;

  ASSERT (key);

  if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
    return 0;

  if (!unformat (i, "%v", &s))
    return 0;

  memset (key, 0, sizeof (*key));
  uword len = encode_pfcp_tbcd (s, vec_len (s), key->tbcd, sizeof (key->tbcd));
  vec_free (s);

  if (len > 8 || len < 4)
    return 0;

  return 1;
}
