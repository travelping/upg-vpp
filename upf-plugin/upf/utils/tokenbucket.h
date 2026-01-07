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

#ifndef UPF_UTILS_TOKENBUCKET_H_
#define UPF_UTILS_TOKENBUCKET_H_

#include <stdbool.h>
#include <vppinfra/types.h>
#include <vppinfra/clib.h>

typedef struct
{
  f32 last_update; // time in seconds
  u32 available;   // current number of tokens in bucket
  f32 rate;        // refill rate (tokens per second)
  f32 fill_time; // how long in seconds it takes to fill the bucket completely
  u32 capacity;  // maximum number of tokens
} tokenbucket_t;

__clib_unused static void
tokenbucket_init (tokenbucket_t *lb, f32 now, f32 rate, u32 capacity)
{
  lb->rate = rate;
  lb->capacity = capacity;
  lb->available = capacity;
  lb->last_update = now;
  lb->fill_time = ((f32) capacity) / ((f32) rate);
};

__clib_unused static void
tokenbucket_refill (tokenbucket_t *lb, f32 now)
{
  f32 elapsed = now - lb->last_update;
  lb->last_update = now;

  if (elapsed > lb->fill_time)
    {
      lb->available = lb->capacity;
      return;
    }

  // add 0.5 to round to nearest instead of down
  u32 tokens_to_add = (u32) (elapsed * lb->rate + 0.5);

  u32 available = lb->available + tokens_to_add;
  if (available > lb->capacity)
    available = lb->capacity;

  lb->available = available;
};

__clib_unused static bool
tokenbucket_can_consume (tokenbucket_t *lb, u32 tokens)
{
  return tokens <= lb->available;
};

__clib_unused static bool
tokenbucket_consume (tokenbucket_t *lb, u32 tokens)
{
  if (tokenbucket_can_consume (lb, tokens))
    {
      lb->available = lb->available - tokens;
      return true;
    }
  return false;
};

#endif // UPF_UTILS_TOKENBUCKET_H_
