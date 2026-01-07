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

#ifndef UPF_UTILS_RATELIMIT_ATOMIC_H_
#define UPF_UTILS_RATELIMIT_ATOMIC_H_

#include <stdbool.h>
#include <vppinfra/types.h>
#include <vppinfra/cache.h>
#include <vppinfra/atomics.h>

#define RATELIMIT_ATOMIC_FP_SCALE                                             \
  (1 << 20) // fixed point time scale (~1us precision)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 last_update_scaled; // atomic contested value
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 time_per_token;
  f32 rate; // refill rate in tokens per second
} ratelimit_atomic_t;

__clib_unused static void
ratelimit_atomic_init (ratelimit_atomic_t *rl, f64 now_f, f32 rate)
{
  u64 now = now_f * RATELIMIT_ATOMIC_FP_SCALE;

  ASSERT (rate > 0.1 && rate < (RATELIMIT_ATOMIC_FP_SCALE / 2.0));

  rl->rate = rate;
  rl->time_per_token =
    (u32) (((f32) RATELIMIT_ATOMIC_FP_SCALE) / rate + 0.5f); // round

  clib_atomic_store_rel_n (&rl->last_update_scaled, now);
}

__clib_unused static bool
ratelimit_atomic_consume (ratelimit_atomic_t *rl, f64 now_f)
{
  u64 now = now_f * RATELIMIT_ATOMIC_FP_SCALE;
  u64 old_time = clib_atomic_load_acq_n (&rl->last_update_scaled);

  do
    {
      old_time = clib_atomic_load_acq_n (&rl->last_update_scaled);
      u64 elapsed = now - old_time;

      // Check if enough time has elapsed for 1 token
      if (elapsed < rl->time_per_token)
        return false;
    }
  while (PREDICT_FALSE (!clib_atomic_cmp_and_swap_acq_relax_n (
    &rl->last_update_scaled, &old_time, now, 0)));
  return true;
}

#endif // UPF_UTILS_RATELIMIT_ATOMIC_H_
