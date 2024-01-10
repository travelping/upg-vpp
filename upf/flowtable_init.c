/*
 * Copyright (c) 2016 Qosmos and/or its affiliates.
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

#include <vnet/plugin/plugin.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/pool.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>

#include "upf.h"

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)                                                        \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

#include "flowtable.h"

flowtable_main_t flowtable_main;

clib_error_t *
flowtable_lifetime_update (flowtable_timeout_type_t type, u16 value)
{
  flowtable_main_t *fm = &flowtable_main;

  if (value > FLOW_TIMER_MAX_LIFETIME)
    return clib_error_return (0, "value is too big");

  if (type >= FT_TIMEOUT_TYPE_MAX)
    return clib_error_return (0, "unknown timer type");

  fm->timer_lifetime[type] = value;

  return 0;
}

static clib_error_t *
flowtable_init_cpu (flowtable_main_t *fm, u32 cpu_index)
{
  clib_error_t *error = 0;
  flowtable_main_per_cpu_t *fmt = &fm->per_cpu[cpu_index];
  /*
   * As advised in the thread below :
   * https://lists.fd.io/pipermail/vpp-dev/2016-October/002787.html
   * hashtable is configured to alloc (NUM_BUCKETS * CLIB_CACHE_LINE_BYTES)
   * Bytes with (flow_count / (BIHASH_KVP_PER_PAGE / 2)) Buckets
   */
  u32 nbuckets = 1 << (fm->log2_size - (BIHASH_KVP_PER_PAGE / 2));
  uword memory_size = nbuckets * CLIB_CACHE_LINE_BYTES * 6;

  /* init hashtable */
  clib_bihash_init_48_8 (&fmt->flows_ht, "flow hash table", nbuckets,
                         memory_size);
  upf_debug ("nbuckets %u memory_size %u", nbuckets, memory_size);

  /* init timer wheel */
  fmt->time_index = ~0;
  fmt->next_check = ~0;

  fmt->timers = 0;
  vec_validate (fmt->timers, FLOW_TIMER_MAX_LIFETIME - 1);
  {
    flow_timeout_list_t *l;
    vec_foreach (l, fmt->timers)
      flow_timeout_list_init (l);
  }

  return error;
}

clib_error_t *
flowtable_init (vlib_main_t *vm)
{
  u32 cpu_index;
  clib_error_t *error = 0;
  flowtable_main_t *fm = &flowtable_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  upf_main_t *gtm = &upf_main;

  fm->vlib_main = vm;

  /* init flow pool */
  fm->flows_max = 1 << fm->log2_size;
  upf_debug ("flows_max %u", fm->flows_max);
  pool_alloc_aligned (fm->flows, fm->flows_max, CLIB_CACHE_LINE_BYTES);
  fm->flows_created_count = 0;

  for (flowtable_timeout_type_t i = FT_TIMEOUT_TYPE_UNKNOWN;
       i < FT_TIMEOUT_TYPE_MAX; i++)
    fm->timer_lifetime[i] = FLOW_TIMER_DEFAULT_LIFETIME;

  /* Init flows counter per cpu */
  vlib_validate_simple_counter (&gtm->upf_simple_counters[UPF_FLOW_COUNTER],
                                0);
  vlib_zero_simple_counter (&gtm->upf_simple_counters[UPF_FLOW_COUNTER], 0);

  vec_validate (fm->per_cpu, tm->n_vlib_mains - 1);
  for (cpu_index = 0; cpu_index < tm->n_vlib_mains; cpu_index++)
    {
      error = flowtable_init_cpu (fm, cpu_index);
      if (error)
        return error;
    }

  return error;
}

static clib_error_t *
flowtable_config_fn (vlib_main_t *vm, unformat_input_t *input)
{
  flowtable_main_t *fm = &flowtable_main;
  fm->log2_size = FLOWTABLE_DEFAULT_LOG2_SIZE;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      u32 log2_size;
      if (unformat (input, "log2-size %u", &log2_size))
        {
          if (log2_size < 5)
            return clib_error_return (0, "flowtable log2 size too small");
          else if (log2_size > 31)
            return clib_error_return (0, "flowtable log2 size too large");
          else
            fm->log2_size = log2_size;
        }
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (flowtable_config_fn, "flowtable");
