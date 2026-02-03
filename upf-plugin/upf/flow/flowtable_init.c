/*
 * Copyright (c) 2016 Qosmos and/or its affiliates
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

#include <vnet/plugin/plugin.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/pool.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>

#include "upf/flow/flowtable.h"

#define UPF_DEBUG_ENABLE 0

flowtable_main_t flowtable_main;

clib_error_t *
flowtable_lifetime_update (flowtable_timeout_type_t type, u32 value_sec)
{
  flowtable_main_t *fm = &flowtable_main;

  if (value_sec <= FLOW_TIMER_MIN_LIFETIME_SEC)
    return clib_error_return (0, "value too small (min %u seconds)",
                              (u32) FLOW_TIMER_MIN_LIFETIME_SEC);
  else if (value_sec > FLOW_TIMER_MAX_LIFETIME_SEC)
    return clib_error_return (0, "value too large (max %u seconds)",
                              (u32) FLOW_TIMER_MAX_LIFETIME_SEC);

  if (type >= FT_TIMEOUT_N_TYPE)
    return clib_error_return (0, "unknown timer type");

  fm->timer_lifetime_ticks[type] = value_sec * TW_CLOCKS_PER_SEC;

  return 0;
}

clib_error_t *
flowtable_init (vlib_main_t *vm)
{
  clib_error_t *error = 0;
  flowtable_main_t *fm = &flowtable_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  /* init flow pool */
  upf_debug ("max_flows_per_worker %u", fm->max_flows_per_worker);
  upf_debug ("workers count %u", tm->n_vlib_mains);

  vec_validate (fm->workers, tm->n_vlib_mains - 1);

  uword hash_log2_size = max_log2 (fm->max_flows_per_worker);
  /*
   * As advised in the thread below :
   * https://lists.fd.io/pipermail/vpp-dev/2016-October/002787.html
   * hashtable is configured to alloc (NUM_BUCKETS * CLIB_CACHE_LINE_BYTES)
   * Bytes with (flow_count / (BIHASH_KVP_PER_PAGE / 2)) Buckets
   */
  u32 nbuckets = 1 << (hash_log2_size - (BIHASH_KVP_PER_PAGE / 2));
  uword memory_size = nbuckets * CLIB_CACHE_LINE_BYTES * 6;

  flowtable_wk_t *fwk;
  vec_foreach (fwk, fm->workers)
    {
      u8 *name4 = format (0, "upf flows ip4 wk-%u", fwk - fm->workers);
      u8 *name6 = format (0, "upf flows ip6 wk-%u", fwk - fm->workers);
      vec_terminate_c_string (name4);
      vec_terminate_c_string (name6);
      /* init hashtables */
      clib_bihash_init_16_8 (&fwk->flows_ht4, (char *) name4, nbuckets,
                             memory_size);
      clib_bihash_init_40_8 (&fwk->flows_ht6, (char *) name6, nbuckets,
                             memory_size);

      fwk->flows = NULL; // lazy flowtable allocation
      fwk->current_flows_count = 0;
    }

  upf_debug ("nbuckets %u memory_size %u", nbuckets, memory_size);

  upf_timer_set_handler (UPF_TIMER_KIND_FLOW_EXPIRATION,
                         flowtable_flow_expiration_handler);

  return error;
}

static clib_error_t *
flowtable_config_fn (vlib_main_t *vm, unformat_input_t *input)
{
  flowtable_main_t *fm = &flowtable_main;

  fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_TCP_ESTABLISHED] =
    300 * TW_CLOCKS_PER_SEC;
  fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_TCP_OPENING] =
    15 * TW_CLOCKS_PER_SEC;
  fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_TCP_CLOSING] =
    7 * TW_CLOCKS_PER_SEC;
  fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_UDP] = 60 * TW_CLOCKS_PER_SEC;
  fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_ICMP] = 20 * TW_CLOCKS_PER_SEC;
  fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_UNKNOWN] = 60 * TW_CLOCKS_PER_SEC;

  fm->max_flows_per_worker = FLOWTABLE_DEFAULT_MAX_FLOWS_PER_WORKER;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      u32 max_flows_per_wk;
      if (unformat (input, "max-flows-per-worker %u", &max_flows_per_wk))
        {
          if (max_flows_per_wk < 8)
            return clib_error_return (0, "flowtable size too small (%u < %u)",
                                      max_flows_per_wk, 8);
          else if (max_flows_per_wk >= (1 << 30))
            return clib_error_return (
              0, "flowtable log2 size too large (%u >= %u)", max_flows_per_wk,
              (1 << 30));
          else
            fm->max_flows_per_worker = max_flows_per_wk;
        }
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (flowtable_config_fn, "flowtable");
