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

#ifndef UPF_UTILS_UPF_TIMER_H_
#define UPF_UTILS_UPF_TIMER_H_

#include <stdbool.h>

#include <vppinfra/types.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

// Use power of 2 to avoid rounding error accumulation in timerwheel which can
// cause timers to be fired earlier then expected
#define TW_CLOCKS_PER_SEC (256.0)
#define TW_SECS_PER_CLOCK (1.0 / TW_CLOCKS_PER_SEC)

// unix time seconds, rounded to pow2 to reduce floating point errors
typedef f64 upf_time_t;

typedef enum : u8
{
  UPF_TIMER_KIND_PFCP_REQUEST_T1 = 0,
  UPF_TIMER_KIND_PFCP_HEARTBEAT,
  UPF_TIMER_KIND_PFCP_RESPONSE_RETRANSMIT,
  UPF_TIMER_KIND_UP_INVACTIVITY,
  UPF_TIMER_KIND_URR,
  UPF_TIMER_KIND_UE_TRAFFIC_HASH_CLEANUP,
  UPF_TIMER_KIND_IPFIX,
  UPF_TIMER_KIND_NAT_BLOCK_TIMEOUT,
  UPF_TIMER_KIND_PERIODIC_STATS,
  UPF_TIMER_KIND_FLOW_EXPIRATION,
  UPF_TIMER_N_KIND,
} upf_timer_kind_t;

// Additional verification needed for cases when timer reference is held inside
// structure. So we could decouple timer handling from events handling. For
// cases like removal of timer inside timer handler.
typedef struct
{
  u32 tw_handle;
  u32 when; // in ticks, for assertion and verification

  upf_timer_kind_t kind;
  u8 is_user_stopped : 1;
  u8 generation : 2; // for asserts matching, part of public timer_id

  u16 opaque2;
  u32 opaque;
} upf_timer_t;

typedef struct
{
  // avoid cacheline sharing between workers
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  upf_timer_t *timers; // pool of local timers
  bool is_inside_handler;
  u32 *removed_inside_handler;

  // this version is passed to timer wheel
  upf_time_t now;

  // Try to avoid floating errors in tw last_run_time and next_run_time.
  // Especially due to incremental error in this line:
  //  tw->last_run_time += i * tw->timer_interval;
  upf_time_t tw_base;

  u32 now_tick; // can overflow

  tw_timer_wheel_1t_3w_1024sl_ov_t tw;
} upf_timer_wk_t;

typedef struct
{
  upf_timer_wk_t *workers; // vec
} upf_timer_main_t;

typedef union
{
  struct
  {
    u32 id : 30;
    u32 generation : 2;
  };
  u32 as_u32;
} upf_timer_id_t;

upf_timer_id_t upf_timer_start_ticks (u16 thread_id, u32 ticks,
                                      upf_timer_kind_t kind, u32 opaque,
                                      u16 opaque2);
void upf_timer_stop (u16 thread_id, upf_timer_id_t timer_id);

typedef void upf_timer_handler_t (u16 thread_id, upf_timer_kind_t kind,
                                  u32 opaque, u16 opaque2);
void upf_timer_set_handler (upf_timer_kind_t kind,
                            upf_timer_handler_t *handler);

extern upf_timer_main_t upf_timer_main;

// in some cases floating point calculations can be optimized out
always_inline __clib_unused upf_timer_id_t
upf_timer_start_secs (u16 thread_id, f64 secs, upf_timer_kind_t kind,
                      u32 opaque, u16 opaque2)
{
  // here we want to round up to never do less ticks then requested
  ASSERT (secs >= 0);
  if (secs < 0)
    {
      clib_warning ("starting timer %d (%d,%d) at incorrect %.5f", kind,
                    opaque, opaque2, secs);
      secs = 0;
    }
  u32 ticks = (u32) (secs * TW_CLOCKS_PER_SEC + 0.5);
  return upf_timer_start_ticks (thread_id, ticks, kind, opaque, opaque2);
}

always_inline __clib_unused void
upf_timer_stop_safe (u16 thread_id, upf_timer_id_t *timer_id)
{
  if (timer_id->as_u32 == ~0)
    return;
  upf_timer_stop (thread_id, *timer_id);
  timer_id->as_u32 = ~0;
}

// returns unix time
always_inline __clib_unused f64
upf_time_now (u16 thread_id)
{
  ASSERT (thread_id == os_get_thread_index ());
  return vec_elt_at_index (upf_timer_main.workers, thread_id)->now;
}

// returns unix time
always_inline __clib_unused f64
upf_time_now_main ()
{
  return upf_time_now (0);
}

format_function_t format_upf_time;
format_function_t format_upf_time_short;

void upf_timer_init ();

#endif // UPF_UTILS_UPF_TIMER_H_
