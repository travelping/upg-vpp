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

#include <math.h>

#include <vppinfra/pool.h>
#include <vlib/vlib.h>

#include "upf/utils/common.h"
#include "upf/utils/upf_timer.h"
#include "upf/upf_stats.h"

#define UPF_DEBUG_ENABLE 0

upf_timer_main_t upf_timer_main = { 0 };
static upf_timer_handler_t *_upf_timer_handlers[UPF_TIMER_N_KIND] = { 0 };
vlib_node_registration_t upf_timer_expire_node;
vlib_node_registration_t upf_timer_process_node;

upf_timer_id_t
upf_timer_start_ticks (u16 thread_id, u32 interval, upf_timer_kind_t kind,
                       u32 opaque, u16 opaque2)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (thread_id);

  upf_timer_main_t *utm = &upf_timer_main;
  upf_timer_wk_t *utw = vec_elt_at_index (utm->workers, thread_id);

  upf_timer_t *t;

  interval = clib_max (interval, 1); // make it at least 1 interval for safety

  pool_get (utw->timers, t);

  // timerwheel starts timers relative to tw->current_tick
  t->tw_handle =
    tw_timer_start_1t_3w_1024sl_ov (&utw->tw, t - utw->timers, 0, interval);

  upf_stats_get_wk_generic (thread_id)->timers_started_total += 1;

  t->when = utw->now_tick + interval;
  t->kind = kind;
  t->opaque = opaque;
  t->opaque2 = opaque2;
  t->is_user_stopped = 0;

  upf_timer_id_t tid = {
    .id = t - utw->timers,
    .generation = t->generation,
  };
  return tid;
}

void
upf_timer_stop (u16 thread_id, upf_timer_id_t timer_id)
{
  ASSERT (thread_id == os_get_thread_index ());
  upf_timer_main_t *utm = &upf_timer_main;
  upf_timer_wk_t *wk = vec_elt_at_index (utm->workers, thread_id);

  u32 tid = timer_id.id;
  upf_timer_t *t = pool_elt_at_index (wk->timers, tid);

  ASSERT (t->generation == timer_id.generation);
  ASSERT (!t->is_user_stopped);

  // existing generation is invalid past this line
  t->generation += 1;
  t->is_user_stopped = 1;

  if (is_valid_id (t->tw_handle))
    {
      tw_timer_stop_1t_3w_1024sl_ov (&wk->tw, t->tw_handle);
      t->tw_handle = ~0;

      upf_stats_get_wk_generic (thread_id)->timers_stopped_total += 1;
    }

  if (wk->is_inside_handler)
    // This stop can be triggered by different timer and in such case this
    // timer id can be in tw expiration vector and still be accessed by tw
    // callback. To avoid this situation delay removal after tw callback.
    vec_add1 (wk->removed_inside_handler, tid);
  else
    // can free this element
    pool_put (wk->timers, t);
}

void
upf_timer_set_handler (upf_timer_kind_t kind, upf_timer_handler_t *handler)
{
  ASSERT (kind < UPF_TIMER_N_KIND);
  ASSERT (_upf_timer_handlers[kind] == NULL);
  _upf_timer_handlers[kind] = handler;
}

u8 *
format_upf_time (u8 *s, va_list *args)
{
  upf_time_t v = va_arg (*args, upf_time_t);
  if (v == 0)
    return format (s, "(none)");
  else if (isinf (v))
    return format (s, "(never)");
  else if (!isfinite (v))
    return format (s, "(invalid)");
  else
    return format (s, "%U", format_time_float, "y/m/d H:M:S.F", v);
}

u8 *
format_upf_time_short (u8 *s, va_list *args)
{
  upf_time_t v = va_arg (*args, upf_time_t);
  if (v == 0)
    return format (s, "(none)");
  else if (isinf (v))
    return format (s, "(never)");
  else if (!isfinite (v))
    return format (s, "(invalid)");
  else
    return format (s, "%U", format_time_float, "H:M:S", v);
}

void
upf_timer_init ()
{
  upf_timer_main_t *utm = &upf_timer_main;
  vlib_thread_main_t *vtm = &vlib_thread_main;

  clib_warning ("workers init");
  vec_validate (utm->workers, vtm->n_vlib_mains - 1);

  // floor ensures that future floating point operations with pow2 multiplier
  // ensured to have no rounding error
  f64 now_init = floor (unix_time_now ());

  upf_stats_get_generic ()->timers_ticks_per_second = TW_CLOCKS_PER_SEC;

  upf_timer_wk_t *wk;
  vec_foreach (wk, utm->workers)
    {
      memset (wk, 0, sizeof (*wk));

      // Disable max_expirations, because they cause timers to be called
      // in past. Since when we start timers, tw current_tick can be behind
      // current time, and timers are started relative to current_tick. We
      // could counter this, but it adds comlexity. So if we need timers rate
      // limit it should be added in our logic.
      tw_timer_wheel_init_1t_3w_1024sl_ov (&wk->tw, NULL, TW_SECS_PER_CLOCK,
                                           0x0fffffff);

      wk->tw_base = now_init;
      wk->now = now_init;
      wk->now_tick = now_init * TW_CLOCKS_PER_SEC;
      wk->tw.last_run_time = 0;
    }
}

VLIB_NODE_FN (upf_timer_expire_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  upf_timer_main_t *utm = &upf_timer_main;
  u32 *p_tid;

  u32 thread_index = vm->thread_index;
  ASSERT (thread_index == os_get_thread_index ());
  upf_timer_wk_t *wk = vec_elt_at_index (utm->workers, thread_index);

  // unix_time_now uses CLOCK_REALTIME which may go backwards due to NTP.
  // Ideally we should use it only for timestamps and for time comparison we
  // should use CLOCK_MONOTONIC. But, due to different conditions system time
  // can go backwards sometimes anyways [0].
  // We do not rely on time stat much, so few seconds +- due to NTP will not
  // play huge rule
  //
  // [0]https://github.com/rust-lang/rust/blob/eed12bcd0cb281979c4c9ed956b9e41fda2bfaeb/src/libstd/time.rs#L201-L232

  // round down to nearest multiply of TW_SECS_PER_CLOCK to avoid rounding
  // errors
  u64 now_tick_u64 = floor (unix_time_now () * TW_CLOCKS_PER_SEC);
  u32 now_tick = now_tick_u64;
  f64 now = now_tick_u64 * TW_SECS_PER_CLOCK;

  const u32 tw_internal_timers = 3 * 1024 /*per wheel*/ + 1 /*overflow*/;
  if (pool_elts (wk->timers) != pool_elts (wk->tw.timers) - tw_internal_timers)
    clib_warning ("timers count don't match our:%d, vpp:%d-%d",
                  pool_elts (wk->timers), pool_elts (wk->tw.timers),
                  tw_internal_timers);

  if ((now_tick - wk->now_tick) >= (1 << 30))
    {
      // time went backwards
      clib_warning ("[t%d] time went backwards %u (%.5f) > %u (%.5f)",
                    thread_index, wk->now_tick, wk->now, now_tick, now);
      goto _exit;
    }
  wk->now_tick = now_tick;
  wk->now = now;

  u32 *expired_timers =
    tw_timer_expire_timers_1t_3w_1024sl_ov (&wk->tw, (now - wk->tw_base));
  if (vec_len (expired_timers) == 0)
    goto _exit;

  upf_debug ("THREAD %u expired %u timers", vm->thread_index,
             vec_len (expired_timers));

  upf_stats_get_wk_generic (thread_index)->timers_expirations_total +=
    vec_len (expired_timers);

  // invalidate tw_handle values. they are removed in tw_timer_expire_timers
  vec_foreach (p_tid, expired_timers)
    {
      u32 tid = *p_tid;
      upf_timer_t *t = pool_elt_at_index (wk->timers, tid);
      t->tw_handle = ~0;
    }

  // run handlers with ability to safely stop timers due to invalid tw_handlers
  wk->is_inside_handler = true;
  vec_foreach (p_tid, expired_timers)
    {
      u32 tid = *p_tid;
      upf_timer_t *t = pool_elt_at_index (wk->timers, tid);
      if (t->is_user_stopped)
        {
          // if stopped by previous handler
          continue;
        }

      if (t->when > now_tick)
        {
          clib_warning ("BUG: executing timer from future: when: %.5f (%d "
                        "ticks), now: %.5f (%d ticks), now_raw: %U, kind: %d",
                        t->when * TW_SECS_PER_CLOCK, t->when,
                        now_tick * TW_SECS_PER_CLOCK, now_tick,
                        format_upf_time, now, t->kind);
          ASSERT (t->when <= now_tick);
        }

      u32 lag_tick = now_tick - t->when;

      upf_stat_wk_generic_counter_t bucket;
      if (lag_tick <= (u32) (0.005 * TW_CLOCKS_PER_SEC))
        bucket = UPF_STAT_WK_GENERIC_COUNTER_timers_lag_5ms;
      else if (lag_tick <= (u32) (0.025 * TW_CLOCKS_PER_SEC))
        bucket = UPF_STAT_WK_GENERIC_COUNTER_timers_lag_25ms;
      else if (lag_tick <= (u32) (0.100 * TW_CLOCKS_PER_SEC))
        bucket = UPF_STAT_WK_GENERIC_COUNTER_timers_lag_100ms;
      else if (lag_tick <= (u32) (0.250 * TW_CLOCKS_PER_SEC))
        bucket = UPF_STAT_WK_GENERIC_COUNTER_timers_lag_250ms;
      else if (lag_tick <= (u32) (1.000 * TW_CLOCKS_PER_SEC))
        bucket = UPF_STAT_WK_GENERIC_COUNTER_timers_lag_1000ms;
      else
        bucket = UPF_STAT_WK_GENERIC_COUNTER_timers_lag_infinity;

      upf_stats_get_wk_generic (thread_index)->_counters[bucket] += 1;
      upf_stats_get_wk_generic (thread_index)->timers_lag_sum_ticks +=
        lag_tick;

      upf_timer_kind_t k = t->kind;
      upf_debug ("expired timer kind %d at %U", k, format_upf_time, now);
      _upf_timer_handlers[k](thread_index, k, t->opaque, t->opaque2);
    }
  vec_reset_length (expired_timers);
  wk->is_inside_handler = false;

  // free delayed removal elements
  vec_foreach (p_tid, wk->removed_inside_handler)
    {
      u32 tid = *p_tid;
      upf_timer_t *t = pool_elt_at_index (wk->timers, tid);
      pool_put (wk->timers, t);
    }
  vec_reset_length (wk->removed_inside_handler);

  // We may have more expirations enqueued for immediate handling due to
  // max_expirations. Process them immediately the next vlib iteration to allow
  // events/packets to pass in between.
  vlib_node_set_interrupt_pending (vm, upf_timer_expire_node.index);

_exit:
  upf_stats_get_wk_generic (thread_index)->timers_scheduled =
    pool_elts (wk->timers);

  return 0;
}

VLIB_REGISTER_NODE (upf_timer_expire_node) = {
  .name = "upf-timer-expire",
  // do timers processing before node graph
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

static uword
upf_timer_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  u32 threads = vlib_get_n_threads ();

  // Update time at least 1000 times per second for use in other nodes for
  // millisecond precision.
  const f64 timer_frequency = clib_min (1.0 / 1000.0, TW_SECS_PER_CLOCK);
  while (1)
    {
      (void) vlib_process_wait_for_event_or_clock (vm, timer_frequency);

      // send interrupts
      for (u32 ti = 0; ti < threads; ti++)
        vlib_node_set_interrupt_pending (vlib_get_main_by_index (ti),
                                         upf_timer_expire_node.index);
    }

  return 0;
}

VLIB_REGISTER_NODE (upf_timer_process_node) = {
  .name = "upf-timer-interrupt",
  .function = upf_timer_process,
  .type = VLIB_NODE_TYPE_PROCESS,
};
