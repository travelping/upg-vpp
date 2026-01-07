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

#include <vlib/vlib.h>
#include <vppinfra/pool.h>

#include "upf/utils/common.h"
#include "upf/utils/upf_mt.h"
#include "upf/upf_stats.h"

#define UPF_DEBUG_ENABLE 0

upf_mt_main_t upf_mt_main;
vlib_node_registration_t upf_mt_event_node;

always_inline void
_upf_mt_enqueue (u16 wk_thread_id, upf_mt_event_t *ev, u32 events_count,
                 vlib_main_t *wake_vm, bool is_m2w)
{
  upf_mt_main_t *umm = &upf_mt_main;
  upf_mt_wk_t *wk = vec_elt_at_index (umm->workers, wk_thread_id);
  upf_mt_event_t **ring = is_m2w ? &wk->ring_m2w : &wk->ring_w2m;

  upf_debug ("sending event %d wk %d (%s)", ev->kind, wk_thread_id,
             is_m2w ? "to worker" : "to main");

  // TODO: this operation is slow and we should get rid of it on every event
  // enqueue by batching events send.
  // Make sure we really wrote memory changes to other cpus caches.
  CLIB_MEMORY_STORE_BARRIER ();

  clib_spinlock_lock (&wk->lock);
  u32 old_ring_size = vec_len (*ring);
  vec_add (*ring, ev, events_count);
  clib_spinlock_unlock (&wk->lock);

  const u32 overload_limit = 10000;
  // check if crossed border
  if (old_ring_size <= overload_limit &&
      old_ring_size + events_count > overload_limit)
    clib_warning ("upf event queue wk %d %s is overloaded (>10000)",
                  wk_thread_id, is_m2w ? "to worker" : "to main");

  vlib_node_set_interrupt_pending (wake_vm, upf_mt_event_node.index);
}

void
upf_mt_enqueue_to_main (u16 wk_thread_id, upf_mt_event_t *ev, u32 count)
{
  vlib_main_t *wake_vm = vlib_get_first_main ();
  _upf_mt_enqueue (wk_thread_id, ev, count, wake_vm, false);

  upf_stats_get_wk_generic (wk_thread_id)->mt_events_sent_w2m += count;
}

void
upf_mt_enqueue_to_wk (u16 wk_thread_id, upf_mt_event_t *ev, u32 count)
{
  vlib_main_t *wake_vm = vlib_get_main_by_index (wk_thread_id);
  _upf_mt_enqueue (wk_thread_id, ev, count, wake_vm, true);

  upf_stats_get_thread (wk_thread_id)->mt_events_sent_m2w += count;
}

void
upf_mt_init ()
{
  upf_mt_main_t *umm = &upf_mt_main;
  vlib_thread_main_t *vtm = &vlib_thread_main;

  clib_warning ("workers init. total threads: %d", vtm->n_vlib_mains);
  vec_validate (umm->workers, vtm->n_vlib_mains - 1);

  upf_mt_wk_t *wk;
  vec_foreach (wk, umm->workers)
    {
      memset (wk, 0, sizeof (*wk));

      clib_spinlock_init (&wk->lock);
      wk->ring_m2w = NULL;
      wk->ring_w2m = NULL;
    }

  upf_stats_ensure_thread (vec_len (umm->workers));
}

static void
handle_mt_event_w2m (u16 wk_thread_id, upf_mt_event_t *events)
{
  upf_mt_event_t *ev;
  vec_foreach (ev, events)
    {
      switch (ev->kind)
        {
        case UPF_MT_EVENT_W2M_SESSION_RESP:
          handle_mt_event_w2m_session_resp (wk_thread_id,
                                            &ev->w2m_session_resp);
          break;
        case UPF_MT_EVENT_W2M_SESSION_REPORT:
          handle_mt_event_w2m_session_report (wk_thread_id,
                                              &ev->w2m_session_report);
          break;
        case UPF_MT_EVENT_W2M_USAGE_REPORT:
          handle_mt_event_w2m_usage_report (wk_thread_id,
                                            &ev->w2m_usage_report);
          break;
        default:
          clib_warning ("!!! unknown event on %d wk_id %d ev %d",
                        vlib_get_thread_index (), wk_thread_id, ev->kind);
        }
    }
}

static void
handle_mt_event_m2w (u16 wk_thread_id, upf_mt_event_t *events)
{
  upf_mt_event_t *ev;
  vec_foreach (ev, events)
    {
      switch (ev->kind)
        {
        case UPF_MT_EVENT_M2W_SESSION_REQ:
          handle_mt_event_m2w_session_req (wk_thread_id, &ev->m2w_session_req);
          break;
        default:
          clib_warning ("!!! unknown event on %d wk_id %d ev %d",
                        vlib_get_thread_index (), wk_thread_id, ev->kind);
        }
    }
}

VLIB_NODE_FN (upf_mt_event_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  upf_mt_main_t *umm = &upf_mt_main;
  u16 thread_index = vm->thread_index;

  if (thread_index == 0)
    {
      // main thread only
      upf_mt_wk_t *wk;
      vec_foreach (wk, umm->workers)
        {
          u16 wk_thread_index = wk - umm->workers;

          clib_spinlock_lock (&wk->lock);
          upf_mt_event_t *events = wk->ring_w2m;
          wk->ring_w2m = NULL;
          clib_spinlock_unlock (&wk->lock);

          if (vec_len (events))
            {
              // Shared objects referenced by events need cache invalidation
              CLIB_MEMORY_BARRIER ();
              handle_mt_event_w2m (wk_thread_index, events);
            }

          upf_stats_get_thread (wk_thread_index)->mt_events_recv_w2m +=
            vec_len (events);

          vec_free (events);
        }
    }

  // worker, including main thread worker
  upf_mt_wk_t *wk = vec_elt_at_index (umm->workers, thread_index);

  clib_spinlock_lock (&wk->lock);
  upf_mt_event_t *events = wk->ring_m2w;
  wk->ring_m2w = NULL;
  clib_spinlock_unlock (&wk->lock);

  if (vec_len (events))
    {
      // Shared objects referenced by events need cache invalidation
      CLIB_MEMORY_BARRIER ();
      handle_mt_event_m2w (thread_index, events);
    }

  upf_stats_get_wk_generic (thread_index)->mt_events_recv_m2w +=
    vec_len (events);

  vec_free (events);

  return 0;
}

VLIB_REGISTER_NODE (upf_mt_event_node) = {
  .name = "upf-mt-event",
  // do event processing before node graph
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};
