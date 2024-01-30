#include <vlib/vlib.h>

#include "flowtable.h"
#include "flowtable_timer.h"

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)                                                        \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

int upf_proxy_flow_expire_event_handler (flow_entry_t *flow);

/* return true if flow was removed */
always_inline bool
try_expire_single_flow (flowtable_main_t *fm, flowtable_main_per_cpu_t *fmt,
                        flow_entry_t *f, flow_timeout_list_t *e, u32 now)
{
  bool keep = f->active + f->lifetime > now;
  ASSERT (f->timer_slot == (e - fmt->timers));
  ASSERT (f->active <= now);

  upf_debug ("Flow Timeout Check %d: %u (%u) > %u (%u)", f - fm->flows,
             f->active + f->lifetime,
             (f->active + f->lifetime) % FLOW_TIMER_MAX_LIFETIME, now,
             fmt->time_index);

  if (!keep && upf_proxy_flow_expire_event_handler (f))
    {
      /* flow still in use, wait for another lifetime */
      upf_debug ("Flow %d: expiration blocked by the event handler",
                 f - fm->flows);
      f->active += f->lifetime;
      keep = true;
    }

  if (keep)
    {
      /* There was activity on the entry, so the idle timeout
         has not passed. Enqueue for another time period. */
      flowtable_timeout_stop_entry (fm, fmt, f);
      flowtable_timeout_start_entry (fm, fmt, f, now);
      return false;
    }
  else
    {
      flowtable_entry_remove_internal (fm, fmt, f, now);
      return true;
    }
}

u64
flowtable_timer_expire (flowtable_main_t *fm, flowtable_main_per_cpu_t *fmt,
                        u32 now)
{
  u32 t;
  u64 expire_cpt = 0;

  /*
   * Must call flowtable_timer_expire() only after
   * flowtable_timer_wheel_index_update() with the same 'now' value
   */
  ASSERT (now % FLOW_TIMER_MAX_LIFETIME == fmt->time_index);

  /*
   * In case some of the time slots were skipped e.g. due to low traffic
   * (so flowtable_timer_expire is not called often enough),
   * process all of the skipped entries, but don't expire too many
   * of them to avoid any pauses. We can expire more of the flows
   * if there's low traffic currently, though, so we apply
   * FLOW_TIMER_MAX_EXPIRE limit per step, not per this function run.
   */

  t = now;
  if (PREDICT_TRUE (fmt->next_check != ~0))
    {
      /*
       * This happens when flowtable_timer_expire() is called
       * multiple times per second and max number of expired flows
       * hasn't been previously reached, as fmt->next_check is set
       * to the next second after last flowtable_timer_expire()
       * call.
       */
      if (PREDICT_TRUE (now < fmt->next_check))
        return 0;

      /* check the skipped slots */
      t = fmt->next_check;
    }

  for (; t <= now; t++)
    {

      flow_timeout_list_t *timer_list =
        vec_elt_at_index (fmt->timers, flowtable_time_to_timer_slot (t));

      /* clang-format off */
      upf_llist_foreach (f, fm->flows, timer_anchor, timer_list,
        {
          if (try_expire_single_flow (fm, fmt, f, timer_list, now))
            expire_cpt++;

          if (expire_cpt >= FLOW_TIMER_MAX_EXPIRE)
            break;
        });
      /* clang-format on */

      /*
       * If max N of expirations has been reached, the timer wheel
       * entry corresponding to this moment will be revisited upon
       * the next flowtable_timer_expire() call
       */
      if (expire_cpt >= FLOW_TIMER_MAX_EXPIRE)
        break;
    }

  fmt->next_check = t;

  return expire_cpt;
}

VLIB_NODE_FN (upf_flowtable_timer_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  flowtable_main_t *fm = &flowtable_main;
  u32 thread_index = os_get_thread_index ();
  flowtable_main_per_cpu_t *fmt = &fm->per_cpu[thread_index];
  u32 current_time = (u32) vlib_time_now (vm);

  flowtable_timer_wheel_index_update (fm, fmt, current_time);
  u64 num_expired = flowtable_timer_expire (fm, fmt, current_time);

  vlib_node_increment_counter (
    vm, node->node_index, FLOWTABLE_TIMER_ERROR_TIMER_EXPIRE, num_expired);

  return 0;
}

static char *flowtable_timer_input_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_flowtable_timer_error
#undef _
};

VLIB_REGISTER_NODE (upf_flowtable_timer_input_node) = {
  .name = "upf-flow-timer-input",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .error_strings = flowtable_timer_input_error_strings,
  .n_errors = FLOWTABLE_TIMER_N_ERROR,
};

VLIB_NODE_FN (upf_flowtable_timer_process_node)
(vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  while (1)
    {
      (void) vlib_process_wait_for_event_or_clock (
        vm, 1.0 / UPF_SLO_PER_THREAD_FLOWS_PER_SECOND);

      // send interrupts
      for (int ti = 0; ti < vlib_get_n_threads (); ti++)
        vlib_node_set_interrupt_pending (vlib_get_main_by_index (ti),
                                         upf_flowtable_timer_input_node.index);
    }

  return 0;
}

/* clang-format off */
VLIB_REGISTER_NODE (upf_flowtable_timer_process_node) = {
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 16,
  .runtime_data_bytes = sizeof (void *),
  .name = "upf-flowtable",
  .state = VLIB_NODE_STATE_DISABLED,
};
