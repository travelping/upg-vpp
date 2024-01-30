#ifndef __flowtable_timer_h__
#define __flowtable_timer_h__

#include "flowtable.h"

#include "slo.h"

u64 flowtable_timer_expire (flowtable_main_t *fm,
                            flowtable_main_per_cpu_t *fmt, u32 now);

#define foreach_upf_flowtable_timer_error                                     \
  _ (TIMER_EXPIRE, "flows that have expired")

typedef enum
{
#define _(sym, str) FLOWTABLE_TIMER_ERROR_##sym,
  foreach_upf_flowtable_timer_error
#undef _
    FLOWTABLE_TIMER_N_ERROR
} upf_flowtable_timer_node_error_t;

vlib_node_registration_t upf_flowtable_timer_wk_process_node;
vlib_node_registration_t upf_flowtable_timer_process_node;
// distribute (batch) flow expirations over time
#define FLOWTABLE_TIMER_FREQUENCY (UPF_SLO_PER_THREAD_FLOWS_PER_SECOND / 512.0)

#endif /* __flowtable_timer_h__ */
