#ifndef __upf_slo_h__
#define __upf_slo_h__

// Flow expiration rate directly depends on flow creation rate,
// so we use same value for two target metrics
// 100_000 flows creation/expiration per thread per second
#define UPF_SLO_PER_THREAD_FLOWS_PER_SECOND (128 * 1024)

#endif /* __upf_slo_h__ */
