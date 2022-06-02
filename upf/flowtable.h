/*---------------------------------------------------------------------------
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
 *---------------------------------------------------------------------------
 */

#ifndef __flowtable_h__
#define __flowtable_h__

#include <pthread.h>
#include <stdbool.h>
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/dlist.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>

#include "flowtable_tcp.h"

#define foreach_flowtable_error				\
  _(HIT, "packets with an existing flow")		\
  _(THRU, "packets gone through")			\
  _(CREATED, "packets which created a new flow")	\
  _(UNHANDLED, "unhandled (non-ip)  packet")		\
  _(TIMER_EXPIRE, "flows that have expired")		\
  _(COLLISION, "hashtable collisions")			\
  _(RECYCLE, "flow recycled")

typedef enum
{
#define _(sym, str) FLOWTABLE_ERROR_ ## sym,
  foreach_flowtable_error
#undef _
  FLOWTABLE_N_ERROR
} flowtable_error_t;

typedef enum
{
  FT_NEXT_DROP,
  FT_NEXT_CLASSIFY,
  FT_NEXT_PROCESS,
  FT_NEXT_PROXY,
  FT_NEXT_N_NEXT
} flowtable_next_t;

typedef enum
{
  FT_ORIGIN = 0,
  FT_REVERSE,
  FT_ORDER_MAX
} flow_direction_t;

/* key */
typedef struct
{
  union
  {
    struct
    {
      u64 seid;
      ip46_address_t ip[FT_ORDER_MAX];
      u16 port[FT_ORDER_MAX];
      u8 proto;
    };
    u64 key[6];
  };
} flow_key_t;

/* dlist helpers */
#define dlist_is_empty(pool, head_index)				\
  ({									\
    dlist_elt_t * head = pool_elt_at_index((pool), (head_index));	\
    (head->next == (u32) ~0 || head->next == (head_index));		\
  })

typedef struct
{
  u32 pkts;
  u32 pkts_unreported;
  u64 bytes;
  u64 bytes_unreported;
  u64 l4_bytes;
  u64 l4_bytes_unreported;
} flow_stats_t;

typedef enum
{
  FT_TIMEOUT_TYPE_UNKNOWN,
  FT_TIMEOUT_TYPE_IPV4,
  FT_TIMEOUT_TYPE_IPV6,
  FT_TIMEOUT_TYPE_ICMP,
  FT_TIMEOUT_TYPE_UDP,
  FT_TIMEOUT_TYPE_TCP,
  FT_TIMEOUT_TYPE_MAX
} flowtable_timeout_type_t;

typedef struct flow_tc
{
  u32 conn_index;
  u32 thread_index;
} flow_tc_t;

typedef struct
{
  u32 sec;
  u32 nsec;
} timestamp_nsec_t;

typedef struct flow_entry
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* flow signature */
  flow_key_t key;
  u32 session_index;
  u8 is_reverse:1;
  u8 is_redirect:1;
  u8 is_l3_proxy:1;
  u8 is_spliced:1;
  u8 spliced_dirty:1;
  u8 dont_splice:1;
  u8 app_detection_done:1;
  u8 exported:1;
  u16 tcp_state;
  u32 ps_index;

  /* stats */
  flow_stats_t stats[FT_ORDER_MAX];

  /* timers */
  u32 active;			/* last activity ts */
  u16 lifetime;			/* in seconds */
  u32 timer_index;		/* index in the timer pool */

  /* UPF data */
  u32 application_id;		/* L7 app index */
  u32 _pdr_id[FT_ORDER_MAX];	/* PDRs */
  u32 _teid[FT_ORDER_MAX];
  u32 _next[FT_ORDER_MAX];

  flow_tc_t _tc[FT_ORDER_MAX];

  u32 _seq_offs[FT_ORDER_MAX];
  u32 _tsval_offs[FT_ORDER_MAX];

  u8 *app_uri;

  timestamp_nsec_t flow_start;
  timestamp_nsec_t flow_end;

  u32 last_exported[FT_ORDER_MAX];
  u32 ipfix_info_index[FT_ORDER_MAX];

  /* Generation ID that must match the session's if this flow is up to date */
  u16 generation;
#if CLIB_DEBUG > 0
  u32 cpu_index;
#endif
  u16 nat_sport;
} flow_entry_t;

/* accessor helper */
#define flow_member(F, M, D)   (F)->M[(D) ^ (F)->is_reverse]
#define flow_next(F, D) flow_member((F), _next, (D))
#define flow_teid(F, D) flow_member((F), _teid, (D))
#define flow_pdr_id(F, D) flow_member((F), _pdr_id, (D))
#define flow_tc(F, D) flow_member((F), _tc, (D))
#define flow_seq_offs(F, D) flow_member((F), _seq_offs, (D))
#define flow_tsval_offs(F, D) flow_member((F), _tsval_offs, (D))
#define flow_stats(F, D) flow_member((F), stats, (D))
#define flow_last_exported(F, D) flow_member((F), last_exported, (D))
#define flow_ipfix_info(F, D) flow_member((F), ipfix_info_index, (D))

/* Timers (in seconds) */
#define TIMER_DEFAULT_LIFETIME (60)
#define TIMER_MAX_LIFETIME (600)

/* Default max number of flows to expire during one run.
 * 256 is the max number of packets in a vector, so this is a minimum
 * if all packets create a flow. */
#define TIMER_MAX_EXPIRE (1 << 8)

typedef struct
{
  /* hashtable */
  clib_bihash_48_8_t flows_ht;

  /* timers */
  dlist_elt_t *timers;
  u32 time_index;
  u32 next_check;

  /* flow cache
   * set cache size to 256 so that the worst node run fills the cache at most once */
#define FLOW_CACHE_SZ 256
  u32 *flow_cache;
} flowtable_main_per_cpu_t;

#define FLOWTABLE_DEFAULT_LOG2_SIZE 22

typedef struct
{
  /* flow entry pool */
  u32 log2_size;
  u32 flows_max;
  flow_entry_t *flows;
  pthread_spinlock_t flows_lock;
  u64 flows_cpt;

  u16 timer_lifetime[FT_TIMEOUT_TYPE_MAX];
  u16 timer_max_lifetime;

  /* per cpu */
  flowtable_main_per_cpu_t *per_cpu;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} flowtable_main_t;

extern flowtable_main_t flowtable_main;
typedef int (*flow_expiration_hook_t) (flow_entry_t * flow);
typedef void (*flow_update_hook_t) (flow_entry_t * flow,
				    flow_direction_t direction, u32 now);
typedef void (*flow_removal_hook_t) (flow_entry_t * flow, u32 now);

extern flow_expiration_hook_t flow_expiration_hook;
extern flow_update_hook_t flow_update_hook;
extern flow_removal_hook_t flow_removal_hook;

u8 *format_flow_key (u8 *, va_list *);
u8 *format_flow (u8 *, va_list *);

clib_error_t *flowtable_lifetime_update (flowtable_timeout_type_t type,
					 u16 value);
clib_error_t *flowtable_max_lifetime_update (u16 value);
clib_error_t *flowtable_init (vlib_main_t * vm);

void foreach_upf_flows (clib_bihash_kv_48_8_t * kvp, void *arg);

static inline u16
flowtable_lifetime_get (flowtable_timeout_type_t type)
{
  flowtable_main_t *fm = &flowtable_main;

  return (type >= FT_TIMEOUT_TYPE_MAX) ? ~0 : fm->timer_lifetime[type];
}

static inline flow_entry_t *
flowtable_get_flow (flowtable_main_t * fm, u32 flow_index)
{
  return pool_elt_at_index (fm->flows, flow_index);
}

u32
flowtable_entry_lookup_create (flowtable_main_t * fm,
			       flowtable_main_per_cpu_t * fmt,
			       clib_bihash_kv_48_8_t * kv,
			       timestamp_nsec_t timestamp, u32 const now,
			       u8 is_reverse, u16 generation, int *created);

void
timer_wheel_index_update (flowtable_main_t * fm,
			  flowtable_main_per_cpu_t * fmt, u32 now);

u64
flowtable_timer_expire (flowtable_main_t * fm, flowtable_main_per_cpu_t * fmt,
			u32 now);

static inline void
parse_packet_protocol (udp_header_t * udp, uword is_reverse, flow_key_t * key)
{
  if (key->proto == IP_PROTOCOL_UDP || key->proto == IP_PROTOCOL_TCP)
    {
      /* tcp and udp ports have the same offset */
      key->port[FT_ORIGIN ^ is_reverse] = udp->src_port;
      key->port[FT_REVERSE ^ is_reverse] = udp->dst_port;
    }
  else
    {
      key->port[FT_ORIGIN] = key->port[FT_REVERSE] = 0;
    }
}

static inline flow_direction_t
ip4_packet_is_reverse (ip4_header_t * ip4)
{
  return (ip4_address_compare (&ip4->src_address, &ip4->dst_address) < 0) ?
    FT_REVERSE : FT_ORIGIN;
}

static inline void
parse_ip4_packet (ip4_header_t * ip4, uword * is_reverse, flow_key_t * key)
{
  key->proto = ip4->protocol;

  *is_reverse = ip4_packet_is_reverse (ip4);

  ip46_address_set_ip4 (&key->ip[FT_ORIGIN ^ *is_reverse], &ip4->src_address);
  ip46_address_set_ip4 (&key->ip[FT_REVERSE ^ *is_reverse],
			&ip4->dst_address);

  parse_packet_protocol ((udp_header_t *) ip4_next_header (ip4), *is_reverse,
			 key);
}

static inline flow_direction_t
ip6_packet_is_reverse (ip6_header_t * ip6)
{
  return (ip6_address_compare (&ip6->src_address, &ip6->dst_address) < 0) ?
    FT_REVERSE : FT_ORIGIN;
}

static inline void
parse_ip6_packet (ip6_header_t * ip6, uword * is_reverse, flow_key_t * key)
{
  key->proto = ip6->protocol;

  *is_reverse = ip6_packet_is_reverse (ip6);

  ip46_address_set_ip6 (&key->ip[FT_ORIGIN ^ *is_reverse], &ip6->src_address);
  ip46_address_set_ip6 (&key->ip[FT_REVERSE ^ *is_reverse],
			&ip6->dst_address);

  parse_packet_protocol ((udp_header_t *) ip6_next_header (ip6), *is_reverse,
			 key);
}

static inline void
flow_mk_key (u64 seid, u8 * header, u8 is_ip4,
	     uword * is_reverse, clib_bihash_kv_48_8_t * kv)
{
  flow_key_t *key = (flow_key_t *) & kv->key;

  memset (key, 0, sizeof (*key));

  key->seid = seid;

  /* compute 5 tuple key so that 2 half connections
   * get into the same flow */
  if (is_ip4)
    {
      parse_ip4_packet ((ip4_header_t *) header, is_reverse, key);
    }
  else
    {
      parse_ip6_packet ((ip6_header_t *) header, is_reverse, key);
    }
}

always_inline void
flow_tcp_update_lifetime (flow_entry_t * f, tcp_header_t * hdr)
{
  tcp_f_state_t old_state, new_state;

  ASSERT (f->tcp_state < TCP_F_STATE_MAX);

  old_state = f->tcp_state;
  new_state = tcp_trans[old_state][tcp_event (hdr)];

  if (new_state && old_state != new_state)
    {
      flowtable_main_t *fm = &flowtable_main;
      u32 cpu_index = os_get_thread_index ();
      flowtable_main_per_cpu_t *fmt = &fm->per_cpu[cpu_index];
      u32 timer_slot_head_index;

      /*
       * Make sure we're not scheduling this flow "in the past",
       * otherwise it may add the period of the "wheel turn" to its
       * expiration time
       */
      ASSERT (fmt->next_check == ~0
	      || f->active + f->lifetime >= fmt->next_check);
      f->tcp_state = new_state;
      f->lifetime = tcp_lifetime[new_state];
      /* reschedule */
      clib_dlist_remove (fmt->timers, f->timer_index);

      timer_slot_head_index =
	(f->active + f->lifetime) % fm->timer_max_lifetime;
      clib_dlist_addtail (fmt->timers, timer_slot_head_index, f->timer_index);
    }
}

always_inline void
flow_update (vlib_main_t * vm, flow_entry_t * f,
	     u8 * iph, u8 is_ip4, u16 len, u32 now)
{
  ASSERT (f->active <= now);
  f->active = now;

  if (f->key.proto == IP_PROTOCOL_TCP && len >= sizeof (tcp_header_t))
    {
      tcp_header_t *hdr = (tcp_header_t *) (is_ip4 ?
					    ip4_next_header ((ip4_header_t *)
							     iph) :
					    ip6_next_header ((ip6_header_t *)
							     iph));
      flow_tcp_update_lifetime (f, hdr);
    }
}

always_inline void
flow_update_stats (vlib_main_t * vm, vlib_buffer_t * b,
		   flow_entry_t * f, u8 is_ip4,
		   timestamp_nsec_t timestamp, u32 now)
{
  /*
   * Performance note:
   * vlib_buffer_length_in_chain() caches its result for the buffer
   */
  u16 len = vlib_buffer_length_in_chain (vm, b);
  u8 *iph = vlib_buffer_get_current (b);
  u8 *l4h = (is_ip4 ?
	     ip4_next_header ((ip4_header_t *)
			      iph) : ip6_next_header ((ip6_header_t *) iph));
  u16 l4_len = len - (l4h - iph);
  u16 diff;
  flow_direction_t is_reverse =
    is_ip4 ?
    ip4_packet_is_reverse ((ip4_header_t *) iph) :
    ip6_packet_is_reverse ((ip6_header_t *) iph);

  flow_direction_t direction = f->is_reverse ^ is_reverse;
  switch (f->key.proto)
    {
    case IP_PROTOCOL_TCP:
      diff = tcp_header_bytes ((tcp_header_t *) l4h);
      break;
    case IP_PROTOCOL_UDP:
      diff = sizeof (udp_header_t);
      break;
    }
  l4_len = l4_len > diff ? l4_len - diff : 0;

  f->stats[is_reverse].pkts++;
  f->stats[is_reverse].pkts_unreported++;
  f->stats[is_reverse].bytes += len;
  f->stats[is_reverse].bytes_unreported += len;
  f->stats[is_reverse].l4_bytes += l4_len;
  f->stats[is_reverse].l4_bytes_unreported += l4_len;
  f->flow_end = timestamp;

  if (flow_update_hook != 0)
    flow_update_hook (f, direction, now);
}

always_inline void
timer_wheel_insert_flow (flowtable_main_t * fm,
			 flowtable_main_per_cpu_t * fmt, flow_entry_t * f)
{
  u32 timer_slot_head_index;

  timer_slot_head_index =
    (fmt->time_index + f->lifetime) % fm->timer_max_lifetime;
  clib_dlist_addtail (fmt->timers, timer_slot_head_index, f->timer_index);
}

extern vlib_node_registration_t flowtable_process_node;

#endif /* __flowtable_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
