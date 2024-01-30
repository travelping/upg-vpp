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
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>

#include "flowtable_tcp.h"
#include "llist.h"
#include "upf_buffer_opaque.h"

#define foreach_flowtable_error                                               \
  _ (HIT, "packets with an existing flow")                                    \
  _ (THRU, "packets gone through")                                            \
  _ (CREATED, "packets which created a new flow")                             \
  _ (NO_SESSION, "packet without session")                                    \
  _ (COLLISION, "hashtable collisions")                                       \
  _ (OVERFLOW, "dropped due to flowtable overflow")

typedef enum
{
#define _(sym, str) FLOWTABLE_ERROR_##sym,
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

// This enum has no high-level meaning like ingres or uplink, but instead
// needed to use same flow key for ingress and egress direction and means
// swapping of dst/src addresses in flow key for this purposes.
// Other meaning of this enum is index of flow directional elements, if
// element with index FT_ORIGIN is used, then it's initiator, otherwise
// responder
typedef enum
{
  // src to dst direction, or initiator (if xored with initiator_direction)
  FT_ORIGIN = 0,
  // dst to src direction, or responder (if xored with initiator_direction)
  FT_REVERSE,
  FT_ORDER_MAX
} __clib_packed flow_key_direction_t;

/* key */
typedef struct
{
  union
  {
    struct
    {
      u64 up_seid;
      ip46_address_t ip[FT_ORDER_MAX];
      u16 port[FT_ORDER_MAX];
      u8 proto;
    };
    u64 key[6];
  };
} flow_key_t;

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

UPF_LLIST_TEMPLATE_TYPES (session_flows_list);
UPF_LLIST_TEMPLATE_TYPES (flow_timeout_list);

typedef struct flow_entry
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* flow signature */
  flow_key_t key;
  u32 session_index;

  // Is src/dst been swapped on flow creation
  // Bascially this means if dst field is initiator of flow or not.
  // Note that initiator of flow is not related to direction in ipfix
  // As well as not related to uplink/downlink in pfcp
  u8 initiator_direction : 1;
  u8 is_redirect : 1;
  u8 is_l3_proxy : 1;
  u8 is_spliced : 1;
  u8 spliced_dirty : 1;
  u8 dont_splice : 1;
  u8 app_detection_done : 1;
  u8 exported : 1;
  u8 tcp_state;
  u32 ps_index;

  /* stats */
  // This array indexes are not relative to initiator_direction, this means
  // that xor with initiator_direction is not needed
  flow_stats_t stats[FT_ORDER_MAX];

  /* timers */
  u32 active;     /* last activity ts */
  u16 lifetime;   /* in seconds */
  u16 timer_slot; /* timer list index in the timer lists pool */
  flow_timeout_list_anchor_t timer_anchor;

  /* UPF data */
  u32 application_id;        /* L7 app index */
  u32 _pdr_id[FT_ORDER_MAX]; /* PDRs */
  u32 _teid[FT_ORDER_MAX];
  u32 _next[FT_ORDER_MAX];

  flow_tc_t _tc[FT_ORDER_MAX];

  u32 _seq_offs[FT_ORDER_MAX];
  u32 _tsval_offs[FT_ORDER_MAX];

  u8 *app_uri;

  u64 flow_start_time; /* unix nanoseconds */
  u64 flow_end_time;   /* unix nanoseconds */

  u32 last_exported[FT_ORDER_MAX];
  u32 ipfix_info_index[FT_ORDER_MAX];

  session_flows_list_anchor_t session_list_anchor;

  /* Generation ID that must match the session's if this flow is up to date */
  u16 generation;
  u32 cpu_index;
  u16 nat_sport;
} flow_entry_t;

UPF_LLIST_TEMPLATE_DEFINITIONS (session_flows_list, flow_entry_t,
                                session_list_anchor);
UPF_LLIST_TEMPLATE_DEFINITIONS (flow_timeout_list, flow_entry_t, timer_anchor);

/* accessor helper */
#define flow_member(F, M, D)     (F)->M[(D) ^ (F)->initiator_direction]
#define flow_next(F, D)          flow_member ((F), _next, (D))
#define flow_teid(F, D)          flow_member ((F), _teid, (D))
#define flow_pdr_id(F, D)        flow_member ((F), _pdr_id, (D))
#define flow_tc(F, D)            flow_member ((F), _tc, (D))
#define flow_seq_offs(F, D)      flow_member ((F), _seq_offs, (D))
#define flow_tsval_offs(F, D)    flow_member ((F), _tsval_offs, (D))
#define flow_stats(F, D)         flow_member ((F), stats, (D))
#define flow_last_exported(F, D) flow_member ((F), last_exported, (D))
#define flow_ipfix_info(F, D)    flow_member ((F), ipfix_info_index, (D))

/* Timers (in seconds) */
#define FLOW_TIMER_DEFAULT_LIFETIME (60)
#define FLOW_TIMER_MAX_LIFETIME     (600)

/* Default max number of flows to expire during one run.
 * 256 is the max number of packets in a vector, so this is a minimum
 * if all packets create a flow. */
#define FLOW_TIMER_MAX_EXPIRE (1 << 8)

typedef struct
{
  /* hashtable */
  clib_bihash_48_8_t flows_ht;

  /* vector of FLOW_TIMER_MAX_LIFETIME timers lists */
  flow_timeout_list_t *timers;

  u32 time_index;
  u32 next_check;
} flowtable_main_per_cpu_t;

#define FLOWTABLE_DEFAULT_LOG2_SIZE 22

typedef struct
{
  /* flow entry pool */
  u32 log2_size;
  u32 flows_max;
  flow_entry_t *flows;
  u32 current_flows_count;

  u16 timer_lifetime[FT_TIMEOUT_TYPE_MAX];

  /* per cpu */
  flowtable_main_per_cpu_t *per_cpu;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} flowtable_main_t;

extern flowtable_main_t flowtable_main;

u8 *format_flow_key (u8 *, va_list *);
u8 *format_flow (u8 *, va_list *);

clib_error_t *flowtable_lifetime_update (flowtable_timeout_type_t type,
                                         u16 value);
clib_error_t *flowtable_init (vlib_main_t *vm);

__clib_unused static inline u16
flowtable_lifetime_get (flowtable_timeout_type_t type)
{
  flowtable_main_t *fm = &flowtable_main;

  return (type >= FT_TIMEOUT_TYPE_MAX) ? ~0 : fm->timer_lifetime[type];
}

__clib_unused static inline flow_entry_t *
flowtable_get_flow (flowtable_main_t *fm, u32 flow_index)
{
  return pool_elt_at_index (fm->flows, flow_index);
}

void flowtable_entry_remove (flowtable_main_t *fm, flow_entry_t *f, u32 now);

u32 flowtable_entry_lookup_create (flowtable_main_t *fm,
                                   flowtable_main_per_cpu_t *fmt,
                                   clib_bihash_kv_48_8_t *kv, u64 timestamp_ns,
                                   u32 const now,
                                   flow_key_direction_t key_direction,
                                   u16 generation, u32 session_index,
                                   int *created);

void flowtable_timer_wheel_index_update (flowtable_main_t *fm,
                                         flowtable_main_per_cpu_t *fmt,
                                         u32 now);

void flowtable_entry_remove_internal (flowtable_main_t *fm,
                                      flowtable_main_per_cpu_t *fmt,
                                      flow_entry_t *f, u32 now);

always_inline u16
flowtable_time_to_timer_slot (u32 when_seconds)
{
  return when_seconds % FLOW_TIMER_MAX_LIFETIME;
}

always_inline void
flowtable_timeout_stop_entry (flowtable_main_t *fm,
                              flowtable_main_per_cpu_t *fmt, flow_entry_t *f)
{
  ASSERT (f->timer_slot != (u16) ~0);

  flow_timeout_list_remove (fm->flows,
                            vec_elt_at_index (fmt->timers, f->timer_slot), f);
  f->timer_slot = ~0;
};

// returns timers slot which was used for flow
always_inline u16
flowtable_timeout_start_entry (flowtable_main_t *fm,
                               flowtable_main_per_cpu_t *fmt, flow_entry_t *f,
                               u32 now)
{
  ASSERT (f->timer_slot == (u16) ~0);

  /*
   * Make sure we're not scheduling this flow "in the past",
   * otherwise it may add the period of the "wheel turn" to its
   * expiration time
   */
  ASSERT (fmt->next_check == ~0 || now + f->lifetime >= fmt->next_check);

  u16 timer_slot = flowtable_time_to_timer_slot (now + f->lifetime);
  flow_timeout_list_insert_tail (
    fm->flows, vec_elt_at_index (fmt->timers, timer_slot), f);
  f->timer_slot = timer_slot;
  return timer_slot;
}

static inline void
parse_packet_protocol (udp_header_t *udp, flow_key_direction_t key_direction,
                       flow_key_t *key)
{
  if (key->proto == IP_PROTOCOL_UDP || key->proto == IP_PROTOCOL_TCP)
    {
      /* tcp and udp ports have the same offset */
      key->port[FT_ORIGIN ^ key_direction] = udp->src_port;
      key->port[FT_REVERSE ^ key_direction] = udp->dst_port;
    }
  else
    {
      key->port[FT_ORIGIN] = key->port[FT_REVERSE] = 0;
    }
}

static inline flow_key_direction_t
ip4_packet_is_reverse (ip4_header_t *ip4)
{
  return (ip4_address_compare (&ip4->src_address, &ip4->dst_address) < 0) ?
           FT_REVERSE :
           FT_ORIGIN;
}

static inline void
parse_ip4_packet (ip4_header_t *ip4, flow_key_direction_t *key_direction,
                  flow_key_t *key)
{
  key->proto = ip4->protocol;

  *key_direction = ip4_packet_is_reverse (ip4);

  ip46_address_set_ip4 (&key->ip[FT_ORIGIN ^ *key_direction],
                        &ip4->src_address);
  ip46_address_set_ip4 (&key->ip[FT_REVERSE ^ *key_direction],
                        &ip4->dst_address);

  parse_packet_protocol ((udp_header_t *) ip4_next_header (ip4),
                         *key_direction, key);
}

static inline flow_key_direction_t
ip6_packet_is_reverse (ip6_header_t *ip6)
{
  return (ip6_address_compare (&ip6->src_address, &ip6->dst_address) < 0) ?
           FT_REVERSE :
           FT_ORIGIN;
}

static inline void
parse_ip6_packet (ip6_header_t *ip6, flow_key_direction_t *key_direction,
                  flow_key_t *key)
{
  key->proto = ip6->protocol;

  *key_direction = ip6_packet_is_reverse (ip6);

  ip46_address_set_ip6 (&key->ip[FT_ORIGIN ^ *key_direction],
                        &ip6->src_address);
  ip46_address_set_ip6 (&key->ip[FT_REVERSE ^ *key_direction],
                        &ip6->dst_address);

  parse_packet_protocol ((udp_header_t *) ip6_next_header (ip6),
                         *key_direction, key);
}

__clib_unused static inline void
flow_mk_key (u64 up_seid, u8 *header, u8 is_ip4,
             flow_key_direction_t *key_direction, clib_bihash_kv_48_8_t *kv)
{
  flow_key_t *key = (flow_key_t *) &kv->key;

  memset (key, 0, sizeof (*key));

  key->up_seid = up_seid;

  /* compute 5 tuple key so that 2 half connections
   * get into the same flow */
  if (is_ip4)
    {
      parse_ip4_packet ((ip4_header_t *) header, key_direction, key);
    }
  else
    {
      parse_ip6_packet ((ip6_header_t *) header, key_direction, key);
    }
}

always_inline void
flow_tcp_update_lifetime (flow_entry_t *f, tcp_header_t *hdr, u32 now)
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

      f->tcp_state = new_state;
      f->lifetime = tcp_lifetime[new_state];

      /* reschedule */
      flowtable_timeout_stop_entry (fm, fmt, f);
      flowtable_timeout_start_entry (fm, fmt, f, now);
    }
}

__clib_unused always_inline void
flow_update (vlib_main_t *vm, flow_entry_t *f, u8 *iph, u8 is_ip4, u16 len,
             u32 now)
{
  ASSERT (f->active <= now);
  f->active = now;

  if (f->key.proto == IP_PROTOCOL_TCP && len >= sizeof (tcp_header_t))
    {
      tcp_header_t *hdr =
        (tcp_header_t *) (is_ip4 ? ip4_next_header ((ip4_header_t *) iph) :
                                   ip6_next_header ((ip6_header_t *) iph));
      flow_tcp_update_lifetime (f, hdr, now);
    }
}

int upf_ipfix_flow_stats_update_handler (flow_entry_t *f,
                                         flow_key_direction_t direction,
                                         u32 now);

__clib_unused always_inline void
flow_update_stats (vlib_main_t *vm, vlib_buffer_t *b, flow_entry_t *f,
                   u8 is_ip4, u64 timestamp_ns, u32 now)
{
  /*
   * Performance note:
   * vlib_buffer_length_in_chain() caches its result for the buffer
   */
  u16 len = vlib_buffer_length_in_chain (vm, b);

  u8 pkt_direction = upf_buffer_opaque (b)->gtpu.pkt_direction;

  u8 *iph = vlib_buffer_get_current (b);
  u8 *l4h = (is_ip4 ? ip4_next_header ((ip4_header_t *) iph) :
                      ip6_next_header ((ip6_header_t *) iph));
  u16 l4_len = len - (l4h - iph);
  u16 diff;

  flow_key_direction_t direction = f->initiator_direction ^ pkt_direction;
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

  f->stats[pkt_direction].pkts++;
  f->stats[pkt_direction].pkts_unreported++;
  f->stats[pkt_direction].bytes += len;
  f->stats[pkt_direction].bytes_unreported += len;
  f->stats[pkt_direction].l4_bytes += l4_len;
  f->stats[pkt_direction].l4_bytes_unreported += l4_len;
  f->flow_end_time = timestamp_ns;

  upf_ipfix_flow_stats_update_handler (f, direction, now);
}

#endif /* __flowtable_h__ */
