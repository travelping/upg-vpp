/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _UPF_PFCP_H_
#define _UPF_PFCP_H_

#include "upf.h"

#define MAX_LEN 128

#define upf_pfcp_associnfo(gtm, ...) \
  vlib_log_info((gtm)->log_class, __VA_ARGS__)

upf_node_assoc_t *pfcp_get_association (pfcp_node_id_t * node_id);
upf_node_assoc_t *pfcp_new_association (session_handle_t session_handle,
					ip46_address_t * lcl_addr,
					ip46_address_t * rmt_addr,
					pfcp_node_id_t * node_id);
void pfcp_release_association (upf_node_assoc_t * n);

upf_session_t *pfcp_create_session (upf_node_assoc_t * assoc,
				    const ip46_address_t * up_address,
				    uint64_t cp_seid,
				    const ip46_address_t * cp_address);
void pfcp_update_session (upf_session_t * sx);
void pfcp_disable_session (upf_session_t * sx);
void pfcp_free_session (upf_session_t * sx);
int session_flow_unlink_handler (flowtable_main_t * fm, flow_entry_t * flow,
				 flow_direction_t direction, u32 now);

#define pfcp_rule_vector_fns(t)						\
upf_##t##_t * pfcp_get_##t##_by_id(struct rules *,			\
				   typeof (((upf_##t##_t *)0)->id) t##_id);	\
upf_##t##_t *pfcp_get_##t(upf_session_t *sx, int rule,			\
			  typeof (((upf_##t##_t *)0)->id) t##_id);	\
int pfcp_create_##t(upf_session_t *sx, upf_##t##_t *t);			\
int pfcp_make_pending_##t(upf_session_t *sx);				\
int pfcp_sort_##t##s(struct rules *rules);				\
int pfcp_delete_##t(upf_session_t *sx, u32 t##_id);			\

/* *INDENT-OFF* */
pfcp_rule_vector_fns (pdr)
pfcp_rule_vector_fns (far)
pfcp_rule_vector_fns (urr)
pfcp_rule_vector_fns (qer)
/* *INDENT-ON* */

#undef pfcp_rule_vector_fns
#define vec_bsearch(k, v, compar)                               \
        bsearch((k), (v), vec_len((v)), sizeof((v)[0]), compar)

void pfcp_send_end_marker (upf_session_t * sx, u16 far_id);

int pfcp_update_apply (upf_session_t * sx);
void pfcp_update_finish (upf_session_t * sx);

upf_session_t *pfcp_lookup (uint64_t sess_id);

static inline struct rules *
pfcp_get_rules (upf_session_t * sx, int rules)
{
  return &sx->rules[sx->active ^ rules];
}

void vlib_free_combined_counter (vlib_combined_counter_main_t * cm);

u32 process_urrs (vlib_main_t * vm, upf_session_t * sess,
		  const char *node_name,
		  struct rules *active,
		  upf_pdr_t * pdr, vlib_buffer_t * b,
		  u8 is_dl, u8 is_ul, u32 next);
u32 process_qers (vlib_main_t * vm, upf_session_t * sess,
		  struct rules *r,
		  upf_pdr_t * pdr, vlib_buffer_t * b,
		  u8 is_dl, u8 is_ul, u32 next);

void upf_pfcp_error_report (upf_session_t * sx, gtp_error_ind_t * error);
void upf_ref_forwarding_policies (upf_far_t * far, u8 is_del);
int pfcp_session_server_apply_config (u64 segment_size, u32 prealloc_fifos,
				      u32 fifo_size);
void pfcp_session_server_get_config (u64 * segment_size, u32 * prealloc_fifos,
				     u32 * fifo_size);

/* format functions */
u8 *format_pfcp_node_association (u8 * s, va_list * args);
u8 *format_upf_far (u8 * s, va_list * args);
u8 *format_pfcp_session (u8 * s, va_list * args);
u8 *format_pfcp_endpoint_key (u8 * s, va_list * args);
u8 *format_network_instance_index (u8 * s, va_list * args);
u8 *format_gtpu_endpoint (u8 * s, va_list * args);

/**
 * Compare integer ids.
 */
#define intcmp(a, b)                                    \
	({                                              \
		typeof (a) a_ = (a);                    \
		typeof (b) b_ = (b);                    \
		(a_) < (b_) ? -1 : (a_) > (b_) ? 1 : 0; \
	})

static inline int
ipfilter_address_cmp_const (const ipfilter_address_t * a,
			    const ipfilter_address_t b)
{
  int r;

  if ((r = intcmp (a->address.as_u64[0], b.address.as_u64[0])) != 0)
    return r;
  if ((r = intcmp (a->address.as_u64[1], b.address.as_u64[1])) != 0)
    return r;
  return intcmp (a->mask, b.mask);
};

static inline void
upf_nwi_if_and_fib_index (upf_main_t * gtm, fib_protocol_t proto,
			  u32 nwi_index, u32 * sw_if_index, u32 * fib_index)
{
  if (!pool_is_free_index (gtm->nwis, nwi_index))
    {
      upf_nwi_t *nwi = pool_elt_at_index (gtm->nwis, nwi_index);

      *sw_if_index = nwi->sw_if_index;
      *fib_index = nwi->fib_index[proto];
    }
  else
    {
      *sw_if_index = vnet_main.local_interface_sw_if_index;
      *fib_index = ~0;
    }
}

static inline u32
upf_nwi_fib_index (fib_protocol_t proto, u32 nwi_index)
{
  upf_main_t *gtm = &upf_main;

  if (!pool_is_free_index (gtm->nwis, nwi_index))
    {
      upf_nwi_t *nwi = pool_elt_at_index (gtm->nwis, nwi_index);
      return nwi->fib_index[proto];
    }
  else
    return ~0;
}

static_always_inline u32
flow_pdr_idx (flow_entry_t * flow, flow_direction_t direction,
	      struct rules *r)
{
  upf_pdr_t *pdr;
  u32 pdr_id = flow_pdr_id (flow, direction);

  if (pdr_id == ~0)
    return ~0;

  pdr = pfcp_get_pdr_by_id (r, pdr_id);
  return pdr ? pdr - r->pdr : ~0;
}

#endif /* _UPF_PFCP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
