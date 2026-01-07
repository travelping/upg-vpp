/*
 * Copyright (c) 2017-2025 Travelping GmbH
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/prctl.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlib/unix/plugin.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_walk.h>

#include "upf/upf.h"
#include "upf/pfcp/pfcp_proto.h"
#include "upf/pfcp/upf_pfcp_server.h"
#include "upf/integrations/upf_ipfix.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/core/upf_buffer_opaque.h"
#include "upf/upf_stats.h"

#include "upf/version.h"

upf_main_t upf_main;

#define UPF_DEBUG_ENABLE 0

static u8 *
_upf_format_buffer_opaque_helper (const vlib_buffer_t *b, u8 *s)
{
  upf_buffer_opaque_t *o = upf_buffer_opaque (b);

  // s = format (
  //   s,
  //   "gtpu.teid: 0x%08x, gtpu.session_index: 0x%x, gtpu.ext_hdr_len: %u, "
  //   "gtpu.data_offset: %u, gtpu.flags: 0x%02x, gtpu.flow_key_direction: %u,
  //   " "gtpu.direction: %u, gtpu.pdr_idx: 0x%x, gtpu.flow_id: 0x%x", (u32)
  //   (o->gtpu.teid), (u32) (o->gtpu.session_index), (u32)
  //   (o->gtpu.ext_hdr_len), (u32) (o->gtpu.data_offset), (u32)
  //   (o->gtpu.flags), (u32) (o->gtpu.flow_key_direction), (u32)
  //   (o->gtpu.direction), (u32) (o->gtpu.pdr_idx), (u32) (o->gtpu.flow_id));
  vec_add1 (s, '\n');

  return s;
}

VLIB_PLUGIN_REGISTER () = {
  .version = UPG_VERSION,
  .description = "User Plane Gateway",
};

void
upf_post_mortem_dump (void)
{
  // VPPs elog file writing is broken with ASAN. And tooling around it is not
  // well supported. This is simpler interface to be able to print last X
  // events after crash.
  // Based on elog_show_buffer_internal from vlib/main.c

  static int in_post_mortem = 0;
  if (in_post_mortem)
    {
      clib_warning ("Recursive post-mortem dump detected, aborting to prevent "
                    "infinite loop");
      return;
    }
  in_post_mortem = 1;

  elog_main_t *em = vlib_get_elog_main ();
  vlib_main_t *vm = vlib_get_main ();
  upf_main_t *um = &upf_main;

  u32 n_events_to_show = um->post_mortem_events_show_limit;

  /* Show events in VLIB time since log clock starts after VLIB clock. */
  f64 dt = (em->init_time.cpu - vm->clib_time.init_cpu_time) *
           vm->clib_time.seconds_per_clock;

  elog_event_t *es = elog_peek_events (em);

  clib_warning ("%d of %d events in buffer, logger %s, output limit %d",
                vec_len (es), em->event_ring_size,
                em->n_total_events < em->n_total_events_disable_limit ?
                  "running" :
                  "stopped",
                n_events_to_show);

  u32 n = clib_min (vec_len (es), n_events_to_show);
  u32 start_id = vec_len (es) - n;

  for (u32 i = 0; i < n; i++)
    {
      elog_event_t *e = vec_elt_at_index (es, start_id + i);
      clib_warning ("%18.9f: %U", e->time + dt, format_elog_event, em, e);
    }

  vec_free (es);
  in_post_mortem = 0;
}

static clib_error_t *
_upf_init (vlib_main_t *vm)
{
  upf_main_t *um = &upf_main;
  upf_mt_main_t *umm = &upf_mt_main;
  upf_acl_main_t *uam = &upf_acl_main;
  clib_error_t *error = NULL;

  *um = (upf_main_t){};

  upf_stats_init ();
  upf_timer_init ();
  upf_mt_init ();
  pfcp_server_main_init ();

  um->pfcp_spec_version = 15;
  um->rand_base = random_default_seed ();
  um->log_class = vlib_log_register_class_rate_limit ("upf", 0, 30);
  um->ueip_export.enabled = false;
  um->post_mortem_events_show_limit = 50;
  um->start_of_traffic_event_timeout_s = 15;
  ratelimit_atomic_init (&um->start_of_traffic_rate_limit,
                         upf_time_now_main (), 5000);

  if ((error = vlib_call_init_function (vm, upf_proxy_main_init)))
    return error;

  netcap_plugin_v1_methods_vtable_init_fn_t netcap_vtbl_init =
    vlib_get_plugin_symbol ("netcap_plugin.so",
                            "netcap_plugin_v1_methods_vtable_init");
  if (netcap_vtbl_init)
    {
      if ((error = netcap_vtbl_init (&um->netcap.methods)))
        return error;

      clib_warning ("upf netcap integration enabled");

      if ((error = um->netcap.methods.register_class (
             "upf_session_ip", 0, &um->netcap.class_session_ip)))
        return error;

      um->netcap.enabled = true;
    }
  else
    {
      clib_warning ("upf netcap integration disabled");
      um->netcap.enabled = false;
    }

  vnet_register_format_buffer_opaque2_helper (
    _upf_format_buffer_opaque_helper);

  mhash_init (&um->pfcp_endpoint_index, sizeof (uword),
              sizeof (upf_pfcp_endpoint_key_t));
  um->nwi_index_by_name = hash_create_vec (0, sizeof (u8), sizeof (uword));

  um->forwarding_policy_by_id =
    hash_create_vec (0, sizeof (u8), sizeof (uword));

  um->assoc_index_by_fqdn = hash_create_vec (0, sizeof (u8), sizeof (uword));
  mhash_init (&um->assoc_index_by_ip, sizeof (uword), sizeof (ip46_address_t));
  mhash_init (&um->mhash_cp_fseid_to_session_idx, sizeof (uword),
              sizeof (upf_cp_fseid_key_t));
  mhash_init (&um->mhash_cached_fseid_id, sizeof (uword),
              sizeof (upf_cached_f_seid_key_t));
  mhash_init (&um->mhash_imsi_to_session_list,
              sizeof (upf_imsi_sessions_list_t), sizeof (upf_imsi_t));
  mhash_init (&um->mhash_imsi_to_capture_list_id,
              sizeof (upf_imsi_capture_list_id_t), sizeof (upf_imsi_t));

  heap_new (um->heaps.pdrs);
  heap_new (um->heaps.fars);
  heap_new (um->heaps.urrs);
  heap_new (um->heaps.qers);
  heap_new (um->heaps.ep_ips4);
  heap_new (um->heaps.ep_ips6);
  heap_new (um->heaps.f_teids);
  heap_new (um->heaps.acls4);
  heap_new (um->heaps.acls6);
  heap_new (um->heaps.netcap_sets);

  vec_validate (um->workers, vec_len (umm->workers) - 1);
  ASSERT (vec_len (um->workers) == vec_len (umm->workers));
  ASSERT (vec_len (um->workers));

  upf_main_wk_t *wk;
  vec_foreach (wk, um->workers)
    {
      *wk = (upf_main_wk_t){};
    }

  upf_periodic_stats_init ();

  um->smf_sets = NULL;
  um->smf_set_by_fqdn = hash_create_vec (0, sizeof (u8), sizeof (uword));

  uam->cache_entry_by_rules =
    hash_create_vec (0, sizeof (ipfilter_rule_t), sizeof (u32));

  udp_register_dst_port (vm, UDP_DST_PORT_GTPU, upf_gtpu4_input_node.index,
                         /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_GTPU6, upf_gtpu6_input_node.index,
                         /* is_ip4 */ 0);

  upf_adf_init ();

  um->node_id.type = PFCP_NID_FQDN;
  um->node_id.fqdn = format (0, (char *) "\x03upg");

  um->ue_ip_pool_index_by_identity =
    hash_create_vec (0, sizeof (u8), sizeof (uword));

  if (!error)
    error = flowtable_init (vm);
  if (!error)
    error = upf_ipfix_init (vm);

  return error;
}

VLIB_INIT_FUNCTION (_upf_init);

VNET_FEATURE_INIT (upf, static) = {
  .arc_name = "device-input",
  .node_name = "upf",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

/* Taken from VPP DNS plugin */
/* original name_to_labels() from dns.c */
/**
 * Translate "foo.com" into "0x3 f o o 0x3 c o m 0x0"
 * A historical / hysterical micro-TLV scheme. DGMS.
 */
u8 *
upf_name_to_labels (u8 *name)
{
  int i;
  int last_label_index;
  u8 *rv;

  rv = vec_dup (name);

  /* punch in space for the first length */
  vec_insert (rv, 1, 0);
  last_label_index = 0;
  i = 1;

  while (i < vec_len (rv))
    {
      if (rv[i] == '.')
        {
          rv[last_label_index] = (i - last_label_index) - 1;
          if ((i - last_label_index) > 63)
            clib_warning ("stupid name, label length %d",
                          i - last_label_index);
          last_label_index = i;
          rv[i] = 0;
        }
      i++;
    }
  /* Set the last real label length */
  rv[last_label_index] = (i - last_label_index) - 1;

  return rv;
}
