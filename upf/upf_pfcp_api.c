/*
 * Copyright(c) 2018 Travelping GmbH.
 *
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

#include <assert.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <math.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/random.h>
#include <vppinfra/sparse_vec.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/fib/fib_path_list.h>

#include "pfcp.h"
#include "upf.h"
#include "upf_pfcp.h"
#include "upf_pfcp_server.h"
#include "upf_pfcp_api.h"
#include "upf_app_db.h"
#include "upf_ipfilter.h"
#include "upf_ipfix.h"

#include <vlib/unix/plugin.h>

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)                                                        \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

#define API_VERSION          1
#define TRAFFIC_TIMER_PERIOD 60

extern char *vpe_version_string;

typedef struct
{
  time_t start_time;
} upf_pfcp_session_t;

/* permit out ip from any to assigned */
static const acl_rule_t wildcard_acl = {
  .type = IPFILTER_WILDCARD,
  .action = ACL_PERMIT,
  .direction = ACL_OUT,
  .proto = ~0,
  .address = { [UPF_ACL_FIELD_SRC] = ACL_ADDR_ANY,
               [UPF_ACL_FIELD_DST] = ACL_ADDR_ASSIGNED },
  .port = { [UPF_ACL_FIELD_SRC] = { .min = 0, .max = ~0 },
            [UPF_ACL_FIELD_DST] = { .min = 0, .max = ~0 } }
};

size_t
upf_pfcp_api_session_data_size ()
{
  return sizeof (upf_pfcp_session_t);
}

void
upf_pfcp_api_session_data_init (void *sxp, time_t start_time)
{
  upf_pfcp_session_t *sx = (upf_pfcp_session_t *) sxp;

  memset (sx, 0, sizeof (*sx));
  sx->start_time = start_time;
}

static void
init_response_node_id (pfcp_ie_node_id_t *node_id)
{
  upf_main_t *gtm = &upf_main;
  *node_id = gtm->node_id;
  if (gtm->node_id.type == PFCP_NID_FQDN)
    {
      node_id->fqdn = vec_dup (gtm->node_id.fqdn);
    }
}

static void
init_response_up_f_seid (pfcp_ie_f_seid_t *up_f_seid, ip46_address_t *address,
                         bool is_ip4)
{
  if (is_ip4)
    {
      up_f_seid->flags |= PFCP_F_SEID_IP_ADDRESS_V4;
      up_f_seid->ip4 = address->ip4;
    }
  else
    {
      up_f_seid->flags |= PFCP_F_SEID_IP_ADDRESS_V6;
      up_f_seid->ip6 = address->ip6;
    }
}

#define tp_error_report(r, fmt, ...)                                          \
  init_tp_error_report (r, __FILE__, __LINE__, fmt, ##__VA_ARGS__);
#define tp_session_error_report(r, fmt, ...)                                  \
  do                                                                          \
    {                                                                         \
      UPF_SET_BIT ((r)->grp.fields,                                           \
                   SESSION_PROCEDURE_RESPONSE_TP_ERROR_REPORT);               \
      tp_error_report (&(r)->tp_error_report, (fmt), ##__VA_ARGS__);          \
    }                                                                         \
  while (0)

void
init_tp_error_report (pfcp_ie_tp_error_report_t *report, const char *file,
                      int line, char *fmt, ...)
{
#if CLIB_DEBUG > 1
  const char *p;
#endif
  va_list va;

  UPF_SET_BIT (report->grp.fields, TP_ERROR_REPORT_TP_ERROR_MESSAGE);

  va_start (va, fmt);
  report->error_message = va_format (0, fmt, &va);
  va_end (va);

#if CLIB_DEBUG > 1
  UPF_SET_BIT (report->grp.fields, TP_ERROR_REPORT_TP_FILE_NAME);
  UPF_SET_BIT (report->grp.fields, TP_ERROR_REPORT_TP_LINE_NUMBER);

  if ((p = strrchr (file, '/')) != NULL)
    {
      p++;
    }
  else
    p = file;
  vec_add (report->file_name, p, strlen (p));
  report->line_number = line;

  clib_warning ("%s:%u PFCP error: %v.\n", p, line, report->error_message);
#endif
}

/*************************************************************************/

/* message helpers */

static void
build_ue_ip_address_information (
  pfcp_ie_ue_ip_address_pool_information_t **ue_pool_info)
{
  upf_main_t *gtm = &upf_main;
  upf_nat_pool_t *np;
  upf_ue_ip_pool_info_t *ue_p;

  vec_alloc (*ue_pool_info, pool_elts (gtm->ueip_pools));

  pool_foreach (ue_p, gtm->ueip_pools)
    {
      pfcp_ie_ue_ip_address_pool_information_t *ueif;

      vec_add2 (*ue_pool_info, ueif, 1);
      ueif->ue_ip_address_pool_identity = vec_dup (ue_p->identity);
      UPF_SET_BIT (ueif->grp.fields,
                   UE_IP_ADDRESS_POOL_INFORMATION_POOL_IDENTIFY);

      ueif->network_instance = vec_dup (ue_p->nwi_name);
      UPF_SET_BIT (ueif->grp.fields,
                   UE_IP_ADDRESS_POOL_INFORMATION_NETWORK_INSTANCE);

      pool_foreach (np, gtm->nat_pools)
        {
          if (!(vec_is_equal (np->network_instance, ue_p->nwi_name)))
            continue;

          pfcp_ie_bbf_nat_port_block_t *block;

          vec_add2 (ueif->port_blocks, block, 1);
          *block = vec_dup (np->name);
          UPF_SET_BIT (ueif->grp.fields,
                       UE_IP_ADDRESS_POOL_INFORMATION_BBF_NAT_PORT_BLOCK);
        }
    }
}

static void
build_user_plane_ip_resource_information (
  pfcp_ie_user_plane_ip_resource_information_t **upip)
{
  upf_main_t *gtm = &upf_main;
  upf_upip_res_t *res;

  vec_alloc (*upip, pool_elts (gtm->upip_res));

  pool_foreach (res, gtm->upip_res)
    {
      pfcp_ie_user_plane_ip_resource_information_t *r;

      vec_add2 (*upip, r, 1);

      if (res->nwi_index != ~0)
        {
          upf_nwi_t *nwi = pool_elt_at_index (gtm->nwis, res->nwi_index);

          r->flags |= PFCP_USER_PLANE_IP_RESOURCE_INFORMATION_ASSONI;
          r->network_instance = vec_dup (nwi->name);
        }

      if (INTF_INVALID != res->intf)
        {

          r->flags |= PFCP_USER_PLANE_IP_RESOURCE_INFORMATION_ASSOSI;
          r->source_intf = res->intf;
        }

      if (res->mask != 0)
        {
          r->teid_range_indication = __builtin_popcount (res->mask);
          r->teid_range = (res->teid >> 24);
        }

      if (!is_zero_ip4_address (&res->ip4))
        {
          r->flags |= PFCP_USER_PLANE_IP_RESOURCE_INFORMATION_V4;
          r->ip4 = res->ip4;
        }

      if (!is_zero_ip6_address (&res->ip6))
        {
          r->flags |= PFCP_USER_PLANE_IP_RESOURCE_INFORMATION_V6;
          r->ip6 = res->ip6;
        }
    }
}

/* message handlers */

static int
handle_heartbeat_request (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_decoded_msg_t resp_dmsg = { .type = PFCP_MSG_HEARTBEAT_RESPONSE };
  pfcp_simple_response_t *resp = &resp_dmsg.simple_response;

  memset (resp, 0, sizeof (*resp));
  UPF_SET_BIT (resp->grp.fields, PFCP_RESPONSE_RECOVERY_TIME_STAMP);
  resp->response.recovery_time_stamp = psm->start_time;

  upf_debug ("PFCP: start_time: %p, %d, %x.", &psm, psm->start_time,
             psm->start_time);

  upf_pfcp_send_response (msg, &resp_dmsg);

  return 0;
}

static int
handle_heartbeat_response (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  upf_main_t *gtm = &upf_main;
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_node_assoc_t *n;
  pfcp_ie_recovery_time_stamp_t ts =
    dmsg->simple_response.response.recovery_time_stamp;

  if (msg->node == ~0 || pool_is_free_index (gtm->nodes, msg->node))
    return -1;

  n = pool_elt_at_index (gtm->nodes, msg->node);

  if (ts > n->recovery_time_stamp)
    pfcp_release_association (n);
  else if (ts < n->recovery_time_stamp)
    {
      /* 3GPP TS 23.007, Sect. 19A:
       *
       * If the value of a Recovery Time Stamp previously stored for a peer is
       * larger than the Recovery Time Stamp value received in the Heartbeat
       * Response message or the PFCP message, this indicates a possible race
       * condition (newer message arriving before the older one). The received
       * PFCP node related message and the received new Recovery Time Stamp
       * value shall be discarded and an error may be logged.
       */
      return -1;
    }
  else
    {
      upf_debug ("restarting HB timer\n");
      n->heartbeat_handle = upf_pfcp_server_start_timer (
        PFCP_SERVER_HB_TIMER, n - gtm->nodes, psm->hb_cfg.timeout);
    }

  return 0;
}

static int
handle_pfd_management_request (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_pfd_management_response (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_association_setup_request (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *gtm = &upf_main;
  pfcp_msg_association_setup_request_t *req = &dmsg->association_setup_request;
  pfcp_decoded_msg_t resp_dmsg = { .type =
                                     PFCP_MSG_ASSOCIATION_SETUP_RESPONSE };
  pfcp_msg_association_procedure_response_t *resp =
    &resp_dmsg.association_setup_response;
  upf_node_assoc_t *n;
  int r = 0;

  memset (resp, 0, sizeof (*resp));
  UPF_SET_BIT (resp->grp.fields, ASSOCIATION_PROCEDURE_RESPONSE_CAUSE);
  resp->cause = PFCP_CAUSE_REQUEST_REJECTED;

  UPF_SET_BIT (resp->grp.fields, ASSOCIATION_PROCEDURE_RESPONSE_NODE_ID);
  init_response_node_id (&resp->node_id);

  UPF_SET_BIT (resp->grp.fields,
               ASSOCIATION_PROCEDURE_RESPONSE_RECOVERY_TIME_STAMP);
  resp->recovery_time_stamp = psm->start_time;

  UPF_SET_BIT (resp->grp.fields, ASSOCIATION_PROCEDURE_RESPONSE_TP_BUILD_ID);
  vec_add (resp->tp_build_id, vpe_version_string, strlen (vpe_version_string));

  n = pfcp_get_association (&req->request.node_id);
  if (n)
    {
      /* 3GPP TS 23.007, Sect. 19A:
       *
       * A PFCP function that receives a PFCP Association Setup Request
       * shall proceed with:
       *
       * - establishing the PFCP association and
       * - deleting the existing PFCP association and associated PFCP sessions,
       *   if a PFCP association was already established for the Node ID
       * received in the request, regardless of the Recovery Timestamp received
       * in the request.
       *
       * A PFCP function shall ignore the Recovery Timestamp received in
       * PFCP Association Setup Response message.
       *
       */
      pfcp_release_association (n);
    }

  n = pfcp_new_association (msg->session_handle, &msg->lcl.address,
                            &msg->rmt.address, &req->request.node_id);
  n->recovery_time_stamp = req->recovery_time_stamp;

  if (ISSET_BIT (req->grp.fields, ASSOCIATION_SETUP_REQUEST_SMF_SET_ID))
    pfcp_node_enter_smf_set (n, req->smf_set_id.fqdn);

  UPF_SET_BIT (resp->grp.fields,
               ASSOCIATION_PROCEDURE_RESPONSE_UP_FUNCTION_FEATURES);
  resp->up_function_features |= PFCP_F_UPFF_EMPU;
  resp->up_function_features |= PFCP_F_UPFF_MPAS;
  if (gtm->pfcp_spec_version >= 16)
    {
      resp->up_function_features |= PFCP_F_UPFF_VTIME;
      resp->up_function_features |= PFCP_F_UPFF_FTUP;
      build_ue_ip_address_information (&resp->ue_ip_address_pool_information);
      if (vec_len (resp->ue_ip_address_pool_information) != 0)
        UPF_SET_BIT (
          resp->grp.fields,
          ASSOCIATION_PROCEDURE_RESPONSE_UE_IP_ADDRESS_POOL_INFORMATION);
      UPF_SET_BIT (resp->grp.fields,
                   ASSOCIATION_PROCEDURE_RESPONSE_BBF_UP_FUNCTION_FEATURES);
      resp->bbf_up_function_features |= PFCP_BBF_UP_NAT;
    }
  else
    {
      build_user_plane_ip_resource_information (
        &resp->user_plane_ip_resource_information);
      if (vec_len (resp->user_plane_ip_resource_information) != 0)
        UPF_SET_BIT (
          resp->grp.fields,
          ASSOCIATION_PROCEDURE_RESPONSE_USER_PLANE_IP_RESOURCE_INFORMATION);
    }
  if (r == 0)
    {
      n->heartbeat_handle = upf_pfcp_server_start_timer (
        PFCP_SERVER_HB_TIMER, n - gtm->nodes, psm->hb_cfg.timeout);

      resp->cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    }

  upf_pfcp_send_response (msg, &resp_dmsg);

  return r;
}

static int
handle_association_setup_response (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_association_update_request (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_association_update_response (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_association_release_request (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_association_release_response (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

#if 0
static int
handle_version_not_supported_response (pfcp_msg_t * msg,
				       pfcp_decoded_msg_t * dmsg)
{
  return -1;
}
#endif

static int
handle_node_report_request (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_node_report_response (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

/* this methods used for cases when incoming message decode is failed */
static void
send_simple_response (pfcp_msg_t *req, u8 type, pfcp_ie_cause_t cause,
                      pfcp_ie_offending_ie_t *err)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_decoded_msg_t resp_dmsg = {
    .type = type,
  };
  pfcp_simple_response_t *resp = &resp_dmsg.simple_response;

  memset (resp, 0, sizeof (*resp));
  UPF_SET_BIT (resp->grp.fields, PFCP_RESPONSE_CAUSE);
  resp->response.cause = cause;

  switch (type)
    {
    case PFCP_MSG_HEARTBEAT_RESPONSE:
    case PFCP_MSG_PFD_MANAGEMENT_RESPONSE:
    case PFCP_MSG_SESSION_MODIFICATION_RESPONSE:
    case PFCP_MSG_SESSION_DELETION_RESPONSE:
    case PFCP_MSG_SESSION_REPORT_RESPONSE:
      break;

    default:
      UPF_SET_BIT (resp->grp.fields, PFCP_RESPONSE_NODE_ID);
      init_response_node_id (&resp->response.node_id);
      break;
    }

  switch (type)
    {
    case PFCP_MSG_HEARTBEAT_RESPONSE:
    case PFCP_MSG_ASSOCIATION_SETUP_RESPONSE:
      UPF_SET_BIT (resp->grp.fields, PFCP_RESPONSE_RECOVERY_TIME_STAMP);
      resp->response.recovery_time_stamp = psm->start_time;
      break;

    default:
      break;
    }

  if (vec_len (err) != 0)
    {
      UPF_SET_BIT (resp->grp.fields, PFCP_RESPONSE_OFFENDING_IE);
      resp->response.offending_ie = err[0];
    }

  upf_pfcp_send_response (req, &resp_dmsg);
}

#define OPT(MSG, FIELD, VALUE, DEFAULT)                                       \
  ((ISSET_BIT ((MSG)->grp.fields, (FIELD))) ? MSG->VALUE : (DEFAULT))

static upf_nwi_t *
lookup_nwi (u8 *name)
{
  upf_main_t *gtm = &upf_main;
  uword *p;

  assert (name);

  if (pool_elts (gtm->nwis) == 0)
    return NULL;

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (!p)
    return NULL;

  return pool_elt_at_index (gtm->nwis, p[0]);
}

static bool
validate_teid (u32 teid)
{
  return ((teid != 0) && (teid != 0xffffffff));
}

static u32
teid_v4_lookup_session_index (upf_main_t *gtm, u32 teid, ip4_address_t *ip4)
{
  clib_bihash_kv_8_8_t kv, value;
  gtpu4_tunnel_key_t key4;

  key4.dst = ip4->as_u32;
  key4.teid = teid;

  kv.key = key4.as_u64;

  if (PREDICT_FALSE (
        clib_bihash_search_8_8 (&gtm->v4_tunnel_by_key, &kv, &value)))
    return ~0;

  /* only lower 32 bits are used here */
  return value.value;
}

static u32
teid_v6_lookup_session_index (upf_main_t *gtm, u32 teid, ip6_address_t *ip6)
{
  clib_bihash_kv_24_8_t kv, value;

  kv.key[0] = ip6->as_u64[0];
  kv.key[1] = ip6->as_u64[1];
  kv.key[2] = teid;

  if (PREDICT_FALSE (
        clib_bihash_search_24_8 (&gtm->v6_tunnel_by_key, &kv, &value)))
    return ~0;

  /* only lower 32 bits are used here */
  return value.value;
}

static u32
process_teid_generation (upf_main_t *gtm, u8 chid, u32 flags,
                         upf_upip_res_t *res, upf_session_t *sx)
{
  u8 retry_cnt = 10;
  u32 teid = 0;
  bool ok = false;
  do
    {
      teid = random_u32 (&gtm->rand_base) & ~res->mask;
      if (!validate_teid (teid))
        {
          retry_cnt--;
          continue;
        }

      gtm->rand_base = teid;

      /* teid_v4/v6_lookup can be called even there is no ip4/ip6 address
         present in a UPIP res. It will always return
         UPF_GTPU_ERROR_NO_SUCH_TUNNEL for such cases
       */
      ok = (!(flags & PFCP_F_TEID_V4) ||
            teid_v4_lookup_session_index (gtm, teid, &res->ip4) == ~0) &&
           (!(flags & PFCP_F_TEID_V6) ||
            teid_v6_lookup_session_index (gtm, teid, &res->ip6) == ~0);

      if (ok)
        break;
    }
  while (retry_cnt > 0);

  if (!ok)
    /* can't generate unique for given UPIP resource */
    return 0;

  if ((flags & PFCP_F_TEID_CHID))
    {
      u32 *n = sparse_vec_validate (sx->teid_by_chid, chid);
      n[0] = teid;
    }

  return teid;
}

static int
handle_f_teid (upf_session_t *sx, upf_main_t *gtm, pfcp_ie_pdi_t *pdi,
               upf_pdr_t *process_pdr, pfcp_ie_created_pdr_t **created_pdr_vec,
               upf_upip_res_t *res, u8 create)
{
  pfcp_ie_created_pdr_t *created_pdr;
  u32 teid = 0;
  u32 sidx = ~0;

  process_pdr->pdi.fields |= F_PDI_LOCAL_F_TEID;

  // We only generate F_TEID if NWI is defined
  if ((pdi->f_teid.flags & PFCP_F_TEID_CH))
    {
      if (!res)
        return -1;

      if ((pdi->f_teid.flags & PFCP_F_TEID_CHID))
        {
          uword i = sparse_vec_index (sx->teid_by_chid, pdi->f_teid.choose_id);
          if (i)
            teid = vec_elt (sx->teid_by_chid, i);
        }

      if (!teid)
        {
          if (!create)
            return -1;

          teid = process_teid_generation (gtm, pdi->f_teid.choose_id,
                                          pdi->f_teid.flags, res, sx);
          if (!teid)
            return -1;
        }

      process_pdr->pdi.teid.teid = teid;

      if ((!is_zero_ip4_address (&res->ip4)) &&
          (pdi->f_teid.flags & PFCP_F_TEID_V4))
        {
          process_pdr->pdi.teid.ip4 = res->ip4;
          process_pdr->pdi.teid.flags |= PFCP_F_TEID_V4;
        }

      if ((!is_zero_ip6_address (&res->ip6)) &&
          (pdi->f_teid.flags & PFCP_F_TEID_V6))
        {
          process_pdr->pdi.teid.flags |= PFCP_F_TEID_V6;
          process_pdr->pdi.teid.ip6 = res->ip6;
        }

      if (create)
        {
          vec_add2 (*created_pdr_vec, created_pdr, 1);
          memset (created_pdr, 0, sizeof (*created_pdr));
          UPF_SET_BIT (created_pdr->grp.fields, CREATED_PDR_PDR_ID);
          UPF_SET_BIT (created_pdr->grp.fields, CREATED_PDR_F_TEID);
          created_pdr->pdr_id = process_pdr->id;
          created_pdr->f_teid = process_pdr->pdi.teid;
        }
    }
  else
    {
      /* CH == 0, check for conflicts with other sessions */

      if (pdi->f_teid.flags & PFCP_F_TEID_V4)
        sidx = teid_v4_lookup_session_index (gtm, pdi->f_teid.teid,
                                             &pdi->f_teid.ip4);
      else if (pdi->f_teid.flags & PFCP_F_TEID_V6)
        sidx = teid_v6_lookup_session_index (gtm, pdi->f_teid.teid,
                                             &pdi->f_teid.ip6);
      if (sidx != ~0 && sidx != sx - gtm->sessions)
        return -1;

      process_pdr->pdi.teid = pdi->f_teid;
    }

  return 0;
}

/*
 * Delete session that conflicts on UE IP if it resides
 * on the same CP node as the new one.
 */
static void
purge_conflicting_session (upf_session_t *sx_old, upf_session_t *sx_new,
                           pfcp_ie_ue_ip_address_t *ue_addr)
{
  if (sx_old->assoc.node != sx_new->assoc.node)
    return;

  clib_warning ("UE IP conflict: deleting session CP SEID=0x%016" PRIx64 " %U "
                "due to attempt to create CP SEID=0x%0x16" PRIx64,
                sx_old->cp_seid, format_pfcp_ie_ue_ip_address, ue_addr,
                sx_new->cp_seid);

  upf_pfcp_session_up_deletion_report (sx_old);

  pfcp_disable_session (sx_old);
  pfcp_free_session (sx_old);
}

static int
resolve_ue_ip_conflicts (upf_session_t *sx, upf_nwi_t *nwi,
                         pfcp_ie_ue_ip_address_t *ue_addr)
{
  upf_main_t *gtm = &upf_main;
  const dpo_id_t *dpo;
  int r = 0;

  if (ue_addr->flags & PFCP_UE_IP_ADDRESS_V4)
    {
      dpo = upf_get_session_dpo_ip4 (nwi, &ue_addr->ip4);
      if (dpo && dpo->dpoi_index != sx - gtm->sessions)
        {
          purge_conflicting_session (gtm->sessions + dpo->dpoi_index, sx,
                                     ue_addr);
          r = -1;
        }
    }

  if (ue_addr->flags & PFCP_UE_IP_ADDRESS_V6)
    {
      dpo = upf_get_session_dpo_ip6 (nwi, &ue_addr->ip6);
      if (dpo && dpo->dpoi_index != sx - gtm->sessions)
        {
          purge_conflicting_session (gtm->sessions + dpo->dpoi_index, sx,
                                     ue_addr);
          r = -1;
        }
    }

  return r;
}

#define pdr_error(r, pdr, fmt, ...)                                           \
  do                                                                          \
    {                                                                         \
      tp_session_error_report ((r), "PDR ID %u, " fmt, (pdr)->pdr_id,         \
                               ##__VA_ARGS__);                                \
      response->failed_rule_id.id = pdr->pdr_id;                              \
    }                                                                         \
  while (0)

upf_nat_addr_t *
get_nat_addr (upf_nat_pool_t *np)
{
  upf_nat_addr_t *this_addr = NULL, *addr = NULL;
  u32 least_locked_ports = ~0;

  vec_foreach (this_addr, np->addresses)
    {
      if ((this_addr->used_blocks < least_locked_ports) &&
          (this_addr->used_blocks < np->max_blocks_per_addr))
        {
          least_locked_ports = this_addr->used_blocks;
          addr = this_addr;
        }
    }
  return addr;
}

int
upf_alloc_and_assign_nat_binding (
  upf_nat_pool_t *np, upf_nat_addr_t *addr, ip4_address_t user_ip,
  upf_session_t *sx, pfcp_ie_tp_created_binding_t *created_binding)
{
  u16 port_start, port_end;
  u16 (*upf_nat_create_binding) (ip4_address_t user_addr,
                                 ip4_address_t ext_addr, u16 min_port,
                                 u16 block_size);

  upf_nat_create_binding =
    vlib_get_plugin_symbol ("nat_plugin.so", "nat_ed_create_binding");

  port_start = upf_nat_create_binding (user_ip, addr->ext_addr, np->min_port,
                                       np->port_block_size);
  if (port_start)
    {
      port_end = port_start + np->port_block_size - 1;
      addr->used_blocks += 1;
      sx->nat_addr = addr;
      created_binding->block = vec_dup (np->name);
      created_binding->outside_addr.as_u32 = addr->ext_addr.as_u32;
      created_binding->port_range.start_port = port_start;
      created_binding->port_range.end_port = port_end;
      UPF_SET_BIT (created_binding->grp.fields,
                   TP_CREATED_BINDING_NAT_PORT_BLOCK);
      UPF_SET_BIT (created_binding->grp.fields,
                   TP_CREATED_BINDING_NAT_OUTSIDE_ADDRESS);
      UPF_SET_BIT (created_binding->grp.fields,
                   TP_CREATED_BINDING_NAT_EXTERNAL_PORT_RANGE);
      return 0;
    }

  return 1;
}

static int
handle_create_pdr (upf_session_t *sx, pfcp_ie_create_pdr_t *create_pdr,
                   pfcp_msg_session_procedure_response_t *response)
{
  upf_main_t *gtm = &upf_main;
  pfcp_ie_create_pdr_t *pdr;
  struct rules *rules;

  if (pfcp_make_pending_pdr (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  rules = pfcp_get_rules (sx, PFCP_PENDING);
  vec_alloc (rules->pdr, vec_len (create_pdr));

  vec_foreach (pdr, create_pdr)
    {
      upf_upip_res_t *res, *ip_res = NULL;
      upf_pdr_t *create;
      upf_nwi_t *nwi = NULL;

      vec_add2 (rules->pdr, create, 1);
      memset (create, 0, sizeof (*create));

      create->pdi.nwi_index = ~0;
      create->pdi.adr.application_id = ~0;
      create->pdi.adr.db_id = ~0;

      create->id = pdr->pdr_id;
      create->precedence = pdr->precedence;

      if (ISSET_BIT (pdr->pdi.grp.fields, PDI_NETWORK_INSTANCE))
        {
          nwi = lookup_nwi (pdr->pdi.network_instance);
          if (!nwi)
            {
              pdr_error (response, pdr, "unknown Network Instance");
              goto out_error;
            }

          create->pdi.nwi_index = nwi - gtm->nwis;
        }

      pool_foreach (ip_res, gtm->upip_res)
        {
          if (ip_res->nwi_index == create->pdi.nwi_index)
            {
              res = ip_res;
              break;
            }
        }

      create->pdi.src_intf = pdr->pdi.source_interface;

      if (ISSET_BIT (pdr->pdi.grp.fields, PDI_F_TEID))
        {
          if (handle_f_teid (sx, gtm, &pdr->pdi, create,
                             &response->created_pdr, res, 1) != 0)
            {
              pdr_error (response, pdr, "can't handle F-TEID");
              goto out_error;
            }
          /* TODO validate TEID and mask
             if (nwi->teid != (pdr->pdi.f_teid.teid & nwi->mask))
             {
             upf_debug("PDR: %d, TEID not within configure partition\n",
             pdr->pdr_id); failed_rule_id->id = pdr->pdr_id; r = -1; vec_pop
             (rules->pdr); break;
             }
           */
        }

      if (ISSET_BIT (pdr->pdi.grp.fields, PDI_UE_IP_ADDRESS))
        {
          create->pdi.fields |= F_PDI_UE_IP_ADDR;
          create->pdi.ue_addr = pdr->pdi.ue_ip_address;
          if (create->pdi.ue_addr.flags & PFCP_UE_IP_ADDRESS_V4)
            sx->user_addr.as_u32 = create->pdi.ue_addr.ip4.as_u32;

          if (!ISSET_BIT (pdr->pdi.grp.fields, PDI_SDF_FILTER) &&
              !ISSET_BIT (pdr->pdi.grp.fields, PDI_APPLICATION_ID))
            {
              /* neither SDF, nor Application Id, generate a wildcard
                 ACL to make ACL scanning simpler */
              create->pdi.fields |= F_PDI_SDF_FILTER;
              vec_add1 (create->pdi.acl, wildcard_acl);
            }
        }

      if (ISSET_BIT (pdr->pdi.grp.fields, PDI_SDF_FILTER))
        {
          pfcp_ie_sdf_filter_t *sdf;

          create->pdi.fields |= F_PDI_SDF_FILTER;

          vec_alloc (create->pdi.acl, _vec_len (pdr->pdi.sdf_filter));

          vec_foreach (sdf, pdr->pdi.sdf_filter)
            {
              unformat_input_t input;
              acl_rule_t *acl;

              unformat_init_string (&input, (char *) sdf->flow,
                                    vec_len (sdf->flow));
              vec_add2 (create->pdi.acl, acl, 1);

              if (!unformat (&input, "%U", unformat_ipfilter, acl))
                {
                  unformat_free (&input);

                  pdr_error (response, pdr, "failed to parse SDF");
                  goto out_error;
                }

              unformat_free (&input);
            }
        }

      if (ISSET_BIT (pdr->pdi.grp.fields, PDI_APPLICATION_ID))
        {
          upf_adf_app_t *app;
          uword *p = NULL;

          create->pdi.fields |= F_PDI_APPLICATION_ID;

          p = hash_get_mem (gtm->upf_app_by_name, pdr->pdi.application_id);
          if (!p)
            {
              pdr_error (response, pdr, "unknown Application ID");
              goto out_error;
            }

          ASSERT (!pool_is_free_index (gtm->upf_apps, p[0]));
          app = pool_elt_at_index (gtm->upf_apps, p[0]);
          create->pdi.adr.application_id = p[0];
          create->pdi.adr.db_id = upf_adf_get_adr_db (p[0]);
          create->pdi.adr.flags = app->flags;

          if (!ISSET_BIT (pdr->pdi.grp.fields, PDI_SDF_FILTER) &&
              (create->pdi.adr.flags & UPF_ADR_IP_RULES))
            {
              create->pdi.fields |= F_PDI_SDF_FILTER;
              vec_add1 (create->pdi.acl, wildcard_acl);
            }
          upf_debug ("app: %v, ADR DB id %u", app->name,
                     create->pdi.adr.db_id);
        }

      create->outer_header_removal =
        OPT (pdr, CREATE_PDR_OUTER_HEADER_REMOVAL, outer_header_removal, ~0);
      create->far_id = OPT (pdr, CREATE_PDR_FAR_ID, far_id, ~0);
      if (ISSET_BIT (pdr->grp.fields, CREATE_PDR_URR_ID))
        {
          pfcp_ie_urr_id_t *urr_id;

          vec_alloc (create->urr_ids, _vec_len (pdr->urr_id));
          vec_foreach (urr_id, pdr->urr_id)
            {
              vec_add1 (create->urr_ids, *urr_id);
            }
        }

      if (ISSET_BIT (pdr->grp.fields, CREATE_PDR_QER_ID))
        {
          pfcp_ie_qer_id_t *qer_id;

          vec_alloc (create->qer_ids, _vec_len (pdr->qer_id));
          vec_foreach (qer_id, pdr->qer_id)
            {
              vec_add1 (create->qer_ids, *qer_id);
            }
        }

      if ((create->pdi.fields & F_PDI_UE_IP_ADDR) && nwi &&
          resolve_ue_ip_conflicts (sx, nwi, &create->pdi.ue_addr) != 0)
        {
          pdr_error (response, pdr, "duplicate UE IP");
          goto out_error;
        }

      // CREATE_PDR_ACTIVATE_PREDEFINED_RULES
    }

  pfcp_sort_pdrs (rules);
  return 0;

out_error:
  response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
  response->failed_rule_id.type = PFCP_FAILED_RULE_TYPE_PDR;

  return -1;
}

static int
handle_update_pdr (upf_session_t *sx, pfcp_ie_update_pdr_t *update_pdr,
                   pfcp_msg_session_procedure_response_t *response)
{
  upf_main_t *gtm = &upf_main;
  pfcp_ie_update_pdr_t *pdr;

  if (pfcp_make_pending_pdr (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  vec_foreach (pdr, update_pdr)
    {
      upf_pdr_t *update;
      upf_upip_res_t *res, *ip_res = NULL;
      upf_nwi_t *nwi = NULL;

      update = pfcp_get_pdr (sx, PFCP_PENDING, pdr->pdr_id);
      if (!update)
        {
          pdr_error (response, pdr, "not found");
          goto out_error;
        }

      if (ISSET_BIT (pdr->pdi.grp.fields, PDI_NETWORK_INSTANCE))
        {
          if (vec_len (pdr->pdi.network_instance) != 0)
            {
              nwi = lookup_nwi (pdr->pdi.network_instance);
              if (!nwi)
                {
                  pdr_error (response, pdr, "unknown Network Instance");
                  goto out_error;
                }
              update->pdi.nwi_index = nwi - gtm->nwis;
            }
          else
            update->pdi.nwi_index = ~0;
        }

      update->precedence = pdr->precedence;
      update->pdi.src_intf = pdr->pdi.source_interface;

      pool_foreach (ip_res, gtm->upip_res)
        {
          if (ip_res->nwi_index == update->pdi.nwi_index)
            {
              res = ip_res;
              break;
            }
        }

      if (ISSET_BIT (pdr->pdi.grp.fields, PDI_F_TEID))
        {
          if (handle_f_teid (sx, gtm, &pdr->pdi, update, NULL, res, 0) != 0)
            {
              pdr_error (response, pdr, "can't handle F-TEID");
              goto out_error;
            }
        }

      if (ISSET_BIT (pdr->pdi.grp.fields, PDI_UE_IP_ADDRESS))
        {
          update->pdi.fields |= F_PDI_UE_IP_ADDR;
          update->pdi.ue_addr = pdr->pdi.ue_ip_address;

          if (!ISSET_BIT (pdr->pdi.grp.fields, PDI_SDF_FILTER) &&
              !ISSET_BIT (pdr->pdi.grp.fields, PDI_APPLICATION_ID))
            {
              /* neither SDF, nor Application Id, generate a wildcard
                 ACL to make ACL scanning simpler */
              update->pdi.fields |= F_PDI_SDF_FILTER;
              vec_reset_length (update->pdi.acl);
              vec_add1 (update->pdi.acl, wildcard_acl);
            }
        }

      if (ISSET_BIT (pdr->pdi.grp.fields, PDI_SDF_FILTER))
        {
          pfcp_ie_sdf_filter_t *sdf;

          update->pdi.fields |= F_PDI_SDF_FILTER;

          vec_reset_length (update->pdi.acl);
          vec_alloc (update->pdi.acl, _vec_len (pdr->pdi.sdf_filter));

          vec_foreach (sdf, pdr->pdi.sdf_filter)
            {
              unformat_input_t input;
              acl_rule_t *acl;

              unformat_init_string (&input, (char *) sdf->flow,
                                    vec_len (sdf->flow));
              vec_add2 (update->pdi.acl, acl, 1);

              if (!unformat (&input, "%U", unformat_ipfilter, acl))
                {
                  unformat_free (&input);

                  pdr_error (response, pdr, "failed to parse SDF");
                  goto out_error;
                }

              unformat_free (&input);
            }
        }

      if (ISSET_BIT (pdr->pdi.grp.fields, PDI_APPLICATION_ID))
        {
          upf_adf_app_t *app;
          uword *p = NULL;

          update->pdi.fields |= F_PDI_APPLICATION_ID;

          p = hash_get_mem (gtm->upf_app_by_name, pdr->pdi.application_id);
          if (!p)
            {
              pdr_error (response, pdr, "unknown Application ID");
              goto out_error;
            }

          ASSERT (!pool_is_free_index (gtm->upf_apps, p[0]));
          app = pool_elt_at_index (gtm->upf_apps, p[0]);
          update->pdi.adr.application_id = p[0];
          update->pdi.adr.db_id = upf_adf_get_adr_db (p[0]);
          update->pdi.adr.flags = app->flags;

          if (!ISSET_BIT (pdr->pdi.grp.fields, PDI_SDF_FILTER))
            {
              vec_reset_length (update->pdi.acl);
              if (update->pdi.adr.flags & UPF_ADR_IP_RULES)
                {
                  update->pdi.fields |= F_PDI_SDF_FILTER;
                  vec_add1 (update->pdi.acl, wildcard_acl);
                }
            }

          upf_debug ("app: %v, ADR DB id %u", app->name,
                     update->pdi.adr.db_id);
        }

      update->outer_header_removal =
        OPT (pdr, UPDATE_PDR_OUTER_HEADER_REMOVAL, outer_header_removal, ~0);
      update->far_id = OPT (pdr, UPDATE_PDR_FAR_ID, far_id, ~0);
      if (ISSET_BIT (pdr->grp.fields, UPDATE_PDR_URR_ID))
        {
          pfcp_ie_urr_id_t *urr_id;

          vec_reset_length (update->urr_ids);
          vec_alloc (update->urr_ids, _vec_len (pdr->urr_id));
          vec_foreach (urr_id, pdr->urr_id)
            {
              vec_add1 (update->urr_ids, *urr_id);
            }
        }

      if (ISSET_BIT (pdr->grp.fields, UPDATE_PDR_QER_ID))
        {
          pfcp_ie_qer_id_t *qer_id;

          vec_reset_length (update->qer_ids);
          vec_alloc (update->qer_ids, _vec_len (pdr->qer_id));
          vec_foreach (qer_id, pdr->qer_id)
            {
              vec_add1 (update->qer_ids, *qer_id);
            }
        }

      if ((update->pdi.fields & F_PDI_UE_IP_ADDR) && nwi &&
          resolve_ue_ip_conflicts (sx, nwi, &update->pdi.ue_addr) != 0)
        {
          pdr_error (response, pdr, "duplicate UE IP");
          goto out_error;
        }

      // UPDATE_PDR_ACTIVATE_PREDEFINED_RULES
    }

  return 0;

out_error:
  response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
  response->failed_rule_id.type = PFCP_FAILED_RULE_TYPE_PDR;

  return -1;
}

static int
handle_remove_pdr (upf_session_t *sx, pfcp_ie_remove_pdr_t *remove_pdr,
                   pfcp_msg_session_procedure_response_t *response)
{
  pfcp_ie_remove_pdr_t *pdr;

  if (pfcp_make_pending_pdr (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  vec_foreach (pdr, remove_pdr)
    {
      if (pfcp_delete_pdr (sx, pdr->pdr_id) != 0)
        {
          pdr_error (response, pdr, "unable to remove");
          goto out_error;
        }
    }

  return 0;

out_error:
  response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
  response->failed_rule_id.type = PFCP_FAILED_RULE_TYPE_PDR;

  return -1;
}

#undef pdr_error

/* find source IP based on outgoing route and UpIP */
static void *
upip_ip_interface_ip (upf_far_forward_t *ff, u32 fib_index, int is_ip4)
{
  ip_lookup_main_t *lm =
    is_ip4 ? &ip4_main.lookup_main : &ip6_main.lookup_main;
  upf_main_t *gtm = &upf_main;
  ip_interface_address_t *a;
  upf_upip_res_t *res;

  pool_foreach (res, gtm->upip_res)
    {
      uword *p;

      if (is_ip4 && is_zero_ip4_address (&res->ip4))
        continue;
      if (!is_ip4 && is_zero_ip6_address (&res->ip6))
        continue;

      if (INTF_INVALID != res->intf && ff->dst_intf != res->intf)
        continue;

      if (~0 != res->nwi_index && ~0 != ff->nwi_index &&
          ff->nwi_index != res->nwi_index)
        continue;

      if (is_ip4)
        {
          ip4_address_fib_t ip4_af;

          ip4_addr_fib_init (&ip4_af, &res->ip4, fib_index);
          p = mhash_get (&lm->address_to_if_address_index, &ip4_af);
        }
      else
        {
          ip6_address_fib_t ip6_af;

          ip6_addr_fib_init (&ip6_af, &res->ip6, fib_index);
          p = mhash_get (&lm->address_to_if_address_index, &ip6_af);
        }
      if (!p)
        continue;

      a = pool_elt_at_index (lm->if_address_pool, p[0]);
      if (a->sw_if_index == ff->dst_sw_if_index)
        return (is_ip4) ? (void *) &res->ip4 : (void *) &res->ip6;
    }

  clib_warning ("No NWI IP found, using first interface IP");
  return ip_interface_get_first_ip (ff->dst_sw_if_index, is_ip4);
}

static void
ip_udp_gtpu_rewrite (upf_far_forward_t *ff, u32 fib_index, int is_ip4)
{
  union
  {
    ip4_gtpu_header_t *h4;
    ip6_gtpu_header_t *h6;
    u8 *rw;
  } r = { .rw = 0 };
  int len = is_ip4 ? sizeof *r.h4 : sizeof *r.h6;

  vec_validate_aligned (r.rw, len - 1, CLIB_CACHE_LINE_BYTES);

  udp_header_t *udp;
  gtpu_header_t *gtpu;
  /* Fixed portion of the (outer) ip header */
  if (is_ip4)
    {
      ip4_header_t *ip = &r.h4->ip4;
      udp = &r.h4->udp;
      gtpu = &r.h4->gtpu;
      ip->ip_version_and_header_length = 0x45;
      ip->ttl = 254;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address =
        *(ip4_address_t *) upip_ip_interface_ip (ff, fib_index, 1);
      ip->dst_address = ff->outer_header_creation.ip.ip4;

      /* we fix up the ip4 header length and checksum after-the-fact */
      ip->checksum = ip4_header_checksum (ip);
    }
  else
    {
      ip6_header_t *ip = &r.h6->ip6;
      udp = &r.h6->udp;
      gtpu = &r.h6->gtpu;
      ip->ip_version_traffic_class_and_flow_label =
        clib_host_to_net_u32 (6 << 28);
      ip->hop_limit = 255;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address =
        *(ip6_address_t *) upip_ip_interface_ip (ff, fib_index, 0);
      ip->dst_address = ff->outer_header_creation.ip.ip6;
    }

  /* UDP header, randomize src port on something, maybe? */
  udp->src_port = clib_host_to_net_u16 (2152);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_GTPU);

  /* GTPU header */
  gtpu->ver_flags = GTPU_V1_VER | GTPU_PT_GTP;
  gtpu->type = GTPU_TYPE_GTPU;
  gtpu->teid = clib_host_to_net_u32 (ff->outer_header_creation.teid);

  ff->rewrite = r.rw;

  /* For now only support 8-byte gtpu header. TBD */
  _vec_find (ff->rewrite)->len = len - 4;

  return;
}

#define far_error(r, far, fmt, ...)                                           \
  do                                                                          \
    {                                                                         \
      tp_session_error_report ((r), "FAR ID %u, " fmt, (far)->far_id,         \
                               ##__VA_ARGS__);                                \
      response->failed_rule_id.id = far->far_id;                              \
    }                                                                         \
  while (0)

static int
handle_nat_binding_creation (upf_session_t *sx, u8 *nat_pool_name,
                             pfcp_msg_session_procedure_response_t *response)
{
  upf_nat_pool_t *np;
  upf_nat_addr_t *ap;
  int rc = 0;

  /* We already created NAT Binding for a session using different FAR */
  if (sx->nat_addr)
    return 0;

  if (!sx->user_addr.as_u32)
    return -1;

  np = get_nat_pool_by_name (nat_pool_name);

  if (!np)
    return -1;

  ap = get_nat_addr (np);
  if (!ap)
    return -1;

  rc = upf_alloc_and_assign_nat_binding (np, ap, sx->user_addr, sx,
                                         &response->created_binding);
  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_TP_CREATED_BINDING);

  return rc;
}

static int
handle_create_far (upf_session_t *sx, pfcp_ie_create_far_t *create_far,
                   pfcp_msg_session_procedure_response_t *response)
{
  upf_main_t *gtm = &upf_main;
  pfcp_ie_create_far_t *far;
  struct rules *rules;
  u8 *policy_id = NULL;
  uword *hash_ptr;
  upf_forwarding_policy_t *fp_entry;

  if (pfcp_make_pending_far (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  rules = pfcp_get_rules (sx, PFCP_PENDING);
  vec_alloc (rules->far, vec_len (create_far));

  vec_foreach (far, create_far)
    {
      upf_far_t *create;
      upf_nwi_t *nwi;

      vec_add2 (rules->far, create, 1);
      memset (create, 0, sizeof (*create));
      create->forward.nwi_index = ~0;
      create->forward.dst_sw_if_index = ~0;

      create->id = far->far_id;
      create->apply_action = far->apply_action;

      if ((create->apply_action & FAR_FORWARD) &&
          ISSET_BIT (far->grp.fields, CREATE_FAR_FORWARDING_PARAMETERS))
        {

          if (ISSET_BIT (far->forwarding_parameters.grp.fields,
                         FORWARDING_PARAMETERS_NETWORK_INSTANCE))
            {
              nwi = lookup_nwi (far->forwarding_parameters.network_instance);
              if (!nwi)
                {
                  far_error (response, far, "unknown Network Instance");
                  goto out_error;
                }

              create->forward.nwi_index = nwi - gtm->nwis;
            }

          create->forward.dst_intf =
            far->forwarding_parameters.destination_interface;

          if (ISSET_BIT (far->forwarding_parameters.grp.fields,
                         FORWARDING_PARAMETERS_REDIRECT_INFORMATION))
            {
              create->forward.flags |= FAR_F_REDIRECT_INFORMATION;
              copy_pfcp_ie_redirect_information (
                &create->forward.redirect_information,
                &far->forwarding_parameters.redirect_information);
            }

          if ((ISSET_BIT (far->forwarding_parameters.grp.fields,
                          FORWARDING_PARAMETERS_BBF_APPLY_ACTION)) &&
              (far->forwarding_parameters.bbf_apply_action &
               PFCP_BBF_APPLY_ACTION_NAT) &&
              (ISSET_BIT (far->forwarding_parameters.grp.fields,
                          FORWARDING_PARAMETERS_BBF_NAT_PORT_BLOCK)))
            {
              int rc = 0;
              pfcp_ie_bbf_nat_port_block_t pool_name =
                vec_dup (far->forwarding_parameters.nat_port_block);
              rc = handle_nat_binding_creation (sx, pool_name, response);
              vec_free (pool_name);
              create->apply_action |= FAR_NAT;
              if (rc)
                {
                  far_error (response, far,
                             "Error creating NAT binding for pool '%v'",
                             far->forwarding_parameters.nat_port_block);
                  goto out_error;
                }
            }

          if (ISSET_BIT (far->forwarding_parameters.grp.fields,
                         FORWARDING_PARAMETERS_OUTER_HEADER_CREATION))
            {
              pfcp_ie_outer_header_creation_t *ohc =
                &far->forwarding_parameters.outer_header_creation;
              u32 fib_index;
              int is_ip4 =
                !!(ohc->description & PFCP_OUTER_HEADER_CREATION_ANY_IP4);
              fib_protocol_t fproto =
                is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;

              create->forward.flags |= FAR_F_OUTER_HEADER_CREATION;
              create->forward.outer_header_creation =
                far->forwarding_parameters.outer_header_creation;

              fib_index =
                upf_nwi_fib_index (fproto, create->forward.nwi_index);
              if (~0 == fib_index)
                {
                  far_error (
                    response, far,
                    "Network Instance with invalid FIB index for IPv%d",
                    is_ip4 ? 4 : 6);
                  goto out_error;
                }
              create->forward.dst_sw_if_index =
                upf_ip46_get_resolving_interface (fib_index, &ohc->ip, is_ip4);
              if (~0 == create->forward.dst_sw_if_index)
                {
                  far_error (response, far, "no route to %U in table %u",
                             format_ip46_address, &ohc->ip, IP46_TYPE_ANY,
                             fib_table_get_table_id (fib_index, fproto));
                  goto out_error;
                }

              ip_udp_gtpu_rewrite (&create->forward, fib_index, is_ip4);
            }
          // TODO: transport_level_marking
          /* forwarding_policy >> oln: Implementation */

          if (ISSET_BIT (far->forwarding_parameters.grp.fields,
                         FORWARDING_PARAMETERS_FORWARDING_POLICY))
            {
              policy_id =
                far->forwarding_parameters.forwarding_policy.identifier;
              hash_ptr =
                hash_get_mem (gtm->forwarding_policy_by_id, policy_id);
              if (hash_ptr)
                {
                  create->forward.flags |= FAR_F_FORWARDING_POLICY;
                  create->forward.forwarding_policy.identifier = vec_dup (
                    far->forwarding_parameters.forwarding_policy.identifier);
                  fp_entry = pool_elt_at_index (gtm->upf_forwarding_policies,
                                                hash_ptr[0]);
                  create->forward.fp_pool_index = hash_ptr[0];
                }
              else
                {
                  far_error (
                    response, far, "forwarding policy '%v' not configured",
                    far->forwarding_parameters.forwarding_policy.identifier);
                  response->cause = PFCP_CAUSE_INVALID_FORWARDING_POLICY;
                  goto out_cause_set;
                }
            } // TODO: header_enrichment
        }

      if (ISSET_BIT (far->grp.fields, CREATE_FAR_TP_IPFIX_POLICY))
        create->ipfix_policy = upf_ipfix_lookup_policy (far->ipfix_policy, 0);
      else
        create->ipfix_policy = UPF_IPFIX_POLICY_UNSPECIFIED;
    }

  pfcp_sort_fars (rules);
  return 0;

out_error:
  response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

out_cause_set:
  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
  response->failed_rule_id.type = PFCP_FAILED_RULE_TYPE_FAR;

  return -1;
}

static int
handle_update_far (upf_session_t *sx, pfcp_ie_update_far_t *update_far,
                   pfcp_msg_session_procedure_response_t *response)
{
  upf_main_t *gtm = &upf_main;
  pfcp_ie_update_far_t *far;
  u8 *policy_id = NULL;
  uword *hash_ptr;
  upf_forwarding_policy_t *fp_entry;

  if (pfcp_make_pending_far (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  vec_foreach (far, update_far)
    {
      upf_far_t *update;
      upf_nwi_t *nwi;

      update = pfcp_get_far (sx, PFCP_PENDING, far->far_id);
      if (!update)
        {
          far_error (response, far, "not found");
          goto out_error;
        }

      update->apply_action =
        OPT (far, UPDATE_FAR_APPLY_ACTION, apply_action, update->apply_action);

      if ((update->apply_action & FAR_FORWARD) &&
          ISSET_BIT (far->grp.fields, UPDATE_FAR_UPDATE_FORWARDING_PARAMETERS))
        {
          if (ISSET_BIT (far->update_forwarding_parameters.grp.fields,
                         UPDATE_FORWARDING_PARAMETERS_NETWORK_INSTANCE))
            {
              if (vec_len (
                    far->update_forwarding_parameters.network_instance) != 0)
                {
                  nwi = lookup_nwi (
                    far->update_forwarding_parameters.network_instance);
                  if (!nwi)
                    {
                      far_error (response, far, "unknown Network Instance");
                      goto out_error;
                    }
                  update->forward.nwi_index = nwi - gtm->nwis;
                }
              else
                {
                  update->forward.nwi_index = ~0;
                }
            }

          update->forward.dst_intf =
            far->update_forwarding_parameters.destination_interface;

          if (ISSET_BIT (far->update_forwarding_parameters.grp.fields,
                         UPDATE_FORWARDING_PARAMETERS_REDIRECT_INFORMATION))
            {
              update->forward.flags |= FAR_F_REDIRECT_INFORMATION;
              free_pfcp_ie_redirect_information (
                &update->forward.redirect_information);
              copy_pfcp_ie_redirect_information (
                &update->forward.redirect_information,
                &far->update_forwarding_parameters.redirect_information);
            }

          if (ISSET_BIT (far->update_forwarding_parameters.grp.fields,
                         UPDATE_FORWARDING_PARAMETERS_OUTER_HEADER_CREATION))
            {
              pfcp_ie_outer_header_creation_t *ohc =
                &far->update_forwarding_parameters.outer_header_creation;
              u32 fib_index;
              int is_ip4 =
                !!(ohc->description & PFCP_OUTER_HEADER_CREATION_ANY_IP4);
              fib_protocol_t fproto =
                is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;

              if (ISSET_BIT (far->update_forwarding_parameters.grp.fields,
                             UPDATE_FORWARDING_PARAMETERS_PFCPSMREQ_FLAGS) &&
                  far->update_forwarding_parameters.pfcpsmreq_flags &
                    PFCP_PFCPSMREQ_SNDEM)
                pfcp_send_end_marker (sx, far->far_id);

              update->forward.flags |= FAR_F_OUTER_HEADER_CREATION;
              update->forward.outer_header_creation = *ohc;

              fib_index =
                upf_nwi_fib_index (fproto, update->forward.nwi_index);
              if (~0 == fib_index)
                {
                  far_error (
                    response, far,
                    "Network Instance with invalid FIB index for IPv%d",
                    is_ip4 ? 4 : 6);
                  goto out_error;
                }

              update->forward.dst_sw_if_index =
                upf_ip46_get_resolving_interface (fib_index, &ohc->ip, is_ip4);
              if (~0 == update->forward.dst_sw_if_index)
                {
                  far_error (response, far, "no route to %U in table %u",
                             format_ip46_address, &ohc->ip, IP46_TYPE_ANY,
                             fib_table_get_table_id (fib_index, fproto));
                  goto out_error;
                }

              ip_udp_gtpu_rewrite (&update->forward, fib_index, is_ip4);
            }
          // TODO: transport_level_marking
          /*forwarding_policy  >> oln: Implementation */
          if (ISSET_BIT (far->update_forwarding_parameters.grp.fields,
                         UPDATE_FORWARDING_PARAMETERS_FORWARDING_POLICY))
            {
              policy_id =
                far->update_forwarding_parameters.forwarding_policy.identifier;
              hash_ptr =
                hash_get_mem (gtm->forwarding_policy_by_id, policy_id);
              if (hash_ptr)
                {
                  fp_entry = pool_elt_at_index (gtm->upf_forwarding_policies,
                                                hash_ptr[0]);
                  update->forward.flags |= FAR_F_FORWARDING_POLICY;
                  update->forward.forwarding_policy.identifier =
                    vec_dup (far->update_forwarding_parameters
                               .forwarding_policy.identifier);
                  update->forward.fp_pool_index = hash_ptr[0];
                }
              else
                {
                  far_error (response, far,
                             "forwarding policy '%v' not configured",
                             far->update_forwarding_parameters
                               .forwarding_policy.identifier);
                  response->cause = PFCP_CAUSE_INVALID_FORWARDING_POLICY;
                  goto out_cause_set;
                }
            }
          // TODO: header_enrichment
        }

      if (ISSET_BIT (far->grp.fields, UPDATE_FAR_TP_IPFIX_POLICY))
        update->ipfix_policy = upf_ipfix_lookup_policy (far->ipfix_policy, 0);
      else
        update->ipfix_policy = UPF_IPFIX_POLICY_UNSPECIFIED;
    }

  return 0;

out_error:
  response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

out_cause_set:
  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
  response->failed_rule_id.type = PFCP_FAILED_RULE_TYPE_FAR;

  return -1;
}

static int
handle_remove_far (upf_session_t *sx, pfcp_ie_remove_far_t *remove_far,
                   pfcp_msg_session_procedure_response_t *response)
{
  pfcp_ie_remove_far_t *far;

  if (pfcp_make_pending_far (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  vec_foreach (far, remove_far)
    {
      if (pfcp_delete_far (sx, far->far_id) != 0)
        {
          far_error (response, far, "unable to remove");
          goto out_error;
        }
    }

  return 0;

out_error:
  response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
  response->failed_rule_id.type = PFCP_FAILED_RULE_TYPE_FAR;

  return -1;
}

#undef far_error

#define urr_error(r, urr, fmt, ...)                                           \
  do                                                                          \
    {                                                                         \
      tp_session_error_report ((r), "URR ID %u, " fmt, (urr)->urr_id,         \
                               ##__VA_ARGS__);                                \
      response->failed_rule_id.id = urr->urr_id;                              \
    }                                                                         \
  while (0)

static int
handle_create_urr (upf_session_t *sx, pfcp_ie_create_urr_t *create_urr,
                   f64 now, pfcp_msg_session_procedure_response_t *response)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_ie_create_urr_t *urr;
  struct rules *rules;

  if (pfcp_make_pending_urr (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  rules = pfcp_get_rules (sx, PFCP_PENDING);
  vec_alloc (rules->urr, vec_len (create_urr));

  vec_foreach (urr, create_urr)
    {
      upf_urr_t *create;

      vec_add2 (rules->urr, create, 1);
      memset (create, 0, sizeof (*create));

      create->measurement_period.handle = create->time_threshold.handle =
        create->time_quota.handle = create->quota_validity_time.handle =
          create->traffic_timer.handle = ~0;
      create->monitoring_time.vlib_time = INFINITY;
      create->time_of_first_packet = INFINITY;
      create->time_of_last_packet = INFINITY;
      create->traffic_timer.period = TRAFFIC_TIMER_PERIOD;
      create->traffic_timer.base = now;

      create->id = urr->urr_id;
      create->methods = urr->measurement_method;
      create->triggers =
        OPT (urr, CREATE_URR_REPORTING_TRIGGERS, reporting_triggers, 0);
      create->start_time = now;

      if (ISSET_BIT (urr->grp.fields, CREATE_URR_MEASUREMENT_PERIOD))
        {
          create->update_flags |= PFCP_URR_UPDATE_MEASUREMENT_PERIOD;
          create->measurement_period.period = urr->measurement_period;
          create->measurement_period.base = now;
        }

      if (ISSET_BIT (urr->grp.fields, CREATE_URR_VOLUME_THRESHOLD))
        {
          create->volume.threshold.ul = urr->volume_threshold.ul;
          create->volume.threshold.dl = urr->volume_threshold.dl;
          create->volume.threshold.total = urr->volume_threshold.total;
        }

      if (ISSET_BIT (urr->grp.fields, CREATE_URR_VOLUME_QUOTA))
        {
          create->volume.quota.ul = urr->volume_quota.ul;
          create->volume.quota.dl = urr->volume_quota.dl;
          create->volume.quota.total = urr->volume_quota.total;
        }

      if (ISSET_BIT (urr->grp.fields, CREATE_URR_TIME_THRESHOLD))
        {
          create->update_flags |= PFCP_URR_UPDATE_TIME_THRESHOLD;
          create->time_threshold.period = urr->time_threshold;
          create->time_threshold.base = now;
        }
      if (ISSET_BIT (urr->grp.fields, CREATE_URR_TIME_QUOTA))
        {
          create->update_flags |= PFCP_URR_UPDATE_TIME_QUOTA;
          create->time_quota.period = urr->time_quota;
          create->time_quota.base = now;
        }

      // TODO: quota_holding_time;
      // TODO: dropped_dl_traffic_threshold;

      if (ISSET_BIT (urr->grp.fields, CREATE_URR_QUOTA_VALIDITY_TIME))
        {
          create->update_flags |= PFCP_URR_UPDATE_QUOTA_VALIDITY_TIME;
          create->quota_validity_time.period = urr->quota_validity_time;
          create->quota_validity_time.base = now;
        }
      if (ISSET_BIT (urr->grp.fields, CREATE_URR_MONITORING_TIME))
        {
          f64 secs;

          create->update_flags |= PFCP_URR_UPDATE_MONITORING_TIME;
          create->monitoring_time.unix_time =
            urr->monitoring_time + modf (sx->unix_time_start, &secs);
          create->monitoring_time.vlib_time =
            vlib_time_now (psm->vlib_main) +
            (create->monitoring_time.unix_time - now);
        }

      // TODO: subsequent_volume_threshold;
      // TODO: subsequent_time_threshold;
      // TODO: inactivity_detection_time;

      if (ISSET_BIT (urr->grp.fields, CREATE_URR_LINKED_URR_ID) &&
          create->triggers & PFCP_REPORTING_TRIGGER_LINKED_USAGE_REPORTING)
        create->linked_urr_ids = vec_dup (urr->linked_urr_id);

      // TODO: linked_urr_id;
      // TODO: measurement_information;
      // TODO: time_quota_mechanism;
    }

  pfcp_sort_urrs (rules);
  return 0;
}

static int
handle_update_urr (upf_session_t *sx, pfcp_ie_update_urr_t *update_urr,
                   f64 now, pfcp_msg_session_procedure_response_t *response)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_ie_update_urr_t *urr;

  if (pfcp_make_pending_urr (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  vec_foreach (urr, update_urr)
    {
      upf_urr_t *update;

      update = pfcp_get_urr (sx, PFCP_PENDING, urr->urr_id);
      if (!update)
        {
          urr_error (response, urr, "not found");
          goto out_error;
        }

      update->methods = urr->measurement_method;
      update->triggers = OPT (urr, UPDATE_URR_REPORTING_TRIGGERS,
                              reporting_triggers, update->triggers);
      update->status &=
        ~(URR_OVER_QUOTA | URR_OVER_VOLUME_THRESHOLD | URR_REPORTED);

      if (ISSET_BIT (urr->grp.fields, UPDATE_URR_MEASUREMENT_PERIOD))
        {
          update->update_flags |= PFCP_URR_UPDATE_MEASUREMENT_PERIOD;
          update->measurement_period.period = urr->measurement_period;

          /* TODO:
           *
           * 3GPP TS 29.244 is not clear on whether the inclusion of
           * Measurement-Period IE resets the start of the periodic
           * reporting.
           *
           * The current implementation does reset the start time
           * for periodic reporting
           */
          update->measurement_period.base = now;
        }

      if (ISSET_BIT (urr->grp.fields, UPDATE_URR_VOLUME_THRESHOLD))
        {
          update->volume.threshold.ul = urr->volume_threshold.ul;
          update->volume.threshold.dl = urr->volume_threshold.dl;
          update->volume.threshold.total = urr->volume_threshold.total;
        }
      if (ISSET_BIT (urr->grp.fields, UPDATE_URR_VOLUME_QUOTA))
        {
          update->update_flags |= PFCP_URR_UPDATE_VOLUME_QUOTA;
          memset (&update->volume.measure.consumed, 0,
                  sizeof (update->volume.measure.consumed));
          update->volume.quota.ul = urr->volume_quota.ul;
          update->volume.quota.dl = urr->volume_quota.dl;
          update->volume.quota.total = urr->volume_quota.total;
        }

      if (ISSET_BIT (urr->grp.fields, UPDATE_URR_TIME_THRESHOLD))
        {
          update->update_flags |= PFCP_URR_UPDATE_TIME_THRESHOLD;
          update->time_threshold.period = urr->time_threshold;
        }
      if (ISSET_BIT (urr->grp.fields, UPDATE_URR_TIME_QUOTA))
        {
          update->update_flags |= PFCP_URR_UPDATE_TIME_QUOTA;
          update->time_quota.period = urr->time_quota;
          update->time_quota.base = update->start_time;
        }

      // TODO: quota_holding_time;
      // TODO: dropped_dl_traffic_threshold;

      if (ISSET_BIT (urr->grp.fields, UPDATE_URR_QUOTA_VALIDITY_TIME))
        {
          update->update_flags |= PFCP_URR_UPDATE_QUOTA_VALIDITY_TIME;
          update->quota_validity_time.period = urr->quota_validity_time;
          update->quota_validity_time.base = now;
        }

      if (ISSET_BIT (urr->grp.fields, UPDATE_URR_MONITORING_TIME))
        {
          f64 secs;

          update->update_flags |= PFCP_URR_UPDATE_MONITORING_TIME;
          update->monitoring_time.unix_time =
            urr->monitoring_time + modf (sx->unix_time_start, &secs);
          update->monitoring_time.vlib_time =
            vlib_time_now (psm->vlib_main) +
            (update->monitoring_time.unix_time - now);
        }

      // TODO: subsequent_volume_threshold;
      // TODO: subsequent_time_threshold;
      // TODO: inactivity_detection_time;

      if (ISSET_BIT (urr->grp.fields, UPDATE_URR_LINKED_URR_ID) &&
          update->triggers & PFCP_REPORTING_TRIGGER_LINKED_USAGE_REPORTING)
        update->linked_urr_ids = vec_dup (urr->linked_urr_id);
      else
        vec_free (update->linked_urr_ids);

      // TODO: measurement_information;
      // TODO: time_quota_mechanism;
    }

  return 0;

out_error:
  response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
  response->failed_rule_id.type = PFCP_FAILED_RULE_TYPE_URR;

  return -1;
}

static int
handle_remove_urr (upf_session_t *sx, pfcp_ie_remove_urr_t *remove_urr,
                   f64 now, pfcp_msg_session_procedure_response_t *response)
{
  pfcp_ie_remove_urr_t *urr;

  if (pfcp_make_pending_urr (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  vec_foreach (urr, remove_urr)
    {
      if (pfcp_delete_urr (sx, urr->urr_id) != 0)
        {
          urr_error (response, urr, "unable to remove");
          goto out_error;
        }
    }

  return 0;

out_error:
  response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
  response->failed_rule_id.type = PFCP_FAILED_RULE_TYPE_URR;

  return -1;
}

#undef urr_error

#define qer_error(r, qer, fmt, ...)                                           \
  do                                                                          \
    {                                                                         \
      tp_session_error_report ((r), "QER ID %u, " fmt, (qer)->qer_id,         \
                               ##__VA_ARGS__);                                \
      response->failed_rule_id.id = qer->qer_id;                              \
    }                                                                         \
  while (0)

static int
handle_create_qer (upf_session_t *sx, pfcp_ie_create_qer_t *create_qer,
                   f64 now, pfcp_msg_session_procedure_response_t *response)
{
  upf_main_t *gtm = &upf_main;
  pfcp_ie_create_qer_t *qer;
  struct rules *rules;

  if (pfcp_make_pending_qer (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  rules = pfcp_get_rules (sx, PFCP_PENDING);
  vec_alloc (rules->qer, vec_len (create_qer));

  vec_foreach (qer, create_qer)
    {
      upf_qer_t *create;

      vec_add2 (rules->qer, create, 1);
      memset (create, 0, sizeof (*create));

      create->id = qer->qer_id;
      create->policer.key =
        OPT (qer, CREATE_QER_QER_CORRELATION_ID, qer_correlation_id,
             (u64) (sx - gtm->sessions) << 32 | create->id);
      create->policer.value = ~0;

      create->gate_status[UPF_UL] = qer->gate_status.ul;
      create->gate_status[UPF_DL] = qer->gate_status.dl;

      if (ISSET_BIT (qer->grp.fields, CREATE_QER_MBR))
        {
          create->flags |= PFCP_QER_MBR;
          create->mbr = qer->mbr;
        }

      // TODO: gbr;
      // TODO: packet_rate;
      // TODO: dl_flow_level_marking;
      // TODO: qos_flow_identifier;
      // TODO: reflective_qos;
    }

  pfcp_sort_qers (rules);
  return 0;
}

static int
handle_update_qer (upf_session_t *sx, pfcp_ie_update_qer_t *update_qer,
                   f64 now, pfcp_msg_session_procedure_response_t *response)
{
  upf_main_t *gtm = &upf_main;
  pfcp_ie_update_qer_t *qer;

  if (pfcp_make_pending_qer (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  vec_foreach (qer, update_qer)
    {
      upf_qer_t *update;

      update = pfcp_get_qer (sx, PFCP_PENDING, qer->qer_id);
      if (!update)
        {
          qer_error (response, qer, "not found");
          goto out_error;
        }

      update->policer.key =
        (ISSET_BIT (qer->grp.fields, UPDATE_QER_QER_CORRELATION_ID)) ?
          qer->qer_correlation_id :
          (u64) (sx - gtm->sessions) << 32 | update->id;
      update->policer.value = ~0;

      if (ISSET_BIT (qer->grp.fields, UPDATE_QER_GATE_STATUS))
        {
          update->gate_status[UPF_UL] = qer->gate_status.ul;
          update->gate_status[UPF_DL] = qer->gate_status.dl;
        }

      if (ISSET_BIT (qer->grp.fields, UPDATE_QER_MBR))
        {
          update->flags |= PFCP_QER_MBR;
          update->mbr = qer->mbr;
        }

      // TODO: gbr;
      // TODO: packet_rate;
      // TODO: dl_flow_level_marking;
      // TODO: qos_flow_identifier;
      // TODO: reflective_qos;
    }

  return 0;

out_error:
  response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
  response->failed_rule_id.type = PFCP_FAILED_RULE_TYPE_QER;

  return -1;
}

static int
handle_remove_qer (upf_session_t *sx, pfcp_ie_remove_qer_t *remove_qer,
                   f64 now, pfcp_msg_session_procedure_response_t *response)
{
  pfcp_ie_remove_qer_t *qer;

  if (pfcp_make_pending_qer (sx) != 0)
    {
      tp_session_error_report (response, "no resources available");
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return -1;
    }

  vec_foreach (qer, remove_qer)
    {
      if (pfcp_delete_qer (sx, qer->qer_id) != 0)
        {
          qer_error (response, qer, "unable to remove");
          goto out_error;
        }
    }

  return 0;

out_error:
  response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

  UPF_SET_BIT (response->grp.fields,
               SESSION_PROCEDURE_RESPONSE_FAILED_RULE_ID);
  response->failed_rule_id.type = PFCP_FAILED_RULE_TYPE_QER;

  return -1;
}

#undef qer_error

static pfcp_ie_usage_report_t *
init_usage_report (upf_urr_t *urr, u32 trigger,
                   pfcp_ie_usage_report_t **report)
{
  pfcp_ie_usage_report_t *r;

  vec_add2 (*report, r, 1);
  memset (r, 0, sizeof (*r));

  UPF_SET_BIT (r->grp.fields, USAGE_REPORT_URR_ID);
  r->urr_id = urr->id;

  UPF_SET_BIT (r->grp.fields, USAGE_REPORT_UR_SEQN);
  r->ur_seqn = urr->seq_no;
  urr->seq_no++;

  UPF_SET_BIT (r->grp.fields, USAGE_REPORT_USAGE_REPORT_TRIGGER);
  r->usage_report_trigger = trigger;

  return r;
}

static void
report_usage_ev (upf_session_t *sess, ip46_address_t *ue, upf_urr_t *urr,
                 u32 trigger, f64 now, pfcp_ie_usage_report_t **report)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_ie_usage_report_t *r;
  urr_volume_t volume;
  u64 start_time, duration;
  f64 vnow = vlib_time_now (psm->vlib_main);

  ASSERT (report);

#ifdef UPF_FLOW_SESSION_SPINLOCK
  clib_spinlock_lock (&sess->lock);
#endif

  volume = urr->volume;
  memset (&urr->volume.measure.packets, 0,
          sizeof (urr->volume.measure.packets));
  memset (&urr->volume.measure.bytes, 0, sizeof (urr->volume.measure.bytes));

  if (!(urr->status & URR_AFTER_MONITORING_TIME) &&
      urr->monitoring_time.vlib_time != INFINITY &&
      urr->monitoring_time.unix_time < now)
    {
      urr->usage_before_monitoring_time.volume = volume.measure;
      memset (&volume.measure.packets, 0, sizeof (volume.measure.packets));
      memset (&volume.measure.bytes, 0, sizeof (volume.measure.bytes));

      urr->usage_before_monitoring_time.start_time = urr->start_time;
      urr->usage_before_monitoring_time.time_of_first_packet =
        urr->time_of_first_packet;
      urr->usage_before_monitoring_time.time_of_last_packet =
        urr->time_of_last_packet;
      urr->start_time = urr->monitoring_time.unix_time;
      urr->time_of_first_packet = INFINITY;
      urr->time_of_last_packet = INFINITY;
      urr->monitoring_time.vlib_time = INFINITY;
      urr->status |= URR_AFTER_MONITORING_TIME;
    }

#ifdef UPF_FLOW_SESSION_SPINLOCK
  clib_spinlock_unlock (&sess->lock);
#endif

  if (urr->status & URR_AFTER_MONITORING_TIME)
    {
      r = init_usage_report (urr, PFCP_USAGE_REPORT_TRIGGER_MONITORING_TIME,
                             report);

      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_USAGE_INFORMATION);
      r->usage_information = PFCP_USAGE_INFORMATION_BEFORE;

      start_time = trunc (urr->usage_before_monitoring_time.start_time);
      duration = trunc (urr->start_time) - start_time;

      if ((trigger & (PFCP_USAGE_REPORT_TRIGGER_START_OF_TRAFFIC |
                      PFCP_USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC)) == 0)
        {
          UPF_SET_BIT (r->grp.fields, USAGE_REPORT_START_TIME);
          UPF_SET_BIT (r->grp.fields, USAGE_REPORT_END_TIME);

          r->start_time = start_time;
          r->end_time = r->start_time + duration;

          if (urr->usage_before_monitoring_time.time_of_first_packet !=
              INFINITY)
            {
              UPF_SET_BIT (r->grp.fields, USAGE_REPORT_TIME_OF_FIRST_PACKET);
              r->time_of_first_packet = trunc (
                now -
                (vnow -
                 urr->usage_before_monitoring_time.time_of_first_packet));

              if (urr->usage_before_monitoring_time.time_of_last_packet !=
                  INFINITY)
                {
                  UPF_SET_BIT (r->grp.fields,
                               USAGE_REPORT_TIME_OF_LAST_PACKET);
                  r->time_of_last_packet = trunc (
                    now -
                    (vnow -
                     urr->usage_before_monitoring_time.time_of_last_packet));
                }
            }

          UPF_SET_BIT (r->grp.fields, USAGE_REPORT_TP_NOW);
          UPF_SET_BIT (r->grp.fields, USAGE_REPORT_TP_START_TIME);
          UPF_SET_BIT (r->grp.fields, USAGE_REPORT_TP_END_TIME);

          r->tp_now = now;
          r->tp_start_time = urr->usage_before_monitoring_time.start_time;
          r->tp_end_time = urr->start_time;
        }

      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_VOLUME_MEASUREMENT);
      r->volume_measurement.fields = PFCP_VOLUME_ALL;

      r->volume_measurement.volume.ul =
        urr->usage_before_monitoring_time.volume.bytes.ul;
      r->volume_measurement.volume.dl =
        urr->usage_before_monitoring_time.volume.bytes.dl;
      r->volume_measurement.volume.total =
        urr->usage_before_monitoring_time.volume.bytes.total;
      r->volume_measurement.packets.ul =
        urr->usage_before_monitoring_time.volume.packets.ul;
      r->volume_measurement.packets.dl =
        urr->usage_before_monitoring_time.volume.packets.dl;
      r->volume_measurement.packets.total =
        urr->usage_before_monitoring_time.volume.packets.total;

      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_DURATION_MEASUREMENT);
      r->duration_measurement = duration;
    }

  r = init_usage_report (urr, trigger, report);

  if (urr->status & URR_AFTER_MONITORING_TIME)
    {
      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_USAGE_INFORMATION);
      r->usage_information = PFCP_USAGE_INFORMATION_AFTER;
    }

  start_time = trunc (urr->start_time);
  duration = trunc (now) - start_time;

  if ((trigger & (PFCP_USAGE_REPORT_TRIGGER_START_OF_TRAFFIC |
                  PFCP_USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC)) == 0)
    {
      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_START_TIME);
      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_END_TIME);

      r->start_time = start_time;
      r->end_time = r->start_time + duration;

      if (urr->time_of_first_packet != INFINITY)
        {
          UPF_SET_BIT (r->grp.fields, USAGE_REPORT_TIME_OF_FIRST_PACKET);
          r->time_of_first_packet =
            trunc (now - (vnow - urr->time_of_first_packet));

          if (urr->time_of_last_packet != INFINITY)
            {
              UPF_SET_BIT (r->grp.fields, USAGE_REPORT_TIME_OF_LAST_PACKET);
              r->time_of_last_packet =
                trunc (now - (vnow - urr->time_of_last_packet));
            }
        }

      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_TP_NOW);
      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_TP_START_TIME);
      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_TP_END_TIME);

      r->tp_now = now;
      r->tp_start_time = urr->start_time;
      r->tp_end_time = urr->start_time + duration;
    }

  if (((trigger & (PFCP_USAGE_REPORT_TRIGGER_START_OF_TRAFFIC |
                   PFCP_USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC)) != 0) &&
      (ue != NULL))
    {

      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_UE_IP_ADDRESS);
      if (ip46_address_is_ip4 (ue))
        {
          r->ue_ip_address.flags = PFCP_UE_IP_ADDRESS_V4;
          r->ue_ip_address.ip4 = ue->ip4;
        }
      else
        {
          r->ue_ip_address.flags = PFCP_UE_IP_ADDRESS_V6;
          r->ue_ip_address.ip6 = ue->ip6;
        }
    }

  if ((trigger & PFCP_USAGE_REPORT_TRIGGER_START_OF_TRAFFIC) == 0)
    {
      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_VOLUME_MEASUREMENT);
      r->volume_measurement.fields = PFCP_VOLUME_ALL;

      r->volume_measurement.volume.ul = volume.measure.bytes.ul;
      r->volume_measurement.volume.dl = volume.measure.bytes.dl;
      r->volume_measurement.volume.total = volume.measure.bytes.total;
      r->volume_measurement.packets.ul = volume.measure.packets.ul;
      r->volume_measurement.packets.dl = volume.measure.packets.dl;
      r->volume_measurement.packets.total = volume.measure.packets.total;

      UPF_SET_BIT (r->grp.fields, USAGE_REPORT_DURATION_MEASUREMENT);
      r->duration_measurement = duration;
    }

  /* UPF_SET_BIT(r->grp.fields,
   * USAGE_REPORT_APPLICATION_DETECTION_INFORMATION); */
  /* UPF_SET_BIT(r->grp.fields, USAGE_REPORT_NETWORK_INSTANCE); */
  /* UPF_SET_BIT(r->grp.fields, USAGE_REPORT_USAGE_INFORMATION); */

  urr->status &= ~URR_AFTER_MONITORING_TIME;
  urr->start_time += duration;
  if (urr->time_threshold.base)
    urr->time_threshold.base = urr->start_time;
  urr->time_of_first_packet = INFINITY;
  urr->time_of_last_packet = INFINITY;
}

void
upf_usage_report_build (upf_session_t *sx, ip46_address_t *ue, upf_urr_t *urr,
                        f64 now, upf_usage_report_t *report,
                        pfcp_ie_usage_report_t **usage_report)
{
  u32 idx;

  upf_debug ("Usage Report:\n  LIUSA %U\n", format_bitmap_hex,
             report->liusa_bitmap);

  vec_foreach_index (idx, report->events)
    {
      upf_usage_report_ev_t *r = vec_elt_at_index (report->events, idx);

      if (r->triggers)
        report_usage_ev (sx, ue, vec_elt_at_index (urr, idx), r->triggers,
                         r->now, usage_report);
      else
        {
          /* not triggered, check LIUSA reporting */

          if (clib_bitmap_get (report->liusa_bitmap, idx))
            report_usage_ev (sx, ue, vec_elt_at_index (urr, idx),
                             PFCP_USAGE_REPORT_TRIGGER_LINKED_USAGE_REPORTING,
                             now, usage_report);
        }
    }
  upf_increment_counter (UPF_SESSION_REPORTS_GENERATED, 0, 1);
}

static int
handle_session_set_deletion_request (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_session_set_deletion_response (pfcp_msg_t *msg,
                                      pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_session_establishment_request (pfcp_msg_t *msg,
                                      pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *gtm = &upf_main;
  pfcp_msg_session_establishment_request_t *req =
    &dmsg->session_establishment_request;
  pfcp_decoded_msg_t resp_dmsg = { .type =
                                     PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE };
  pfcp_msg_session_procedure_response_t *resp =
    &resp_dmsg.session_procedure_response;
  upf_session_t *sess = NULL;
  upf_node_assoc_t *assoc;
  f64 now = psm->now;
  int r = 0;
  int is_ip4;
  u64 cp_seid;

  memset (resp, 0, sizeof (*resp));
  UPF_SET_BIT (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CAUSE);
  resp->cause = PFCP_CAUSE_REQUEST_REJECTED;

  UPF_SET_BIT (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_NODE_ID);
  init_response_node_id (&resp->node_id);

  cp_seid = req->f_seid.seid;
  resp_dmsg.seid = cp_seid;

  assoc = pfcp_get_association (&req->request.node_id);
  if (!assoc)
    {
      tp_session_error_report (resp, "no established PFCP association");

      resp->cause = PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION;
      upf_pfcp_send_response (msg, &resp_dmsg);

      return -1;
    }

  if (pfcp_lookup_cp_f_seid (&req->f_seid))
    {
      tp_session_error_report (resp, "Duplicate F-SEID");
      r = -1;
      goto out_send_resp;
    }

  /*
     Generate up_seid
     Try to reuse cp seid for up seid to simplify debugging (search in
     wireshark)
   */
  u64 up_seid = cp_seid;
  if (PREDICT_FALSE (pfcp_lookup_up_seid (up_seid) != NULL))
    {
      u64 seed = unix_time_now_nsec () ^ cp_seid;
      u8 retry_cnt = 10;

      do
        {
          /* try to generate random seid */
          up_seid = random_u64 (&seed);
          if (up_seid == 0 || up_seid == ~0)
            {
              continue;
            }

          if (!pfcp_lookup_up_seid (up_seid))
            {
              break;
            }
        }
      while (retry_cnt--);

      if (retry_cnt == 0)
        {
          tp_session_error_report (resp, "Out of attempts to generate SEID");
          r = -1;
          goto out_send_resp;
        }
    }

  is_ip4 = ip46_address_is_ip4 (&msg->rmt.address);

  UPF_SET_BIT (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_UP_F_SEID);
  init_response_up_f_seid (&resp->up_f_seid, &msg->lcl.address, is_ip4);
  resp->up_f_seid.seid = up_seid;

#if CLIB_DEBUG > 1
  ip46_address_t up_address = ip46_address_initializer;
  ip46_address_t cp_address = ip46_address_initializer;

  ip_set (&up_address, &msg->lcl.address.ip4, is_ip4);
  ip_set (&cp_address, &req->f_seid.ip4, is_ip4);

  upf_debug ("CP F-SEID: 0x%016" PRIx64 " @ %U %U\n"
             "UP F-SEID: 0x%016" PRIx64 " @ %U\n",
             req->f_seid.seid, format_ip4_address, &req->f_seid.ip4,
             format_ip6_address, &req->f_seid.ip6, up_seid,
             format_ip46_address, &up_address, IP46_TYPE_ANY);
#endif

  sess = pfcp_create_session (assoc, &req->f_seid, up_seid);

  if (ISSET_BIT (req->grp.fields,
                 SESSION_ESTABLISHMENT_REQUEST_USER_PLANE_INACTIVITY_TIMER))
    {
      struct rules *pending = pfcp_get_rules (sess, PFCP_PENDING);

      pending->inactivity_timer.period = req->user_plane_inactivity_timer;
      pending->inactivity_timer.handle = ~0;
    }

  if (ISSET_BIT (req->grp.fields, SESSION_ESTABLISHMENT_REQUEST_USER_ID))
    {
      memcpy (&sess->user_id, &req->user_id, sizeof (pfcp_ie_user_id_t));
      sess->user_id.nai = vec_dup (req->user_id.nai);
    }

  if ((r = handle_create_pdr (sess, req->create_pdr, resp)) != 0)
    goto out_send_resp;

  if (vec_len (resp->created_pdr) > 0)
    UPF_SET_BIT (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CREATED_PDR);

  if ((r = handle_create_far (sess, req->create_far, resp)) != 0)
    goto out_send_resp;

  if ((r = handle_create_urr (sess, req->create_urr, now, resp)) != 0)
    goto out_send_resp;

  r = pfcp_update_apply (sess);
  upf_debug ("Apply: %d\n", r);

  pfcp_update_finish (sess);

  upf_debug ("%U", format_pfcp_session, sess, PFCP_ACTIVE, /*debug */ 1);

out_send_resp:
  if (r == 0)
    resp->cause = PFCP_CAUSE_REQUEST_ACCEPTED;

  upf_pfcp_send_response (msg, &resp_dmsg);

  if (sess && r != 0)
    {
      pfcp_disable_session (sess);
      pfcp_free_session (sess);
    }

  return r;
}

static int
handle_session_establishment_response (pfcp_msg_t *msg,
                                       pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_session_modification_request (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_usage_report_t report;
  pfcp_ie_query_urr_t *qry;
  pfcp_ie_remove_urr_t *rurr;
  bool has_report = false;
  struct rules *active;
  upf_session_t *sess;
  f64 now = psm->now;
  int r = 0;
  pfcp_msg_session_modification_request_t *req =
    &dmsg->session_modification_request;
  pfcp_decoded_msg_t resp_dmsg = {
    .type = PFCP_MSG_SESSION_MODIFICATION_RESPONSE,
  };
  pfcp_msg_session_procedure_response_t *resp =
    &resp_dmsg.session_procedure_response;

  memset (resp, 0, sizeof (*resp));
  UPF_SET_BIT (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CAUSE);
  resp->cause = PFCP_CAUSE_REQUEST_REJECTED;

  if (!(sess = pfcp_lookup_up_seid (dmsg->seid)))
    {
      upf_debug ("PFCP Session %" PRIu64 " not found.\n", dmsg->seid);
      resp->cause = PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;

      r = -1;
      goto out_send_resp;
    }

  resp_dmsg.seid = sess->cp_seid;

  active = pfcp_get_rules (sess, PFCP_ACTIVE);

  /* 3GPP TS 29.244 version 16.5.0 clause 5.2.2.3.1
   * When being instructed to remove a URR or the last PDR associated to a URR,
   * the UP function shall stop its ongoing measurements for the URR and
   * include a Usage Report in the PFCP Session Modification Response or in an
   * additional PFCP Session Report Request.
   */

  if (ISSET_BIT (req->grp.fields, SESSION_MODIFICATION_REQUEST_REMOVE_URR) &&
      vec_len (req->remove_urr) != 0)
    {
      upf_usage_report_init (&report, vec_len (active->urr));
      has_report = true;
      UPF_SET_BIT (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_USAGE_REPORT);

      vec_foreach (rurr, req->remove_urr)
        {
          upf_urr_t *urr;

          if (!(urr = pfcp_get_urr_by_id (active, rurr->urr_id)))
            continue;

          upf_usage_report_trigger (&report, urr - active->urr,
                                    PFCP_USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT,
                                    urr->liusa_bitmap, now);
        }
    }

  if (req->grp.fields &
      (BIT (SESSION_MODIFICATION_REQUEST_USER_PLANE_INACTIVITY_TIMER) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_PDR) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_FAR) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_URR) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_QER) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_BAR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_PDR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_FAR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_URR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_QER) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_BAR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_PDR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_FAR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_URR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_QER) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_BAR)))
    {
      /* invoke the update process only if a update is include */
      pfcp_update_session (sess);

      if (req->grp.fields &
          BIT (SESSION_MODIFICATION_REQUEST_USER_PLANE_INACTIVITY_TIMER))
        {
          struct rules *pending = pfcp_get_rules (sess, PFCP_PENDING);

          pending->inactivity_timer.period = req->user_plane_inactivity_timer;
          pending->inactivity_timer.handle = ~0;
        }

      if ((r = handle_create_pdr (sess, req->create_pdr, resp)) != 0)
        goto out_send_resp;

      if (vec_len (resp->created_pdr) > 0)
        UPF_SET_BIT (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CREATED_PDR);

      if ((r = handle_update_pdr (sess, req->update_pdr, resp)) != 0)
        goto out_send_resp;

      if ((r = handle_remove_pdr (sess, req->remove_pdr, resp)) != 0)
        goto out_send_resp;

      if ((r = handle_create_far (sess, req->create_far, resp)) != 0)
        goto out_send_resp;

      if ((r = handle_update_far (sess, req->update_far, resp)) != 0)
        goto out_send_resp;

      if ((r = handle_remove_far (sess, req->remove_far, resp)) != 0)
        goto out_send_resp;

      if ((r = handle_create_urr (sess, req->create_urr, now, resp)) != 0)
        goto out_send_resp;

      if ((r = handle_update_urr (sess, req->update_urr, now, resp)) != 0)
        goto out_send_resp;

      if ((r = handle_remove_urr (sess, req->remove_urr, now, resp)) != 0)
        goto out_send_resp;

      if ((r = handle_create_qer (sess, req->create_qer, now, resp)) != 0)
        goto out_send_resp;

      if ((r = handle_update_qer (sess, req->update_qer, now, resp)) != 0)
        goto out_send_resp;

      if ((r = handle_remove_qer (sess, req->remove_qer, now, resp)) != 0)
        goto out_send_resp;

      if ((r = pfcp_update_apply (sess)) != 0)
        goto out_update_finish;

      /* TODO: perhaps only increase it on PDR updates */
      sess->generation++;
    }

  if (ISSET_BIT (req->grp.fields, SESSION_MODIFICATION_REQUEST_QUERY_URR) &&
      vec_len (req->query_urr) != 0)
    {
      UPF_SET_BIT (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_USAGE_REPORT);
      if (!has_report)
        {
          has_report = true;
          upf_usage_report_init (&report, vec_len (active->urr));
        }

      vec_foreach (qry, req->query_urr)
        {
          upf_urr_t *urr;

          if (!(urr = pfcp_get_urr_by_id (active, qry->urr_id)))
            continue;

          upf_usage_report_trigger (&report, urr - active->urr,
                                    PFCP_USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT,
                                    urr->liusa_bitmap, now);
        }
    }
  else if (ISSET_BIT (req->grp.fields,
                      SESSION_MODIFICATION_REQUEST_PFCPSMREQ_FLAGS) &&
           req->pfcpsmreq_flags & PFCP_PFCPSMREQ_QAURR)
    {
      if (!has_report)
        {
          has_report = true;
          upf_usage_report_init (&report, vec_len (active->urr));
        }
      if (vec_len (active->urr) != 0)
        {
          UPF_SET_BIT (resp->grp.fields,
                       SESSION_PROCEDURE_RESPONSE_USAGE_REPORT);
          upf_usage_report_set (
            &report, PFCP_USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT, now);
        }
    }

  if (has_report)
    upf_usage_report_build (sess, NULL, active->urr, now, &report,
                            &resp->usage_report);

out_update_finish:
  pfcp_update_finish (sess);

  upf_debug ("%U", format_pfcp_session, sess, PFCP_ACTIVE, /*debug */ 1);

out_send_resp:
  if (r == 0)
    resp->cause = PFCP_CAUSE_REQUEST_ACCEPTED;

  upf_pfcp_send_response (msg, &resp_dmsg);
  if (has_report)
    upf_usage_report_free (&report);

  return r;
}

static int
handle_session_modification_response (pfcp_msg_t *msg,
                                      pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_session_deletion_request (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_decoded_msg_t resp_dmsg = {
    .type = PFCP_MSG_SESSION_DELETION_RESPONSE,
  };
  pfcp_msg_session_procedure_response_t *resp =
    &resp_dmsg.session_procedure_response;
  struct rules *active;
  f64 now = psm->now;
  upf_session_t *sess;
  int r = 0;

  memset (resp, 0, sizeof (*resp));
  UPF_SET_BIT (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_CAUSE);
  resp->cause = PFCP_CAUSE_REQUEST_REJECTED;

  if (!(sess = pfcp_lookup_up_seid (dmsg->seid)))
    {
      upf_debug ("PFCP Session %" PRIu64 " not found.\n", dmsg->seid);
      resp->cause = PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;

      r = -1;
      goto out_send_resp_no_session;
    }

  resp_dmsg.seid = sess->cp_seid;

  pfcp_disable_session (sess);

  active = pfcp_get_rules (sess, PFCP_ACTIVE);
  if (vec_len (active->urr) != 0)
    {
      upf_usage_report_t report;

      UPF_SET_BIT (resp->grp.fields, SESSION_PROCEDURE_RESPONSE_USAGE_REPORT);

      upf_usage_report_init (&report, vec_len (active->urr));
      upf_usage_report_set (&report,
                            PFCP_USAGE_REPORT_TRIGGER_TERMINATION_REPORT, now);
      upf_usage_report_build (sess, NULL, active->urr, now, &report,
                              &resp->usage_report);
      upf_usage_report_free (&report);
    }

  if (r == 0)
    {
      pfcp_free_session (sess);
      resp->cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    }

out_send_resp_no_session:
  upf_pfcp_send_response (msg, &resp_dmsg);

  return r;
}

static int
handle_session_deletion_response (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

static int
handle_session_report_request (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  return -1;
}

/**
 * @brief Handle a PFCP Session Report Response
 *
 * @note dmsg has to contain valid SEID
 */
static int
handle_session_report_response (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg)
{
  upf_main_t *gtm = &upf_main;
  pfcp_msg_session_report_response_t *resp = &dmsg->session_report_response;

  if (msg->session.idx == ~0)
    {
      /* related session was removed previously, nothing to do */
      return -1;
    }

  if (pool_is_free_index (gtm->sessions, msg->session.idx))
    {
      /* Precaution against buggy code */
      ASSERT (0);
      return -1;
    }

  upf_session_t *sx = pool_elt_at_index (gtm->sessions, msg->session.idx);

  if (msg->up_seid != sx->up_seid)
    {
      /*
         TODO: this check is not needed anymore since now we detach request
         from session on session removal, but keeping it for safety
       */
      /*
         since this is a response, and some time passed since the request
         make sure that session index still matches the original session
       */
      upf_debug ("PFCP Session seid not matching (deleted already?).\n");
      ASSERT (msg->up_seid != sx->up_seid);
      return -1;
    }

  upf_debug ("session report response cause %d", resp->response.cause);
  if (resp->response.cause == PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND)
    {
      /* TODO: count those drops */
      pfcp_disable_session (sx);
      pfcp_free_session (sx);
    }
  else if (resp->response.cause == PFCP_CAUSE_REQUEST_ACCEPTED)
    {
      upf_debug ("session report response session flags 0x%x", sx->flags);

      /*
         This is first response since we lost smf peer
         So we have to use new cp_f_seid
       */
      if ((sx->flags & UPF_SESSION_LOST_CP) &&
          (resp->grp.fields & SESSION_REPORT_RESPONSE_CP_F_SEID))
        {
          pfcp_ie_f_seid_t *cp_f_seid =
            &dmsg->session_report_response.cp_f_seid;

          sx->flags &= ~(UPF_SESSION_LOST_CP);
          pfcp_session_set_cp_fseid (sx, cp_f_seid);

          upf_debug ("updated session cp_seid 0x%x (%U,%U) session flags 0x%x",
                     sx->cp_seid, format_ip4_address, &cp_f_seid->ip4,
                     format_ip6_address, &cp_f_seid->ip6, sx->flags);
        }
    }

  return -1;
}

void
upf_pfcp_error_report (upf_session_t *sx, gtp_error_ind_t *error)
{
  pfcp_ie_f_teid_t f_teid;
  pfcp_decoded_msg_t dmsg = { .type = PFCP_MSG_SESSION_REPORT_REQUEST };
  pfcp_msg_session_report_request_t *req = &dmsg.session_report_request;

  memset (req, 0, sizeof (*req));
  UPF_SET_BIT (req->grp.fields, SESSION_REPORT_REQUEST_REPORT_TYPE);
  req->report_type = PFCP_REPORT_TYPE_ERIR;

  UPF_SET_BIT (req->grp.fields,
               SESSION_REPORT_REQUEST_ERROR_INDICATION_REPORT);
  UPF_SET_BIT (req->error_indication_report.grp.fields,
               ERROR_INDICATION_REPORT_F_TEID);

  f_teid.teid = error->teid;
  if (ip46_address_is_ip4 (&error->addr))
    {
      f_teid.flags = PFCP_F_TEID_V4;
      f_teid.ip4 = error->addr.ip4;
    }
  else
    {
      f_teid.flags = PFCP_F_TEID_V6;
      f_teid.ip6 = error->addr.ip6;
    }

  vec_add1 (req->error_indication_report.f_teid, f_teid);

  upf_pfcp_send_request (sx, &dmsg);
}

typedef int (*msg_handler_fun_t) (pfcp_msg_t *msg, pfcp_decoded_msg_t *dmsg);

typedef struct
{
  msg_handler_fun_t fun;
  upf_counters_type_t counter;
} msg_handler_t;

/* clang-format off */
static msg_handler_t msg_handlers[] = {
  [PFCP_MSG_HEARTBEAT_REQUEST] = { handle_heartbeat_request, UPF_PFCP_HB_REQUEST_OK },
  [PFCP_MSG_HEARTBEAT_RESPONSE] = { handle_heartbeat_response, UPF_PFCP_HB_RESPONSE_OK },
  [PFCP_MSG_PFD_MANAGEMENT_REQUEST] = { handle_pfd_management_request, UPF_PFCP_PFD_MANAGEMENT_REQUEST_OK },
  [PFCP_MSG_PFD_MANAGEMENT_RESPONSE] = { handle_pfd_management_response, UPF_PFCP_PFD_MANAGEMENT_RESPONSE_OK },
  [PFCP_MSG_ASSOCIATION_SETUP_REQUEST] = { handle_association_setup_request, UPF_PFCP_ASSOCIATION_SETUP_REQUEST_OK },
  [PFCP_MSG_ASSOCIATION_SETUP_RESPONSE] = { handle_association_setup_response, UPF_PFCP_ASSOCIATION_SETUP_RESPONSE_OK },
  [PFCP_MSG_ASSOCIATION_UPDATE_REQUEST] = { handle_association_update_request, UPF_PFCP_ASSOCIATION_UPDATE_REQUEST_OK },
  [PFCP_MSG_ASSOCIATION_UPDATE_RESPONSE] = { handle_association_update_response, UPF_PFCP_ASSOCIATION_UPDATE_RESPONSE_OK },
  [PFCP_MSG_ASSOCIATION_RELEASE_REQUEST] = { handle_association_release_request, UPF_PFCP_ASSOCIATION_RELEASE_REQUEST_OK },
  [PFCP_MSG_ASSOCIATION_RELEASE_RESPONSE] = { handle_association_release_response, UPF_PFCP_ASSOCIATION_RELEASE_RESPONSE_OK },
  [PFCP_MSG_VERSION_NOT_SUPPORTED_RESPONSE] = {0, ~0}, /* handle_version_not_supported_response, */
  [PFCP_MSG_NODE_REPORT_REQUEST] = { handle_node_report_request, UPF_PFCP_NODE_REPORT_REQUEST_OK },
  [PFCP_MSG_NODE_REPORT_RESPONSE] = { handle_node_report_response, UPF_PFCP_NODE_REPORT_RESPONSE_OK },
  [PFCP_MSG_SESSION_SET_DELETION_REQUEST] = { handle_session_set_deletion_request, UPF_PFCP_SESSION_SET_DELETION_REQUEST_OK },
  [PFCP_MSG_SESSION_SET_DELETION_RESPONSE] = { handle_session_set_deletion_response, UPF_PFCP_SESSION_SET_DELETION_RESPONSE_OK },
  [PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST] = { handle_session_establishment_request, UPF_PFCP_SESSION_ESTABLISHMENT_REQUEST_OK },
  [PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE] = { handle_session_establishment_response, UPF_PFCP_SESSION_ESTABLISHMENT_RESPONSE_OK },
  [PFCP_MSG_SESSION_MODIFICATION_REQUEST] = { handle_session_modification_request, UPF_PFCP_SESSION_MODIFICATION_REQUEST_OK },
  [PFCP_MSG_SESSION_MODIFICATION_RESPONSE] = { handle_session_modification_response, UPF_PFCP_SESSION_MODIFICATION_RESPONSE_OK },
  [PFCP_MSG_SESSION_DELETION_REQUEST] = { handle_session_deletion_request, UPF_PFCP_SESSION_DELETION_REQUEST_OK },
  [PFCP_MSG_SESSION_DELETION_RESPONSE] = { handle_session_deletion_response, UPF_PFCP_SESSION_DELETION_RESPONSE_OK },
  [PFCP_MSG_SESSION_REPORT_REQUEST] = { handle_session_report_request, UPF_PFCP_SESSION_REPORT_REQUEST_OK },
  [PFCP_MSG_SESSION_REPORT_RESPONSE] = { handle_session_report_response, UPF_PFCP_SESSION_REPORT_RESPONSE_OK },
};
/* clang-format on */

/**
 * @brief Handle a PFCP message
 *
 * @param msg PFCP message
 *
 * @note if msg is a response, it needs to contain a valid session_index from
 * request
 */
int
upf_pfcp_handle_msg (pfcp_msg_t *msg)
{
  pfcp_decoded_msg_t dmsg;
  pfcp_ie_offending_ie_t *err = NULL;
  u8 type = pfcp_msg_type (msg->data);
  int r;

  upf_debug ("received message %U", format_pfcp_msg_type,
             pfcp_msg_type (msg->data));

  msg_handler_t *handler = &msg_handlers[type];
  if (type >= ARRAY_LEN (msg_handlers) || !handler->fun)
    {
      /* probably non-PFCP datagram, nothing to reply */
      upf_debug ("PFCP: msg type invalid: %d.", type);
      return -1;
    }

  r = pfcp_decode_msg (msg->data, vec_len (msg->data), &dmsg, &err);

  upf_counters_type_t counter =
    r == 0 ? handler->counter : handler->counter + 1;

  if (r < 0)
    {
      /* not enough info in the message to produce any meaningful reply */
      upf_debug ("PFCP: broken message");
      upf_increment_counter (UPF_PFCP_RECEIVED_CORRUPTED, 0, 1);
      return -1;
    }

  if (r != 0) /* if cause != 0 */
    {
      upf_debug ("PFCP: error response %d", r);
      switch (dmsg.type)
        {
        case PFCP_MSG_HEARTBEAT_REQUEST:
        case PFCP_MSG_PFD_MANAGEMENT_REQUEST:
        case PFCP_MSG_ASSOCIATION_SETUP_REQUEST:
        case PFCP_MSG_ASSOCIATION_UPDATE_REQUEST:
        case PFCP_MSG_ASSOCIATION_RELEASE_REQUEST:
        case PFCP_MSG_SESSION_SET_DELETION_REQUEST:
        case PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST:
        case PFCP_MSG_SESSION_MODIFICATION_REQUEST:
        case PFCP_MSG_SESSION_DELETION_REQUEST:
        case PFCP_MSG_SESSION_REPORT_REQUEST:
          send_simple_response (msg, dmsg.type + 1, r, err);
          break;

        default:
          break;
        }

      vec_free (err);
      goto count;
    }

  // handle message
  r = handler->fun (msg, &dmsg);

count:
  upf_increment_counter (counter, 0, 1);

  pfcp_free_dmsg_contents (&dmsg);

  return r;
}
