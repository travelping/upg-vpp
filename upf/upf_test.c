/*
 * upf.c - 3GPP TS 29.244 GTP-U UP plug-in
 *
 * Copyright (c) 2017 Travelping GmbH
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
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vppinfra/error.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} upf_test_main_t;

upf_test_main_t upf_test_main;

#define __plugin_msg_base upf_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#include <vnet/format_fns.h>
#include <upf/upf.api_enum.h>
#include <upf/upf.api_types.h>

static int
api_upf_app_add_del (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_app_ip_rule_add_del (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_app_l7_rule_add_del (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_app_flow_timeout_set (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_update_app (vat_main_t * vam)
{
  return -1;
}

#define vl_api_upf_application_l7_rule_details_t_handler vl_noop_handler
#define vl_api_upf_applications_details_t_handler vl_noop_handler
#define vl_api_upf_nat_pool_details_t_handler vl_noop_handler
#define vl_api_upf_policy_details_t_handler vl_noop_handler
#define vl_api_upf_nwi_details_t_handler vl_noop_handler
#define vl_api_upf_pfcp_endpoint_details_t_handler vl_noop_handler

static int
api_upf_applications_dump (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_application_l7_rule_dump (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_pfcp_reencode (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_pfcp_format (vat_main_t * vam)
{
  return -1;
}

static void vl_api_upf_pfcp_reencode_reply_t_handler
  (vl_api_upf_pfcp_reencode_reply_t * mp)
{
  vat_main_t *vam = upf_test_main.vat_main;

  fformat (vam->ofp, "retval %d packet_len %u\n", mp->retval, mp->packet_len);
}

static void vl_api_upf_pfcp_format_reply_t_handler
  (vl_api_upf_pfcp_format_reply_t * mp)
{
  vat_main_t *vam = upf_test_main.vat_main;

  fformat (vam->ofp, "retval %d text_len %u\n", mp->retval, mp->text_len);
}

static int
api_upf_nat_pool_dump (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_policy_dump (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_policy_add_del (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_nwi_dump (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_nwi_add_del (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_pfcp_endpoint_dump (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_pfcp_endpoint_add_del (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_pfcp_server_set (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_pfcp_policer_set (vat_main_t * vam)
{
  return -1;
}

static int
api_upf_pfcp_heartbeats_set (vat_main_t * vam)
{
  return -1;
}

#include <upf/upf.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
