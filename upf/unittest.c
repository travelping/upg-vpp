#include <vlib/vlib.h>

#include "upf.h"
#include "upf_ipfilter.h"
#include "pfcp.h"
#include "upf_app_db.h"

static int upf_test_do_debug = 0;

/* based on fib_test.c */
#define UPF_TEST_I(_cond, _comment, _args...)		\
  ({							\
    int _evald = (_cond);				\
    if (!(_evald)) {					\
      fformat(stderr, "FAIL:%d: " _comment "\n",	\
	      __LINE__, ##_args);			\
      res = 1;						\
    } else {						\
      if (upf_test_do_debug)				\
	fformat(stderr, "PASS:%d: " _comment "\n",	\
		__LINE__, ##_args);			\
    }							\
    res;						\
  })
#define UPF_TEST(_cond, _comment, _args...)	\
  {						\
    if (UPF_TEST_I(_cond, _comment, ##_args))	\
      ASSERT(!("FAIL: " _comment));		\
  }

static int
test_add_ip_rule (u8 *app_name, u32 id, char *ipfilter)
{
  int res = 0;
  upf_main_t * gtm = &upf_main;
  unformat_input_t input;
  acl_rule_t rule;
  unformat_init_string (&input, ipfilter, strlen(ipfilter));
  UPF_TEST (unformat (&input, "%U", unformat_ipfilter, &rule),
            "unformat ipfilter");
  unformat_free (&input);
  UPF_TEST (upf_rule_add_del (gtm, app_name, id, 1, 0, &rule) == 0,
            "upf_rule_add_del");
  return res;
}

static int
setup_apps (u32 *app_id, u32 *app_id_any)
{
  int res = 0;
  upf_main_t * gtm = &upf_main;
  u8 * app_name = format (0, "IPAPP"), * app_name_any = format (0, "IPANY");
  uword *p;

  UPF_TEST (upf_app_add_del (gtm, app_name, 0, 1) == 0, "add app");
  UPF_TEST (test_add_ip_rule (app_name, 2000,
                              "permit out ip from 10.10.10.10 to assigned") == 0,
            "add ip rule 2000");
  UPF_TEST (test_add_ip_rule (app_name, 2001,
                              "permit out ip from 192.168.0.0/24 70-100 to assigned") == 0,
            "add ip rule 2001");
  UPF_TEST (test_add_ip_rule (app_name, 2002,
                              "permit out ip from 2001:db8:12::2 to assigned") == 0,
            "add ip rule 2002");
  UPF_TEST (test_add_ip_rule (app_name, 2003,
                              "permit out ip from 2001:db8:13::/64 70-100 to assigned") == 0,
            "add ip rule 2003");
  UPF_TEST (upf_app_add_del (gtm, app_name_any, 0, 1) == 0, "add app");
  UPF_TEST (test_add_ip_rule (app_name_any, 12345,
                              "permit out ip from any to assigned") == 0,
            "add ip rule 12345");

  p = hash_get_mem (gtm->upf_app_by_name, app_name);
  UPF_TEST (!!p, "get app by name");
  UPF_TEST (!pool_is_free_index (gtm->upf_apps, p[0]), "app entry not free");
  *app_id = upf_adf_get_adr_db (p[0]);
  /* UPF_TEST (fib_table_find (FIB_PROTOCOL_IP4, 10000000 + (*app - gtm->upf_apps)) != ~0, */
  /*           "FIB table created (IP4)"); */
  /* UPF_TEST (fib_table_find (FIB_PROTOCOL_IP6, 20000000 + (*app - gtm->upf_apps)) != ~0, */
  /*           "FIB table created (IP6)"); */

  p = hash_get_mem (gtm->upf_app_by_name, app_name_any);
  UPF_TEST (!!p, "get app by name");
  UPF_TEST (!pool_is_free_index (gtm->upf_apps, p[0]), "app entry not free");
  *app_id_any = upf_adf_get_adr_db (p[0]);
  /* UPF_TEST (fib_table_find (FIB_PROTOCOL_IP4, 10000000 + (*app_any - gtm->upf_apps)) != ~0, */
  /*           "FIB table created (IP4)"); */
  /* UPF_TEST (fib_table_find (FIB_PROTOCOL_IP6, 20000000 + (*app_any - gtm->upf_apps)) != ~0, */
  /*           "FIB table created (IP6)"); */

  vec_free (app_name);
  vec_free (app_name_any);

  return res;
}

static int
cleanup_apps (u32 app_id, u32 app_id_any)
{
  int res = 0;
  upf_main_t * gtm = &upf_main;
  u8 * app_name = format (0, "IPAPP"), * app_name_any = format (0, "IPANY");
  /* u32 app_table_id = 10000000 + (app - gtm->upf_apps), */
  /*   app_any_table_id = 20000000 + (app_any - gtm->upf_apps); */

  upf_adf_put_adr_db (app_id);
  upf_adf_put_adr_db (app_id_any);

  UPF_TEST (upf_app_add_del (gtm, app_name, 0, 0) == 0, "del IPAPP");

  /* FIXME: trying to remove FIB table causes crash
  UPF_TEST (fib_table_find (FIB_PROTOCOL_IP4, app_table_id) == ~0,
            "IPAPP FIB table removed (IP4)");
  UPF_TEST (fib_table_find (FIB_PROTOCOL_IP6, app_table_id) == ~0,
            "IPAPP FIB table removed (IP6)");
  */

  UPF_TEST (upf_app_add_del (gtm, app_name_any, 0, 0) == 0, "del IPANY");
  /* FIXME: trying to remove FIB table causes crash
  UPF_TEST (fib_table_find (FIB_PROTOCOL_IP4, app_any_table_id) == ~0,
            "IPANY FIB table removed (IP4)");
  UPF_TEST (fib_table_find (FIB_PROTOCOL_IP6, app_any_table_id) == ~0,
            "IPANY FIB table removed (IP6)");
  */

  vec_free (app_name);
  vec_free (app_name_any);

  return res;
}

static int
ip_app_test_v4 (void)
{
  int res = 0;
  u32 app_id, app_id_any;

  setup_apps (&app_id, &app_id_any);

  ip46_address_t ip_ue_172_17_0_5 = {
    .ip4.as_u32 = clib_host_to_net_u32(0xac110005),
  };
  ip46_address_t ip_192_168_0_5 = {
    .ip4.as_u32 = clib_host_to_net_u32(0xc0a80005),
  };
  ip46_address_t ip_10_10_10_10 = {
    .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a0a),
  };
  ip46_address_t ip_10_20_20_20 = {
    .ip4.as_u32 = clib_host_to_net_u32(0x0a141414),
  };

  flow_entry_t flow;
  memset (&flow, 0, sizeof(flow));
  flow.key.ip[FT_ORIGIN].ip4.as_u32 = ip_ue_172_17_0_5.ip4.as_u32;
  flow.key.port[FT_ORIGIN] = clib_host_to_net_u16(12345);
  flow.key.ip[FT_REVERSE].ip4.as_u32 = ip_10_20_20_20.ip4.as_u32;
  flow.key.port[FT_REVERSE] = clib_host_to_net_u16(80);

  UPF_TEST (!upf_app_ip_rule_match (app_id, &flow, &ip_ue_172_17_0_5),
            "rule mismatch (IPAPP): 172.17.0.5:12345 -> 10.20.20.20:80");
  UPF_TEST (upf_app_ip_rule_match (app_id_any, &flow, &ip_ue_172_17_0_5),
            "rule match (IPANY): 172.17.0.5:12345 -> 10.20.20.20:80");

  flow.key.ip[FT_REVERSE].ip4.as_u32 = ip_10_10_10_10.ip4.as_u32;
  UPF_TEST (upf_app_ip_rule_match (app_id, &flow, &ip_ue_172_17_0_5),
            "rule match (IPAPP): 172.17.0.5:12345 -> 10.10.10.10:80");
  UPF_TEST (upf_app_ip_rule_match (app_id_any, &flow, &ip_ue_172_17_0_5),
            "rule match (IPANY): 172.17.0.5:12345 -> 10.10.10.10:80");

  flow.key.ip[FT_REVERSE].ip4.as_u32 = ip_192_168_0_5.ip4.as_u32;
  UPF_TEST (upf_app_ip_rule_match (app_id, &flow, &ip_ue_172_17_0_5),
            "rule match (IPAPP): 172.17.0.5:12345 -> 192.168.0.5:80");
  UPF_TEST (upf_app_ip_rule_match (app_id_any, &flow, &ip_ue_172_17_0_5),
            "rule match (IPANY): 172.17.0.5:12345 -> 192.168.0.5:80");

  flow.key.port[FT_REVERSE] = clib_host_to_net_u16(9999);
  UPF_TEST (!upf_app_ip_rule_match (app_id, &flow, &ip_ue_172_17_0_5),
            "rule mismatch (IPAPP): 172.17.0.5:12345 -> 192.168.0.5:9999");
  UPF_TEST (upf_app_ip_rule_match (app_id_any, &flow, &ip_ue_172_17_0_5),
            "rule match (IPANY): 172.17.0.5:12345 -> 192.168.0.5:9999");

  flow.key.ip[FT_ORIGIN].ip4.as_u32 = ip_10_20_20_20.ip4.as_u32;
  flow.key.port[FT_REVERSE] = clib_host_to_net_u16(80);
  UPF_TEST (!upf_app_ip_rule_match (app_id, &flow, &ip_ue_172_17_0_5),
            "rule mismatch (IPAPP): 10.20.20.20:12345 -> 192.168.0.5:80");
  UPF_TEST (!upf_app_ip_rule_match (app_id_any, &flow, &ip_ue_172_17_0_5),
            "rule mismatch (IPANY): 10.20.20.20:12345 -> 192.168.0.5:80");

  cleanup_apps(app_id, app_id_any);

  return res;
}

static int
ip_app_test_v6 (void)
{
  int res = 0;
  u32 app_id, app_id_any;

  setup_apps (&app_id, &app_id_any);

  ip46_address_t ip_ue_2001_db8_11__3 = {
    .ip6.as_u64 = {
      clib_host_to_net_u64(0x20010db800110000),
      clib_host_to_net_u64(0x0000000000000003),
    }
  };
  ip46_address_t ip_2001_db8_13__5 = {
    .ip6.as_u64 = {
      clib_host_to_net_u64(0x20010db800130000),
      clib_host_to_net_u64(0x0000000000000005),
    }
  };
  ip46_address_t ip_2001_db8_12__2 = {
    .ip6.as_u64 = {
      clib_host_to_net_u64(0x20010db800120000),
      clib_host_to_net_u64(0x0000000000000002),
    }
  };
  ip46_address_t ip_2001_db8_12__3 = {
    .ip6.as_u64 = {
      clib_host_to_net_u64(0x20010db800120000),
      clib_host_to_net_u64(0x0000000000000003),
    }
  };

  flow_entry_t flow;
  memset (&flow, 0, sizeof(flow));
  flow.key.ip[FT_ORIGIN].ip6.as_u64[0] = ip_ue_2001_db8_11__3.ip6.as_u64[0];
  flow.key.ip[FT_ORIGIN].ip6.as_u64[1] = ip_ue_2001_db8_11__3.ip6.as_u64[1];
  flow.key.port[FT_ORIGIN] = clib_host_to_net_u16(12345);
  flow.key.ip[FT_REVERSE].ip6.as_u64[0] = ip_2001_db8_12__3.ip6.as_u64[0];
  flow.key.ip[FT_REVERSE].ip6.as_u64[1] = ip_2001_db8_12__3.ip6.as_u64[1];
  flow.key.port[FT_REVERSE] = clib_host_to_net_u16(80);

  UPF_TEST (!upf_app_ip_rule_match (app_id, &flow, &ip_ue_2001_db8_11__3),
            "rule mismatch (IPAPP): [2001:db8:11::3]:12345 -> [2001:db8:12::3]:80");
  UPF_TEST (upf_app_ip_rule_match (app_id_any, &flow, &ip_ue_2001_db8_11__3),
            "rule match (IPANY): [2001:db8:11::3]:12345 -> [2001:db8:12::3]:80");

  flow.key.ip[FT_REVERSE].ip6.as_u64[0] = ip_2001_db8_12__2.ip6.as_u64[0];
  flow.key.ip[FT_REVERSE].ip6.as_u64[1] = ip_2001_db8_12__2.ip6.as_u64[1];
  UPF_TEST (upf_app_ip_rule_match (app_id, &flow, &ip_ue_2001_db8_11__3),
            "rule match (IPAPP): [2001:db8:11::3]:12345 -> [2001:db8:12::2]:80");
  UPF_TEST (upf_app_ip_rule_match (app_id_any, &flow, &ip_ue_2001_db8_11__3),
            "rule match (IPANY): [2001:db8:11::3]:12345 -> [2001:db8:12::2]:80");

  flow.key.ip[FT_REVERSE].ip6.as_u64[0] = ip_2001_db8_13__5.ip6.as_u64[0];
  flow.key.ip[FT_REVERSE].ip6.as_u64[1] = ip_2001_db8_13__5.ip6.as_u64[1];
  UPF_TEST (upf_app_ip_rule_match (app_id, &flow, &ip_ue_2001_db8_11__3),
            "rule match (IPAPP): [2001:db8:11::3]:12345 -> [2001:db8:13::5]:80");
  UPF_TEST (upf_app_ip_rule_match (app_id_any, &flow, &ip_ue_2001_db8_11__3),
            "rule match (IPANY): [2001:db8:11::3]:12345 -> [2001:db8:13::5]:80");

  flow.key.port[FT_REVERSE] = clib_host_to_net_u16(9999);
  UPF_TEST (!upf_app_ip_rule_match (app_id, &flow, &ip_ue_2001_db8_11__3),
            "rule mismatch (IPAPP): [2001:db8:11::3]:12345 -> [2001:db8:13::5]:9999");
  UPF_TEST (upf_app_ip_rule_match (app_id_any, &flow, &ip_ue_2001_db8_11__3),
            "rule match (IPANY): [2001:db8:11::3]:12345 -> [2001:db8:13::5]:9999");

  flow.key.ip[FT_ORIGIN].ip6.as_u64[0] = ip_2001_db8_12__3.ip6.as_u64[0];
  flow.key.ip[FT_ORIGIN].ip6.as_u64[1] = ip_2001_db8_12__3.ip6.as_u64[1];
  flow.key.port[FT_REVERSE] = clib_host_to_net_u16(80);
  UPF_TEST (!upf_app_ip_rule_match (app_id, &flow, &ip_ue_2001_db8_11__3),
            "rule mismatch (IPAPP): [2001:db8:12::3]:12345 -> [2001:db8:13::5]:80");
  UPF_TEST (!upf_app_ip_rule_match (app_id_any, &flow, &ip_ue_2001_db8_11__3),
            "rule mismatch (IPANY): [2001:db8:12::3]:12345 -> [2001:db8:13::5]:80");

  cleanup_apps(app_id, app_id_any);

  return res;
}

static int
tbcd_test()
{
  int res = 0;
  u8 sample_value[] = { 0x09, 0x09, 0x60, 0x00, 0xa2, 0xcb, 0xed, 0xf9 };
  u8 * expected = "909006002*#abc9";
  u8 * actual = format(0, "%U", format_tbcd, sample_value, sizeof(sample_value));

  UPF_TEST (vec_len (actual) == strlen (expected) &&
	    !memcmp (actual, expected, strlen(expected)),
	    "bad format_tbcd result");

  return res;
}

static clib_error_t *
test_upf_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  if (unformat (input, "debug"))
    upf_test_do_debug = 1;

  if (ip_app_test_v4 () == 0 && ip_app_test_v6 () == 0 && tbcd_test () == 0)
    return 0;
  else
    return clib_error_return (0, "test failed");
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_upf_command, static) =
  {
    .path = "test upf",
    .short_help = "test upf [debug]",
    .function = test_upf_command_fn,
  };
/* *INDENT-ON* */

/*
  TODO: test intersecting rules
  TODO: test reverse flows
 */
