#include <vlib/vlib.h>

#include "upf/upf.h"
#include "upf/rules/upf_ipfilter.h"
#include "upf/adf/matcher.h"
#include "upf/pfcp/pfcp_proto.h"
#include "upf/utils/worker_pool.h"

static int upf_test_do_debug = 0;

/* based on fib_test.c */
#define UPF_TEST_I(_cond, _comment, _args...)                                 \
  ({                                                                          \
    int _evald = (_cond);                                                     \
    if (!(_evald))                                                            \
      {                                                                       \
        fformat (stderr, "FAIL:%d: " _comment "\n", __LINE__, ##_args);       \
        res = 1;                                                              \
      }                                                                       \
    else                                                                      \
      {                                                                       \
        if (upf_test_do_debug)                                                \
          fformat (stderr, "PASS:%d: " _comment "\n", __LINE__, ##_args);     \
      }                                                                       \
    res;                                                                      \
  })
#define UPF_TEST(_cond, _comment, _args...)                                   \
  {                                                                           \
    if (UPF_TEST_I (_cond, _comment, ##_args))                                \
      ASSERT (!("FAIL: " _comment));                                          \
  }

typedef struct
{
  ip46_address_t ip_ue;
  u16 port_ue;
  ip46_address_t ip_rmt;
  u16 port_rmt;
  u8 *uri;
  bool is_ue_assigned;
  bool should_hit;
} test_match_t;

uword
unformat_test_match (unformat_input_t *input, va_list *args)
{
  test_match_t *tm = va_arg (*args, test_match_t *);
  u8 *uri = NULL;

  tm->is_ue_assigned = false;

  u32 port_ue, port_rmt;

  if (unformat (input, "hit"))
    tm->should_hit = true;
  else if (unformat (input, "miss"))
    tm->should_hit = false;
  else
    {
      ASSERT (0);
      return 0;
    }

  if (unformat (input, "assigned:%u", &port_ue))
    tm->is_ue_assigned = true;
  else if (unformat (input, "%U:%u", unformat_ip4_address, &tm->ip_ue.ip4,
                     &port_ue))
    ip46_address_mask_ip4 (&tm->ip_ue);
  else if (unformat (input, "[%U]:%u", unformat_ip6_address, &tm->ip_ue.ip6,
                     &port_ue))
    ;
  else
    {
      ASSERT (0);
      return 0;
    }

  if (!unformat (input, "->"))
    {
      ASSERT (0);
      return 0;
    }

  if (unformat (input, "%U:%u", unformat_ip4_address, &tm->ip_rmt.ip4,
                &port_rmt))
    ip46_address_mask_ip4 (&tm->ip_rmt);
  else if (unformat (input, "[%U]:%u", unformat_ip6_address, &tm->ip_rmt.ip6,
                     &port_rmt))
    ;
  else
    {
      ASSERT (0);
      return 0;
    }

  if (unformat (input, "uri %v", &uri))
    tm->uri = vec_dup (uri);

  tm->port_rmt = port_rmt;
  tm->port_ue = port_ue;

  return 1;
}

typedef struct
{
  const char *app_name;
  const char **ip_rules;
  const char **tests;

  upf_adf_app_t *app;
} test_app_t;

test_app_t app_tests[] = {
  {
    .app_name = "IPAPP",
    .ip_rules =
      (const char *[]){
        "permit out ip from 10.10.10.10 to assigned",
        "permit out ip from 192.168.0.0/24 70-100 to assigned",
        "permit out ip from 2001:db8:12::2 to assigned",
        "permit out ip from 2001:db8:13::/64 70-100 to assigned",
        NULL,
      },
    .tests =
      (const char *[]){
        "miss  assigned:12345 -> 10.20.20.20:80",
        "hit   assigned:12345 -> 10.10.10.10:80",
        "hit   assigned:12345 -> 192.168.0.5:80",
        "miss  assigned:12345 -> 192.168.0.5:9999",
        "miss  10.10.10.20:12345 -> 192.168.0.5:9999",
        "miss  assigned:12345 -> [2001:db8:12::3]:80",
        "hit   assigned:12345 -> [2001:db8:12::2]:80",
        "hit   assigned:12345 -> [2001:db8:13::5]:80",
        "miss  assigned:12345 -> [2001:db8:13::5]:9999",
        "miss  [2001:db8:12::3]:12345 -> [2001:db8:13::5]:80",
        NULL,
      },
  },
  {
    .app_name = "IPANY",
    .ip_rules =
      (const char *[]){
        "permit out ip from any to assigned",
        NULL,
      },
    .tests =
      (const char *[]){
        "hit  assigned:12345 -> 10.20.20.20:80",
        "hit  assigned:12345 -> 10.10.10.10:80",
        "hit  assigned:12345 -> 192.168.0.5:80",
        "hit  assigned:12345 -> 192.168.0.5:9999",
        "miss 10.10.10.20:12345 -> 192.168.0.5:9999",
        "hit  assigned:12345 -> [2001:db8:12::3]:80",
        "hit  assigned:12345 -> [2001:db8:12::2]:80",
        "hit  assigned:12345 -> [2001:db8:13::5]:80",
        "hit  assigned:12345 -> [2001:db8:13::5]:9999",
        "miss  [2001:db8:12::3]:12345 -> [2001:db8:13::5]:80",
        NULL,
      },
  },
  {},
};

static int
ip_app_test (void)
{
  int res = 0;
  upf_main_t *um = &upf_main;

  for (test_app_t *ta = app_tests; ta->app_name; ta++)
    {
      u8 *app_name = format (0, "%s", ta->app_name);
      UPF_TEST (upf_adf_app_create (app_name) == 0, "add app %s",
                ta->app_name);
      vec_free (app_name);
    }

  // get after creation, so vector is not reallocated anymore
  for (test_app_t *ta = app_tests; ta->app_name; ta++)
    {
      u8 *app_name = format (0, "%s", ta->app_name);
      ta->app = upf_adf_app_get_by_name (app_name);
      UPF_TEST (ta->app != NULL, "get app %s", ta->app_name);

      UPF_TEST (upf_adf_app_version_create (ta->app, NULL) == 0,
                "create app %s version", ta->app_name);

      vec_free (app_name);
    }

  for (test_app_t *ta = app_tests; ta->app_name; ta++)
    {
      for (const char **s_rule = ta->ip_rules; *s_rule; s_rule++)
        {
          unformat_input_t input;
          ipfilter_rule_t rule;

          unformat_init_string (&input, *s_rule, strlen (*s_rule));
          UPF_TEST (unformat_user (&input, unformat_upf_ipfilter, &rule),
                    "unformat ipfilter: %s", *s_rule);
          unformat_free (&input);

          // clib_warning ("parsed '%s' as '%U'", *s_rule, format_upf_ipfilter,
          //               &rule);

          UPF_TEST (upf_adf_app_rule_create_by_acl (ta->app, &rule) == 0,
                    "rule add %s", *s_rule);
        }
    }

  for (test_app_t *ta = app_tests; ta->app_name; ta++)
    UPF_TEST (upf_adf_commit_version (ta->app) == 0, "commit app %s",
              ta->app_name);

  for (test_app_t *ta = app_tests; ta->app_name; ta++)
    {
      upf_adf_app_version_t *ver =
        pool_elt_at_index (um->adf_main.versions, ta->app->active_ver_idx);

      for (const char **s_test = ta->tests; *s_test; s_test++)
        {
          unformat_input_t input;
          test_match_t tm = {};

          unformat_init_string (&input, *s_test, strlen (*s_test));
          UPF_TEST (unformat_user (&input, unformat_test_match, &tm),
                    "unformat test %s", *s_test);
          unformat_free (&input);
          bool hit = false;
          if (ip46_address_is_ip4 (&tm.ip_rmt))
            hit =
              upf_adf_ip_match4 (ver, &tm.ip_ue.ip4, &tm.ip_rmt.ip4,
                                 tm.port_ue, tm.port_rmt, tm.is_ue_assigned);
          else
            hit =
              upf_adf_ip_match6 (ver, &tm.ip_ue.ip6, &tm.ip_rmt.ip6,
                                 tm.port_ue, tm.port_rmt, tm.is_ue_assigned);

          UPF_TEST (hit == tm.should_hit, "rule %s should %s",
                    tm.should_hit ? "hit" : "miss", *s_test);
        }
    }

  return res;
}

static int
tbcd_test ()
{
  int res = 0;
  u8 sample_value[] = { 0x09, 0x09, 0x60, 0x00, 0xa2, 0xcb, 0xed, 0xf9 };
  const char *expected = "909006002*#abc9";
  u8 *actual =
    format (0, "%U", format_pfcp_tbcd, sample_value, sizeof (sample_value));

  UPF_TEST (vec_len (actual) == strlen (expected), "tbcd should match len");
  UPF_TEST (!memcmp (actual, expected, strlen (expected)),
            "tbcd should match val");

  return res;
}

static clib_error_t *
test_upf_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "debug"))
            upf_test_do_debug = 1;
          else
            {
              unformat_free (line_input);
              return clib_error_return (0, "unknown input");
            }
        }
      unformat_free (line_input);
    }

  if (ip_app_test () == 0 && tbcd_test () == 0)
    return 0;
  else
    return clib_error_return (0, "test failed");
}

VLIB_CLI_COMMAND (test_upf_command, static) = {
  .path = "test upf",
  .short_help = "test upf [debug]",
  .function = test_upf_command_fn,
};
