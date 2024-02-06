#include <vnet/ip/ip.h>

typedef union
{
  struct
  {
    ip4_address_t saddr, daddr;
    u16 sport; // ICMP id for ICMP case
    u16 dport;
    u32 fib_index : 24;
    u8 proto;
  };
  u64 as_u64[2];
  u64x2u as_u128;
} nat_6t_t;

STATIC_ASSERT_SIZEOF (nat_6t_t, 2 * sizeof (u64));

typedef struct
{
#define NAT_FLOW_OP_SADDR_REWRITE   (1 << 1)
#define NAT_FLOW_OP_SPORT_REWRITE   (1 << 2)
#define NAT_FLOW_OP_DADDR_REWRITE   (1 << 3)
#define NAT_FLOW_OP_DPORT_REWRITE   (1 << 4)
#define NAT_FLOW_OP_ICMP_ID_REWRITE (1 << 5)
#define NAT_FLOW_OP_TXFIB_REWRITE   (1 << 6)
  int ops;
  nat_6t_t match;
  struct
  {
    ip4_address_t saddr, daddr;
    u16 sport;
    u16 dport;
    u32 fib_index;
    u8 proto;
    u16 icmp_id;
  } rewrite;
  uword l3_csum_delta;
  uword l4_csum_delta;
} nat_6t_flow_t;
