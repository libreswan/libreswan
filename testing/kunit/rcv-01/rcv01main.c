#include <linux/config.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <stdio.h>
#include <assert.h>

#include "skb_fake.h"
#include "slab_fake.h"

#include "openswan.h"
#include "openswan/ipsec_rcv.h"
#include "openswan/ipsec_sa.h"
#include "openswan/ipsec_policy.h"
#include "openswan/ipsec_proto.h"
#include "pfkeyv2.h"
#include "pfkey.h"

int debug_tunnel;
int debug_eroute;
int debug_spi;
int debug_radij;
int debug_pfkey;
int debug_ah;
int debug_esp;
int debug_netlink;
int sysctl_ipsec_debug_verbose;
int sysctl_ipsec_debug_ipcomp;
int sysctl_ipsec_icmp;
int sysctl_ipsec_tos;
extern int debug_rcv;

struct prng ipsec_prng;


struct supported_list *pfkey_supported_list[SADB_SATYPE_MAX+1];

bool should_i_fail(const char *func)
{
  return 0;
}

bool should_i_fail_once(const char *func)
{
  return 0;
}

void sock_wfree(struct sk_buff *skb)
{
}

void sock_rfree(struct sk_buff *skb)
{
}

void *field_value(const void *strct, const char *name)
{
  return NULL;
}

void field_attach(const void *strct, const char *name, void *val)
{
}

void field_attach_static(const void *strct, const char *name, void *val)
{
}

void field_detach(const void *strct, const char *name)
{
}

void field_detach_all(const void *strct, const char *name)
{
}

int
pfkey_list_insert_supported(struct ipsec_alg_supported *supported,
			    struct supported_list **supported_list)
{
  return -1;
}

int
pfkey_list_remove_supported(struct ipsec_alg_supported *supported,
			    struct supported_list **supported_list)
{
  return -1;
}

#include "rcv01pack.c"

int netif_rx_count=0;

int netif_rx(struct sk_buff *skb)
{
  ipsec_dmp_block("netif_rx", skb->data, skb->len);
  ipsec_dmp_block("shouldbe", (unsigned char *)packet10+14, packet10_len-14);
  netif_rx_count++;
  return 0;
}

int
pfkey_register_reply(int satype, struct sadb_msg *sadb_msg)
{
  return 0;
}

void ipsec_print_ip(struct iphdr *ip)
{
  return;
}

int pfkey_expire(struct ipsec_sa *sa, int time)
{
  return 1;
}

int pfkey_nat_t_new_mapping(struct ipsec_sa *sa, struct sockaddr *mapping,
			    __u16 port)
{
  return 1;
}

struct sk_buff *skb_decompress(struct sk_buff *skb)
{
  return skb;
}

struct sk_buff *skb_compress(struct sk_buff *skb)
{
  return skb;
}

unsigned char seed[8]={ 0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08};

int main(char *argv[], int argc)
{
  int ret;
  int error;
  struct sockaddr_in saddr,daddr;
  struct sockaddr_in saddr2,daddr2;
  void *rcv01_talloc = NULL;

  struct ipsec_sa *sa, *sa1;
  char auth1[]={0x87, 0x65, 0x87, 0x65,
	       0x87, 0x65, 0x87, 0x65,
	       0x87, 0x65, 0x87, 0x65,
	       0x87, 0x65, 0x87, 0x65};
  char enc[] ={0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46, 0x49,
	       0x49, 0x4a, 0x4a, 0x4c, 0x4c, 0x4f, 0x4f, 0x51,
	       0x51, 0x52, 0x52, 0x54, 0x54, 0x57, 0x57, 0x58};

  init_kmalloc();
  debug_rcv=0xffffffff;
  sysctl_ipsec_debug_verbose = 1;
  prng_init(&ipsec_prng, seed, sizeof(seed));
  ipsec_sadb_init();
  ipsec_alg_init();

  {
    sa1 = ipsec_sa_alloc(&error);
    assert(error == 0);

    sa1->ips_said.spi = htonl(0x12345678);
    sa1->ips_said.proto = IPPROTO_IPIP;
    sa1->ips_said.dst.u.v4.sin_addr.s_addr = htonl(0xc001022D);

    sa1->ips_seq = 1;
    sa1->ips_pid = 10;
    
    sa1->ips_state = SADB_SASTATE_MATURE;
    daddr2.sin_addr.s_addr = htonl(0xc001022D);
    saddr2.sin_addr.s_addr = htonl(0xc0010217);
    sa1->ips_addr_s = (struct sockaddr *)&saddr2;
    sa1->ips_addr_d = (struct sockaddr *)&daddr2;
  }
    
  {
    sa = ipsec_sa_alloc(&error);
    assert(error == 0);
    sa->ips_said.spi = htonl(0x12345678);
    sa->ips_said.proto = IPPROTO_ESP;
    sa->ips_said.dst.u.v4.sin_addr.s_addr = htonl(0xc001022D);

    sa->ips_seq = 1;
    sa->ips_pid = 10;
    sa->ips_inext = sa1;

    {
      /* make a copy so that ipsec_sa_init() can zero it out */
      char *auth = talloc_size(rcv01_talloc, AHMD596_KLEN);

      memcpy(auth, auth1, AHMD596_KLEN);
      sa->ips_authalg = AH_MD5;
      sa->ips_key_bits_a = AHMD596_KLEN * 8;
      sa->ips_key_a = auth;
    }

    sa->ips_encalg = ESP_3DES;
    sa->ips_key_bits_e = 192;
    sa->ips_iv_bits = 128;
    sa->ips_key_e_size = 0;
    sa->ips_key_e = talloc_memdup(rcv01_talloc, enc, sa->ips_key_bits_e);

    sa->ips_state = SADB_SASTATE_MATURE;
    daddr.sin_addr.s_addr = htonl(0xc001022D);
    saddr.sin_addr.s_addr = htonl(0xc0010217);
    sa->ips_addr_s = (struct sockaddr *)&saddr;
    sa->ips_addr_d = (struct sockaddr *)&daddr;

    ipsec_sa_add(sa);
    assert(ipsec_sa_init(sa) == 0);
    //ipsec_sa_put(sa);
  }
    
  {
    struct sk_buff *skb = skbFromArray(packet1, packet1_len);
    skb_ethernet_ip_setup(skb);

    ret = ipsec_rcv(skb);
    assert(netif_rx_count == 1);
  }
  
  return 0;
}

  

  
