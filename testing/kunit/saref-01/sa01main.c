#include <linux/config.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <stdio.h>
#include <assert.h>

#include "skb_fake.h"
#include "slab_fake.h"

#include "libreswan.h"
#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipsec_sa.h"
#include "libreswan/ipsec_policy.h"
#include "libreswan/ipsec_proto.h"
#include "libreswan/ipsec_sysctl.h"
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

struct supported_list *pfkey_supported_list[SADB_SATYPE_MAX + 1];

bool should_i_fail(const char *func)
{
	return 0;
}

bool should_i_fail_once(const char *func)
{
	return 0;
}

#if 0
void sock_wfree(struct sk_buff *skb)
{
}

void sock_rfree(struct sk_buff *skb)
{
}
#endif

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

int pfkey_list_insert_supported(struct ipsec_alg_supported *supported,
				struct supported_list **supported_list)
{
	return -1;
}

int pfkey_list_remove_supported(struct ipsec_alg_supported *supported,
				struct supported_list **supported_list)
{
	return -1;
}

int pfkey_register_reply(int satype, struct sadb_msg *sadb_msg)
{
	return 0;
}

#if 0
int netif_rx_count = 0;

int netif_rx(struct sk_buff *skb)
{
	netif_rx_count++;
	return 0;
}

void ipsec_print_ip(struct iphdr *ip)
{
}

struct net_device *ipsec_get_device(int inst)
{
	struct net_device *ipsec_dev;

	ipsec_dev = NULL;

	return ipsec_dev;
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
#endif

void ipsec_SAtest(void)
{
	IPsecSAref_t SAref = 258;
	struct ipsec_sa ips;

	ips.ips_ref = 772;

	printk("klips_debug:ipsec_SAtest: "
	       "IPSEC_SA_REF_SUBTABLE_IDX_WIDTH=%u\n"
	       "IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES=%u\n"
	       "IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES=%u\n"
	       "IPSEC_SA_REF_HOST_FIELD_WIDTH=%lu\n"
	       "IPSEC_SA_REF_TABLE_MASK=%x\n"
	       "IPSEC_SA_REF_ENTRY_MASK=%x\n"
	       "IPsecSAref2table(%d)=%u\n"
	       "IPsecSAref2entry(%d)=%u\n"
	       "IPsecSAref2NFmark(%d)=%u\n"
	       "IPsecSAref2SA(%d)=%p\n"
	       "IPsecSA2SAref(%p)=%d\n"
	       ,
	       IPSEC_SA_REF_SUBTABLE_IDX_WIDTH,
	       IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES,
	       IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES,
	       (unsigned long) IPSEC_SA_REF_HOST_FIELD_WIDTH,
	       IPSEC_SA_REF_TABLE_MASK,
	       IPSEC_SA_REF_ENTRY_MASK,
	       SAref, IPsecSAref2table(SAref),
	       SAref, IPsecSAref2entry(SAref),
	       SAref, IPsecSAref2NFmark(SAref),
	       SAref, IPsecSAref2SA(SAref),
	       (&ips), IPsecSA2SAref((&ips))
	       );
}

int main(char *argv[], int argc)
{
	int error = 0;

	talloc_enable_leak_report_full();
	debug_xform = 1;

	ipsec_sadb_init();

	printf("test 0\n");
	{
		volatile IPsecSAref_t sa1, sa2;
		volatile unsigned int nf1;

		sa1 = 1;
		nf1 = IPsecSAref2NFmark(sa1);
		sa2 = NFmark2IPsecSAref(nf1);

		/* Test 0 - basic understanding of macros */
		printf("saref= %08x => nfmark= %08x\n",
		       sa1, nf1);

		printf("nfmark=%08x => saref=  %08x\n",
		       nf1, sa2);

		assert( sa1 == sa2 );
	}

	printf("test 1\n");
	/* Test 1 - allocate an SA and let it get a random SAref */
	{
		struct ipsec_sa *sa1;
		/* allocate a new SA */
		sa1 = ipsec_sa_alloc(&error);
		assert(error == 0);

		/* set it to NULL */
		sa1->ips_ref = IPSEC_SAREF_NULL;

		error = ipsec_sa_intern(sa1);
		assert(sa1->ips_ref != IPSEC_SAREF_NULL);

		ipsec_sa_put(sa1);
	}

	printf("test 2\n");
	/* Test 2 - allocate an SA and give it a known value */
	{
		struct ipsec_sa *sa2;
		/* allocate a new SA */
		sa2 = ipsec_sa_alloc(&error);
		assert(error == 0);

		sa2->ips_ref = 2727;

		error = ipsec_sa_intern(sa2);
		assert(sa2->ips_ref != IPSEC_SAREF_NULL);

		ipsec_sa_put(sa2);
	}

	printf("test 3\n");
	/* Test 2 - allocate an SA, and give it a known value twice */
	{
		struct ipsec_sa *sa1;
		struct ipsec_sa *sa2;
		/* allocate a new SA */
		sa2 = ipsec_sa_alloc(&error);
		assert(error == 0);

		sa2->ips_ref = 27;

		error = ipsec_sa_intern(sa2);
		assert(sa2->ips_ref != IPSEC_SAREF_NULL);

		/* allocate a new SA */
		sa1 = ipsec_sa_alloc(&error);
		assert(error == 0);

		/* set it to 27 */
		sa1->ips_ref = 27;

		error = ipsec_sa_intern(sa1);
		assert(sa1->ips_ref != IPSEC_SAREF_NULL);

		ipsec_sa_put(sa1);
		ipsec_sa_put(sa2);
	}

	printf("freeing things up\n");
	ipsec_sadb_cleanup(0); /* 0 = all protocols */
	ipsec_sadb_free();

	exit(0);
}

