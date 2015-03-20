/*
 * IPCOMP zlib interface code.
 * implementation of RFC 3173.
 *
 * Copyright (C) 2000  Svenning Soerensen <svenning@post5.tele.dk>
 * Copyright (C) 2000, 2001  Richard Guy Briggs <rgb@conscoop.ottawa.on.ca>
 * Copyright (C) 2012, Paul Wouters <paul@libreswan.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/* SSS */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

#include "libreswan/ipsec_param.h"

#include <linux/slab.h>         /* kmalloc() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

#include <linux/netdevice.h>    /* struct device, and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/ip.h>           /* struct iphdr */
#include <linux/skbuff.h>
#include <asm/uaccess.h>
#include <asm/checksum.h>

#include <libreswan.h>

#include <net/ip.h>

#include "libreswan/ipsec_kversion.h"
#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_sa.h"

#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_rcv.h" /* sysctl_ipsec_inbound_policy_check */
extern int sysctl_ipsec_inbound_policy_check;
#include "libreswan/ipsec_proto.h"
#include "libreswan/ipcomp.h"
#include "zlib/zlib.h"
#include "zlib/zutil.h"

#include <libreswan/pfkeyv2.h> /* SADB_X_CALG_DEFLATE */

static
voidpf my_zcalloc(voidpf opaque, uInt items, uInt size)
{
	return (voidpf) kmalloc(items * size, GFP_ATOMIC);
}

static
void my_zfree(voidpf opaque, voidpf address)
{
	kfree(address);
}

/*
 * We use this function because sometimes we want to pass a negative offset
 * into skb_put(), this does not work on 64bit platforms because long to
 * unsigned int casting.
 */
static inline unsigned char *safe_skb_put(struct sk_buff *skb, int extend)
{
	unsigned char *ptr;

	if (extend > 0) {
		/* increase the size of the packet */
		ptr = skb_put(skb, extend);
	} else {
		/* shrink the size of the packet */
		ptr = skb_tail_pointer(skb);
		skb_trim(skb, skb->len + extend);
	}

	return ptr;
}

struct sk_buff *skb_compress(struct sk_buff *skb, struct ipsec_sa *ips,
			     unsigned int *flags)
{
	struct iphdr *iph;

#ifdef CONFIG_KLIPS_IPV6
	struct ipv6hdr *iph6;
#endif
	unsigned char nexthdr;
	unsigned int iphlen, pyldsz, cpyldsz;
	unsigned char *buffer;
	z_stream zs;
	int zresult;

	KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
		    "klips_debug:skb_compress: .\n");

	if (skb == NULL) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "passed in NULL skb, returning ERROR.\n");
		if (flags != NULL)
			*flags |= IPCOMP_PARMERROR;
		return skb;
	}

	if (ips == NULL) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "passed in NULL ipsec_sa needed for cpi, returning ERROR.\n");
		if (flags)
			*flags |= IPCOMP_PARMERROR;
		return skb;
	}

	if (flags == NULL) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "passed in NULL flags, returning ERROR.\n");
		ipsec_kfree_skb(skb);
		return NULL;
	}

	iph = ip_hdr(skb);
#ifdef CONFIG_KLIPS_IPV6
	iph6 = ipv6_hdr(skb);
#endif

#ifdef CONFIG_KLIPS_IPV6
	if (iph->version == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		int nexthdroff;
		nexthdr = iph6->nexthdr;
		nexthdroff = ipsec_ipv6_skip_exthdr(skb,
						    ((void *)(iph6 +
							      1)) - (void*)skb->data, &nexthdr,
						    &frag_off);
		iphlen = nexthdroff - ((void *)iph6 - (void*)skb->data);
		pyldsz = ntohs(iph6->payload_len) + sizeof(struct ipv6hdr) -
			 iphlen;
	} else
#endif
	{
		nexthdr = iph->protocol;
		iphlen = iph->ihl << 2;
		pyldsz = ntohs(iph->tot_len) - iphlen;
	}

	switch (nexthdr) {
	case IPPROTO_COMP:
	case IPPROTO_AH:
	case IPPROTO_ESP:
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "skipping compression of packet with ip protocol %d.\n",
			    iph->protocol);
		*flags |= IPCOMP_UNCOMPRESSABLE;
		return skb;
	}

	/* Don't compress packets already fragmented */
	if (iph->version == 4 &&
	    (iph->frag_off & __constant_htons(IP_MF | IP_OFFSET))) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "skipping compression of fragmented packet.\n");
		*flags |= IPCOMP_UNCOMPRESSABLE;
		return skb;
	}

	/* Don't compress less than 90 bytes (rfc 2394) */
	if (pyldsz < 90) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "skipping compression of tiny packet, len=%d.\n",
			    pyldsz);
		*flags |= IPCOMP_UNCOMPRESSABLE;
		return skb;
	}

	/* Adaptive decision */
	if (ips->ips_comp_adapt_skip) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_debug:skb_compress: "
			    "skipping compression: ips_comp_adapt_skip=%d.\n",
			    ips->ips_comp_adapt_skip);
		ips->ips_comp_adapt_skip--;
		*flags |= IPCOMP_UNCOMPRESSABLE;
		return skb;
	}

	zs.zalloc = my_zcalloc;
	zs.zfree = my_zfree;
	zs.opaque = 0;

	/* We want to use deflateInit2 because we don't want the adler
	   header. */
	zresult = deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -11,
			       DEF_MEM_LEVEL,  Z_DEFAULT_STRATEGY);
	if (zresult != Z_OK) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_compress: "
			    "deflateInit2() returned error %d (%s), "
			    "skipping compression.\n",
			    zresult,
			    zs.msg ? zs.msg : zError(zresult));
		*flags |= IPCOMP_COMPRESSIONERROR;
		return skb;
	}

	/* Max output size. Result should be max this size.
	 * Implementation specific tweak:
	 * If it's not at least 32 bytes and 6.25% smaller than
	 * the original packet, it's probably not worth wasting
	 * the receiver's CPU cycles decompressing it.
	 * Your mileage may vary.
	 */
	cpyldsz = pyldsz - sizeof(struct ipcomphdr) -
		  (pyldsz <= 512 ? 32 : pyldsz >> 4);

	buffer = kmalloc(cpyldsz, GFP_ATOMIC);
	if (!buffer) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_compress: "
			    "unable to kmalloc(%d, GFP_ATOMIC), "
			    "skipping compression.\n",
			    cpyldsz);
		*flags |= IPCOMP_COMPRESSIONERROR;
		deflateEnd(&zs);
		return skb;
	}

	if (sysctl_ipsec_debug_ipcomp && sysctl_ipsec_debug_verbose) {
		__u8 *c;

		c = (__u8*)iph + iphlen;
		ipsec_dmp_block("compress before", c, pyldsz);
	}

	zs.next_in = (char *) iph + iphlen;     /* start of payload */
	zs.avail_in = pyldsz;
	zs.next_out = buffer;                   /* start of compressed payload */
	zs.avail_out = cpyldsz;

	/* Finish compression in one step */
	zresult = deflate(&zs, Z_FINISH);

	/* Free all dynamically allocated buffers */
	deflateEnd(&zs);
	if (zresult != Z_STREAM_END) {
		*flags |= IPCOMP_UNCOMPRESSABLE;
		kfree(buffer);

		/* Adjust adaptive counters */
		if (++(ips->ips_comp_adapt_tries) ==
		    IPCOMP_ADAPT_INITIAL_TRIES) {
			KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
				    "klips_debug:skb_compress: "
				    "first %d packets didn't compress, "
				    "skipping next %d\n",
				    IPCOMP_ADAPT_INITIAL_TRIES,
				    IPCOMP_ADAPT_INITIAL_SKIP);
			ips->ips_comp_adapt_skip = IPCOMP_ADAPT_INITIAL_SKIP;
		} else if (ips->ips_comp_adapt_tries ==
			   IPCOMP_ADAPT_INITIAL_TRIES +
			   IPCOMP_ADAPT_SUBSEQ_TRIES) {
			KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
				    "klips_debug:skb_compress: "
				    "next %d packets didn't compress, "
				    "skipping next %d\n",
				    IPCOMP_ADAPT_SUBSEQ_TRIES,
				    IPCOMP_ADAPT_SUBSEQ_SKIP);
			ips->ips_comp_adapt_skip = IPCOMP_ADAPT_SUBSEQ_SKIP;
			ips->ips_comp_adapt_tries = IPCOMP_ADAPT_INITIAL_TRIES;
		}

		return skb;
	}

	/* resulting compressed size */
	cpyldsz -= zs.avail_out;

	/* Insert IPCOMP header */
	((struct ipcomphdr*) ((char*) iph + iphlen))->ipcomp_nh = nexthdr;
	((struct ipcomphdr*) ((char*) iph + iphlen))->ipcomp_flags = 0;
	/* use the bottom 16 bits of the spi for the cpi.  The top 16 bits are
	   for internal reference only. */
	((struct ipcomphdr*) (((char*)iph) +
			      iphlen))->ipcomp_cpi =
		htons((__u16)(ntohl(ips->ips_said.spi) & 0x0000ffff));
	KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
		    "klips_debug:skb_compress: "
		    "spi=%08x, spi&0xffff=%04x, cpi=%04x, payload size: raw=%d, comp=%d.\n",
		    ntohl(ips->ips_said.spi),
		    ntohl(ips->ips_said.spi) & 0x0000ffff,
		    ntohs(((struct ipcomphdr*)(((char*)iph) +
					       iphlen))->ipcomp_cpi),
		    pyldsz,
		    cpyldsz);

	/* Update IP header */
#ifdef CONFIG_KLIPS_IPV6
	if (iph->version == 6) {
		iph6->nexthdr = IPPROTO_COMP;
		iph6->payload_len = htons(iphlen + sizeof(struct ipcomphdr) + cpyldsz -
					  sizeof(struct ipv6hdr));
	} else
#endif
	{
		iph->protocol = IPPROTO_COMP;
		iph->tot_len = htons(
			iphlen + sizeof(struct ipcomphdr) + cpyldsz);
#if 1           /* XXX checksum is done by ipsec_tunnel ? */
		iph->check = 0;
		iph->check = ip_fast_csum((char *) iph, iph->ihl);
#endif
	}

	/* Copy compressed payload */
	memcpy((char *) iph + iphlen + sizeof(struct ipcomphdr),
	       buffer,
	       cpyldsz);
	kfree(buffer);

	/* Update skb length/tail by "unputting" the shrinkage */
	safe_skb_put(skb, cpyldsz + sizeof(struct ipcomphdr) - pyldsz);

	if (sysctl_ipsec_debug_ipcomp && sysctl_ipsec_debug_verbose) {
		__u8 *c;

		c = (__u8*)iph + iphlen + sizeof(struct ipcomphdr);
		ipsec_dmp_block("compress result", c, cpyldsz);
	}

	ips->ips_comp_adapt_skip = 0;
	ips->ips_comp_adapt_tries = 0;

	return skb;
}

struct sk_buff *skb_decompress(struct sk_buff *skb, struct ipsec_sa *ips,
			       unsigned int *flags)
{
	struct sk_buff *nskb = NULL;
	/* original ip header */
	struct iphdr *oiph, *iph;

#ifdef CONFIG_KLIPS_IPV6
	struct ipv6hdr *oiph6, *iph6;
#endif
	unsigned char nexthdr;
	unsigned int tot_len, iphlen, pyldsz, cpyldsz;
	z_stream zs;
	int zresult;

	KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
		    "klips_debug:skb_decompress: .\n");

	if (!skb) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "passed in NULL skb, returning ERROR.\n");
		if (flags)
			*flags |= IPCOMP_PARMERROR;
		return skb;
	}

	if (!ips && sysctl_ipsec_inbound_policy_check) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "passed in NULL ipsec_sa needed for comp alg, returning ERROR.\n");
		if (flags)
			*flags |= IPCOMP_PARMERROR;
		return skb;
	}

	if (!flags) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "passed in NULL flags, returning ERROR.\n");
		ipsec_kfree_skb(skb);
		return NULL;
	}

	oiph = ip_hdr(skb);
#ifdef CONFIG_KLIPS_IPV6
	oiph6 = ipv6_hdr(skb);
#endif

#ifdef CONFIG_KLIPS_IPV6
	if (oiph->version == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		int nexthdroff;
		nexthdr = oiph6->nexthdr;
		nexthdroff = ipsec_ipv6_skip_exthdr(skb,
						    ((void *)(oiph6 +
							      1)) - (void*)skb->data, &nexthdr,
						    &frag_off);
		iphlen = nexthdroff - ((void *)oiph6 - (void*)skb->data);
		tot_len = ntohs(oiph6->payload_len) + sizeof(struct ipv6hdr);
	} else
#endif
	{
		iphlen = oiph->ihl << 2;
		tot_len = ntohs(oiph->tot_len);
		nexthdr = oiph->protocol;
	}

	if (nexthdr != IPPROTO_COMP) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "called with non-IPCOMP packet (protocol=%d),"
			    "skipping decompression.\n",
			    oiph->protocol);
		*flags |= IPCOMP_PARMERROR;
		return skb;
	}

	if (((struct ipcomphdr*)((char*) oiph + iphlen))->ipcomp_flags != 0 ||
	     (((struct ipcomphdr*) ((char*) oiph + iphlen))->ipcomp_cpi !=
	       htons(SADB_X_CALG_DEFLATE) &&
	      sysctl_ipsec_inbound_policy_check &&
	      (ips == NULL || ips->ips_encalg != SADB_X_CALG_DEFLATE))) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "called with incompatible IPCOMP packet (flags=%d, "
			    "cpi=%d), ips-compalg=%d, skipping decompression.\n",
			    ntohs(((struct ipcomphdr*) ((char*) oiph +
							iphlen))->ipcomp_flags),
			    ntohs(((struct ipcomphdr*) ((char*) oiph +
							iphlen))->ipcomp_cpi),
			    ips == NULL ? 0 : ips->ips_encalg);
		*flags |= IPCOMP_PARMERROR;

		return skb;
	}

	/* if anything other than the DF bit is set */
	if (oiph->version == 4 && ntohs(oiph->frag_off) & ~IP_DF) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "called with fragmented IPCOMP packet, "
			    "skipping decompression.\n");
		*flags |= IPCOMP_PARMERROR;
		return skb;
	}

	/* original compressed payload size */
	cpyldsz = tot_len - iphlen - sizeof(struct ipcomphdr);

	zs.zalloc = my_zcalloc;
	zs.zfree = my_zfree;
	zs.opaque = 0;

	zs.next_in = (char *) oiph + iphlen + sizeof(struct ipcomphdr);
	zs.avail_in = cpyldsz;

	/* Maybe we should be a bit conservative about memory
	   requirements and use inflateInit2 */
	/* Beware, that this might make us unable to decompress packets
	   from other implementations - HINT: check PGPnet source code */
	/* We want to use inflateInit2 because we don't want the adler
	   header. */
	zresult = inflateInit2(&zs, -15);
	if (zresult != Z_OK) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "inflateInit2() returned error %d (%s), "
			    "skipping decompression.\n",
			    zresult,
			    zs.msg ? zs.msg : zError(zresult));
		*flags |= IPCOMP_DECOMPRESSIONERROR;

		return skb;
	}

	/* We have no way of knowing the exact length of the resulting
	   decompressed output before we have actually done the decompression.
	   For now, we guess that the packet will not be bigger than the
	   attached ipsec device's mtu or 16260, whichever is biggest.
	   This may be wrong, since the sender's mtu may be bigger yet.
	   XXX This must be dealt with later XXX
	 */

	/* max payload size */
	pyldsz = skb->dev ? (skb->dev->mtu < 16260 ? 16260 : skb->dev->mtu) :
		 (65520 - iphlen);
	KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
		    "klips_debug:skb_decompress: "
		    "max payload size: %d\n", pyldsz);

	while (pyldsz > (cpyldsz + sizeof(struct ipcomphdr)) &&
	       (nskb = skb_copy_expand(skb,
				       skb_headroom(skb),
				       pyldsz - cpyldsz -
				       sizeof(struct ipcomphdr),
				       GFP_ATOMIC)) == NULL) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "unable to skb_copy_expand(skb, 0, %d, GFP_ATOMIC), "
			    "trying with less payload size.\n",
			    (int)(pyldsz - cpyldsz -
				  sizeof(struct ipcomphdr)));
		pyldsz >>= 1;
	}

	if (!nskb) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "unable to allocate memory, dropping packet.\n");
		*flags |= IPCOMP_DECOMPRESSIONERROR;
		inflateEnd(&zs);

		return skb;
	}

	if (sysctl_ipsec_debug_ipcomp && sysctl_ipsec_debug_verbose) {
		__u8 *c;

		c = (__u8*)oiph + iphlen + sizeof(struct ipcomphdr);
		ipsec_dmp_block("decompress before", c, cpyldsz);
	}

	safe_skb_put(nskb, pyldsz - cpyldsz - sizeof(struct ipcomphdr));

	iph = ip_hdr(nskb);
#ifdef CONFIG_KLIPS_IPV6
	iph6 = ipv6_hdr(nskb);
#endif
	zs.next_out = (char *)iph + iphlen;
	zs.avail_out = pyldsz;

	zresult = inflate(&zs, Z_SYNC_FLUSH);

	/* work around a bug in zlib, which sometimes wants to taste an extra
	 * byte when being used in the (undocumented) raw deflate mode.
	 */
	if (zresult == Z_OK && !zs.avail_in && zs.avail_out) {
		__u8 zerostuff = 0;

		zs.next_in = &zerostuff;
		zs.avail_in = 1;
		zresult = inflate(&zs, Z_FINISH);
	}

	inflateEnd(&zs);
	if (zresult != Z_STREAM_END) {
		KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
			    "klips_error:skb_decompress: "
			    "inflate() returned error %d (%s), "
			    "skipping decompression.\n",
			    zresult,
			    zs.msg ? zs.msg : zError(zresult));
		*flags |= IPCOMP_DECOMPRESSIONERROR;
		ipsec_kfree_skb(nskb);

		return skb;
	}

	/* Update IP header */
	/* resulting decompressed size */
	pyldsz -= zs.avail_out;
	nexthdr = ((struct ipcomphdr *) ((char *)oiph + iphlen))->ipcomp_nh;
#ifdef CONFIG_KLIPS_IPV6
	if (iph->version == 6) {
		iph6->payload_len =
			htons(pyldsz + iphlen - sizeof(struct ipv6hdr));
		iph6->nexthdr = nexthdr;
	} else
#endif
	{
		iph->tot_len = htons(iphlen + pyldsz);
		iph->protocol = nexthdr;
#if 1           /* XXX checksum is done by ipsec_rcv ? */
		iph->check = 0;
		iph->check = ip_fast_csum((char*) iph, iph->ihl);
#endif
	}
	KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
		    "klips_debug:skb_decompress: "
		    "spi=%08x, spi&0xffff=%04x, cpi=%04x, payload size: comp=%d, raw=%d, nh=%d.\n",
		    ips ? ntohl(ips->ips_said.spi) : 0,
		    ips ? ntohl(ips->ips_said.spi) & 0x0000ffff : 0,
		    ntohs(((struct ipcomphdr*)(((char*)oiph) +
					       iphlen))->ipcomp_cpi),
		    cpyldsz,
		    pyldsz,
		    nexthdr);

	/* Update skb length/tail by "unputting" the unused data area */
	safe_skb_put(nskb, -zs.avail_out);

	ipsec_kfree_skb(skb);

	if (nexthdr == IPPROTO_COMP) {
		if (sysctl_ipsec_debug_ipcomp) {
			KLIPS_PRINT(sysctl_ipsec_debug_ipcomp,
				    "klips_debug:skb_decompress: "
				    "Eh? inner packet is also compressed, dropping.\n");
		}

		ipsec_kfree_skb(nskb);
		return NULL;
	}

	if (sysctl_ipsec_debug_ipcomp && sysctl_ipsec_debug_verbose) {
		__u8 *c;

		c = (__u8*)iph + iphlen;
		ipsec_dmp_block("decompress result", c, pyldsz);
	}

	return nskb;
}

