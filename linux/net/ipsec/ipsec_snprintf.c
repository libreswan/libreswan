/*
 * @(#) ipsec_snprintf() function
 *
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs <rgb@freeswan.org>
 *                                 2001  Michael Richardson <mcr@freeswan.org>
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * Split out from ipsec_proc.c.
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

#include "libreswan/ipsec_kversion.h"
#include "libreswan/ipsec_param.h"

#include <net/ip.h>

#include "libreswan/radij.h"

#include "libreswan/ipsec_life.h"
#include "libreswan/ipsec_stats.h"
#include "libreswan/ipsec_sa.h"

#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_xmit.h"

#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipsec_esp.h"

#ifdef CONFIG_KLIPS_IPCOMP
#include "libreswan/ipcomp.h"
#endif /* CONFIG_KLIPS_IPCOMP */

#include "libreswan/ipsec_proto.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

/* ipsec_snprintf: like snprintf except
 * - size is signed and a negative value is treated as if it were 0
 * - the returned result is never negative --
 *   an error generates a "?" or null output (depending on space).
 *   (Our callers are too lazy to check for an error return.)
 *
 * @param buf String buffer
 * @param size Size of the string
 * @param fmt printf string
 * @param ... Variables to be displayed in fmt
 * @return int Return code
 */
int ipsec_snprintf(char *buf, ssize_t size, const char *fmt, ...)
{
	va_list args;
	int i;
	size_t possize = size < 0 ? 0 : size;

	va_start(args, fmt);
	i = vsnprintf(buf, possize, fmt, args);
	va_end(args);
	if (i < 0) {
		/* create empty output in place of error */
		i = 0;
		if (size > 0)
			*buf = '\0';
	}
	return i;
}

void ipsec_dmp_block(char *s, caddr_t bb, int len)
{
	int i;
	unsigned char *b = bb;

	printk(KERN_INFO "klips_dmp: "
	       "at %s, len=%d:\n", s, len);

	for (i = 0; i < len; i++ /*, c++*/) {
		if (!(i % 16)) {
			printk(KERN_INFO
			       "klips_debug:   @%03x:",
			       i);
		}
		printk(" %02x", b[i]);
		if (!((i + 1) % 16))
			printk("\n");
	}
	if (i % 16)
		printk("\n");
}

