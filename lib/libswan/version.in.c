/*
 * return IPsec version information
 * Copyright (C) 2001  Henry Spencer.
 * Copyright (C) 2013  Paul Wouters
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifdef __KERNEL__
# include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#  include <linux/config.h>
# endif
# define __NO_VERSION__
# include <linux/module.h>
# if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0) && LINUX_VERSION_CODE >= \
	KERNEL_VERSION(2, 4, 26)
#  include <linux/moduleparam.h>
# endif
#endif

#include "libreswan.h"

#define V       "@IPSECVERSION@"        /* substituted in by Makefile */
#define VID    "@IPSECVIDVERSION@"     /* substituted in by Makefile */
#define OUR_VENDOR_VID    "OE-Libreswan-@IPSECVIDVERSION@"     /* substituted in by Makefile */
static const char libreswan_number[] = V;
static const char libreswan_string[] = "Libreswan " V;
#ifdef __KERNEL__
static
#endif
const char libreswan_vendorid[] = OUR_VENDOR_VID;


/*
 * pass version to modinfo
 */
#ifdef MODULE_VERSION
MODULE_VERSION(V);
#endif

const char *ipsec_version_code(void)
{
	return libreswan_number;
}

const char *ipsec_version_string(void)
{
	return libreswan_string;
}

const char *ipsec_version_vendorid(void)
{
	return libreswan_vendorid;
}
