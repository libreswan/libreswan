/*
 * Common routines for IPSEC transformations.
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 * Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
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

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38) && !defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif
#include <linux/kernel.h> /* printk() */

#include "freeswan/ipsec_param.h"

#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/skbuff.h>
#include <linux/random.h>	/* get_random_bytes() */
#include <freeswan.h>
#include <linux/spinlock.h> /* *lock* */

#include <net/ip.h>

#include "freeswan/radij.h"
#include "freeswan/ipsec_encap.h"
#include "freeswan/ipsec_radij.h"
#include "freeswan/ipsec_xform.h"
#include "freeswan/ipsec_ipe4.h"
#include "freeswan/ipsec_ah.h"
#include "freeswan/ipsec_esp.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

/*
 *
 * Local Variables:
 * c-file-style: "linux"
 * End:
 *
 */
