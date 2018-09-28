#ifndef _IPSEC_OCF_H_
#define _IPSEC_OCF_H_
/****************************************************************************/
/*
 * IPSEC OCF support
 *
 * This code written by David McCullough <dmccullough@cyberguard.com>
 * Copyright (C) 2005 Intel Corporation.  All Rights Reserved.
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
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif
#include <linux/kernel.h>

#ifdef CONFIG_KLIPS_OCF

#include <cryptodev.h>

extern int  ipsec_ocf_sa_init(struct ipsec_sa *ipsp, int authalg, int encalg);
extern int  ipsec_ocf_comp_sa_init(struct ipsec_sa *ipsp, int compalg);
extern int  ipsec_ocf_sa_free(struct ipsec_sa *ipsp);
extern enum ipsec_rcv_value ipsec_ocf_rcv(struct ipsec_rcv_state *irs);
extern enum ipsec_xmit_value ipsec_ocf_xmit(struct ipsec_xmit_state *ixs);
extern void     ipsec_ocf_init(void);

#else
# error \
	This file should not be used without CONFIG_KLIPS_OCF, check MODULE_DEF_INCLUDE and MODULE_DEFCONFIG
#endif

/****************************************************************************/
#endif /* _IPSEC_OCF_H_ */

