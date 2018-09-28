/*
 * Authentication Header declarations
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
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
 */

#include "ipsec_md5h.h"
#include "ipsec_sha1.h"

#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif /* IPPROTO_AH */

#include "ipsec_auth.h"

#ifdef __KERNEL__

#ifndef CONFIG_XFRM_ALTERNATE_STACK
extern struct inet_protocol ah_protocol;
#endif /* CONFIG_XFRM_ALTERNATE_STACK */

struct options;

struct ahhdr                            /* Generic AH header */
{
	__u8 ah_nh;                     /* Next header (protocol) */
	__u8 ah_hl;                     /* AH length, in 32-bit words */
	__u16 ah_rv;                    /* reserved, must be 0 */
	__u32 ah_spi;                   /* Security Parameters Index */
	__u32 ah_rpl;                   /* Replay prevention */
	__u8 ah_data[AHHMAC_HASHLEN];   /* Authentication hash */
};
#define AH_BASIC_LEN 8                  /* basic AH header is 8 bytes, nh,hl,rv,spi
					 * and the ah_hl, says how many bytes after that
					 * to cover.
					 */

extern struct xform_functions ah_xform_funcs[];

#include "libreswan/ipsec_sysctl.h"

#endif /* __KERNEL__ */

