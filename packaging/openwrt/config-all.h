#ifndef _CONFIG_ALL_H_
/*
 * Copyright (C) 2011              Paul Wouters <paul@xelerance.com>
 *
 * This kernel module is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This kernel module is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * This version is specific for openwrt. It requires OCF support in the kernel
 * so that libreswan's kernel module can use the broadcom based OCF crypto
 * hardware offload (via kmod-ocf-ubsec_ssb)
 * I also plan to add SAref patches to the kernel for better L2TP support
 */
#define _CONFIG_ALL_H_  /* seen it, no need to see it again */

#define CONFIG_KLIPS 1

#define CONFIG_KLIPS_AH 1
#define CONFIG_KLIPS_ESP 1
#define CONFIG_KLIPS_IPCOMP 1
#define CONFIG_KLIPS_DEBUG 1
#define CONFIG_KLIPS_IPIP 1

#define CONFIG_KLIPS_ENC_3DES 1
#define CONFIG_KLIPS_ENC_AES 1
#define CONFIG_KLIPS_AUTH_HMAC_MD5 1
#define CONFIG_KLIPS_AUTH_HMAC_SHA1 1

#define CONFIG_KLIPS_DYNDEV 1

#if 0
/* Only required for 2.4.x kernels or 2.6.x kernels older then 2.6.23 */
#ifndef CONFIG_IPSEC_NAT_TRAVERSAL
#define CONFIG_IPSEC_NAT_TRAVERSAL 0
#endif
#endif

#define CONFIG_KLIPS_ENC_CRYPTOAPI 1

/* Requires OCF support be compiled in */
#define CONFIG_KLIPS_OCF 1

#define CONFIG_KLIPS_ALG_AES_MAC 1

#ifndef CONFIG_KLIPS_ALG
#define CONFIG_KLIPS_ALG 1
#endif

#endif /* _CONFIG_ALL_H */
