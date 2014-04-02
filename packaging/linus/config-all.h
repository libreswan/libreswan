#ifndef _CONFIG_ALL_H_
/*
 * Copyright (C) 2002              Michael Richardson <mcr@freeswan.org>
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
 */
#define _CONFIG_ALL_H_  /* seen it, no need to see it again */

#define CONFIG_KLIPS_MODULE 1

#ifndef CONFIG_KLIPS_AH
#define CONFIG_KLIPS_AH 1
#endif

#ifndef CONFIG_KLIPS_DEBUG
#define CONFIG_KLIPS_DEBUG 1
#endif

#ifndef CONFIG_KLIPS_ESP
#define CONFIG_KLIPS_ESP 1
#endif

#ifndef CONFIG_KLIPS_IPCOMP
#define CONFIG_KLIPS_IPCOMP 1
#endif

#ifndef CONFIG_KLIPS_IPIP
#define CONFIG_KLIPS_IPIP 1
#endif

#ifndef CONFIG_KLIPS_AUTH_HMAC_MD5
#define CONFIG_KLIPS_AUTH_HMAC_MD5 1
#endif

#ifndef CONFIG_KLIPS_AUTH_HMAC_SHA1
#define CONFIG_KLIPS_AUTH_HMAC_SHA1 1
#endif

#ifndef CONFIG_KLIPS_DYNDEV
#define CONFIG_KLIPS_DYNDEV 1
#endif

#ifndef CONFIG_KLIPS_ENC_3DES
#define CONFIG_KLIPS_ENC_3DES 1
#endif

/* no longer needed as of 2.6.22 and up */
#if 0
# ifndef CONFIG_IPSEC_NAT_TRAVERSAL
#  define CONFIG_IPSEC_NAT_TRAVERSAL 1
# endif
#endif
#undef CONFIG_IPSEC_NAT_TRAVERSAL

#ifndef CONFIG_KLIPS_ENC_AES
#define CONFIG_KLIPS_ENC_AES 1
#endif

#ifndef CONFIG_KLIPS_ENC_CRYPTOAPI
#define CONFIG_KLIPS_ENC_CRYPTOAPI 1
#endif

#define CONFIG_KLIPS_ALG_CRYPTOAPI #error
#define CONFIG_KLIPS_ALG_AES #error

/* off by default requires kernel patch */
#if 0
# ifndef CONFIG_KLIPS_OCF
#  define CONFIG_KLIPS_OCF 1
# endif
#endif
#undef CONFIG_KLIPS_OCF

#ifndef CONFIG_KLIPS_ALG_AES_MAC
#define CONFIG_KLIPS_ALG_AES_MAC 1
#endif

/* ALGO: */
#if 0
/* goal: cleanup KLIPS code from hardcoded algos :} */
# undef CONFIG_KLIPS_AUTH_HMAC_MD5
# undef CONFIG_KLIPS_AUTH_HMAC_SHA1
# undef CONFIG_KLIPS_ENC_3DES
#endif

#ifndef CONFIG_KLIPS_ALG
#define CONFIG_KLIPS_ALG 1
#endif

#endif /* _CONFIG_ALL_H */
