#ifndef _CONFIG_RH_I686_SMP_H_
/*
 * Copyright (C) 2002              Michael Richardson <mcr@freeswan.org>
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
 * RCSID $Id: config-i686-smp.h,v 1.5 2005/01/06 01:34:59 paul Exp $
 */
#define	_CONFIG_RH_I686_SMP_H_	/* seen it, no need to see it again */

#define CONFIG_KLIPS 1

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

#ifndef CONFIG_KLIPS_ENC_AES
#define CONFIG_KLIPS_ENC_AES 1
#endif

#ifndef CONFIG_KLIPS_NAT_TRAVERSAL
#define CONFIG_KLIPS_NAT_TRAVERSAL 1
#endif

#ifndef CONFIG_IPSEC_NAT_TRAVERSAL
#define CONFIG_IPSEC_NAT_TRAVERSAL 1
#endif

/* off by default for now */
#ifndef CONFIG_KLIPS_ENC_CRYPTOAPI
#define CONFIG_KLIPS_ENC_CRYPTOAPI 0
#endif

#define CONFIG_KLIPS_ALG_CRYPTOAPI #error
#define CONFIG_KLIPS_ALG_AES #error

#ifndef CONFIG_KLIPS_ALG_AES_MAC
#define CONFIG_KLIPS_ALG_AES_MAC 1
#endif

#ifndef CONFIG_KLIPS_REGRESS
#define CONFIG_KLIPS_REGRESS 0
#endif

/* ALGO: */
#if 0
/* goal: cleanup KLIPS code from hardcoded algos :} */
#undef CONFIG_KLIPS_AUTH_HMAC_MD5
#undef CONFIG_KLIPS_AUTH_HMAC_SHA1
#undef CONFIG_KLIPS_ENC_3DES
#endif

#ifndef CONFIG_KLIPS_ALG
#define CONFIG_KLIPS_ALG 1
#endif

/* keep rhconfig.h from doing anything */
#define __rh_config_h__ 

/* pick which arch we are supposed to be */
#undef  __module__up
#define __module__smp
#define __module__i686
#define __module__i686_smp

#if defined(__module__smp) || defined(__module__BOOTsmp) || defined(__module__enterprise) || defined(__module__bigmem)
#define _ver_str(x) smp_ ## x
#else
#define _ver_str(x) x
#endif

#define RED_HAT_LINUX_KERNEL 1

#endif /* _CONFIG_RH_I686_SMP_H_ */

