#ifndef _CONFIG_ALL_H_
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
 */

#define _CONFIG_ALL_H_  /* seen it, no need to see it again */

#define CONFIG_IPSEC 1

#ifndef CONFIG_IPSEC_AH
#define CONFIG_IPSEC_AH 1
#endif

#ifndef CONFIG_IPSEC_DEBUG
#define CONFIG_IPSEC_DEBUG 1
#endif

#ifndef CONFIG_KLIPS_ESP
#define CONFIG_KLIPS_ESP 1
#endif

#ifdef CONFIG_KLIPS_IPCOMP
#define CONFIG_KLIPS_IPCOMP 1
#endif

#ifndef CONFIG_KLIPS_IPIP
#define CONFIG_KLIPS_IPIP 1
#endif

#define CONFIG_KLIPS_AUTH_HMAC_MD5 1
#define CONFIG_KLIPS_AUTH_HMAC_SHA1 1

#ifndef CONFIG_KLIPS_DYNDEV
#define CONFIG_KLIPS_DYNDEV 1
#endif

#define CONFIG_KLIPS_ALG 1
#undef CONFIG_KLIPS_ENC_3DES
#undef CONFIG_KLIPS_ENC_AES
#define CONFIG_KLIPS_ENC_CRYPTOAPI 1
#define CONFIG_KLIPS_ENC_1DES 1

#ifdef CONFIG_KLIPS_REGRESS
#undef CONFIG_KLIPS_REGRESS
#endif

#endif /* _CONFIG_ALL_H */
