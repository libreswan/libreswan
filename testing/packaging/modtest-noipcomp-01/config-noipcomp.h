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
 *
 * RCSID $Id: config-noipcomp.h,v 1.4 2003/03/14 08:09:26 rgb Exp $
 */
#define	_CONFIG_ALL_H_	/* seen it, no need to see it again */

#define CONFIG_IPSEC 1

#ifndef CONFIG_IPSEC_AH
#define CONFIG_IPSEC_AH
#endif

#ifndef CONFIG_IPSEC_DEBUG 
#define CONFIG_IPSEC_DEBUG
#endif

#ifndef CONFIG_IPSEC_ESP
#define CONFIG_IPSEC_ESP
#endif

#ifdef CONFIG_IPSEC_IPCOMP
#undef CONFIG_IPSEC_IPCOMP
#endif

#ifndef CONFIG_IPSEC_IPIP
#define CONFIG_IPSEC_IPIP
#endif

#ifndef CONFIG_IPSEC_AUTH_HMAC_MD5
#define CONFIG_IPSEC_AUTH_HMAC_MD5
#endif

#ifndef CONFIG_IPSEC_AUTH_HMAC_SHA1
#define CONFIG_IPSEC_AUTH_HMAC_SHA1
#endif 

#ifndef CONFIG_IPSEC_DYNDEV
#define CONFIG_IPSEC_DYNDEV 1
#endif

#ifndef CONFIG_IPSEC_ENC_3DES
#define CONFIG_IPSEC_ENC_3DES
#endif

#ifdef CONFIG_IPSEC_REGRESS
#undef CONFIG_IPSEC_REGRESS
#endif


#endif /* _CONFIG_ALL_H */
