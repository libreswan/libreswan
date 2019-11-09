/* byte-order stuff
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
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

/* sets BYTE_ORDER, LITTLE_ENDIAN, and BIG_ENDIAN */

#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__FreeBSD__)
# include <machine/endian.h>
#elif defined(linux)
# if defined(i386) && !defined(__i386__)
#  define __i386__ 1
#  define MYHACKFORTHIS 1
# endif
# include <endian.h>
# if 0	/* kernel's <asm/byteorder.h> clashes with glibc's <netinet/in.h> */
/* The problem (in RedHat 5.0) is the typing of the "longs" (32-bit values)
 * in the [nh]to[hn]l functions:
 * - <asm/byteorder.h> uses unsigned long
 * - <netinet/in.h> uses uint32_t which is unsigned int
 * Since 64-bit machines are supported, <asm/byteorder.h> should be changed.
 * For now, we simply don't use <asm/byteorder.h>.
 */
#  include <asm/byteorder.h>
# endif
# ifdef MYHACKFORTHIS
#  undef __i386__
#  undef MYHACKFORTHIS
# endif
#elif !(defined(BIG_ENDIAN) && defined(LITTLE_ENDIAN) && defined(BYTE_ORDER))
/* we don't know how to do this, so we require the macros to be defined
 * with compiler flags:
 *    -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=BIG_ENDIAN
 * or -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=LITTLE_ENDIAN
 * Thse match the GNU definitions
 */
# include <sys/endian.h>
#endif

#ifndef BIG_ENDIAN
# error BIG_ENDIAN must be defined
#endif

#ifndef LITTLE_ENDIAN
# error LITTLE_ENDIAN must be defined
#endif

#ifndef BYTE_ORDER
# error BYTE_ORDER must be defined
#endif
