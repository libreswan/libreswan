/*
 * internal definitions for use within the library; do not export!
 * Copyright (C) 1998, 1999  Henry Spencer.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */

#ifndef ABITS
#define ABITS   32      /* bits in an IPv4 address */
#endif

/* case-independent ASCII character equality comparison */
#define CIEQ(c1, c2)    ( ((c1) & ~040) == ((c2) & ~040) )

/*
 * Headers, greatly complicated by stupid and unnecessary inconsistencies
 * between the user environment and the kernel environment.  These are done
 * here so that this mess need exist in only one place.
 *
 * It may seem like a -I or two could avoid most of this, but on closer
 * inspection it is not quite that easy.
 */

/* things that need to come from one place or the other, depending */
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/string.h>
#include <linux/ctype.h>
#define assert(foo)     /* nothing */
#else
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#endif

/* things that exist only in userland */
#ifndef __KERNEL__

/* You'd think this would be okay in the kernel too -- it's just a */
/* bunch of constants -- but no, in RH5.1 it screws up other things. */
/* (Credit:  Mike Warfield tracked this problem down.  Thanks Mike!) */
/* Fortunately, we don't need it in the kernel subset of the library. */
#include <limits.h>

/* header files for things that should never be called in kernel */
#include <netdb.h>

/* memory allocation, currently user-only, macro-ized just in case */
#include <stdlib.h>
#define MALLOC(n)       malloc(n)
#define FREE(p)         free(p)

#endif /* __KERNEL__ */

