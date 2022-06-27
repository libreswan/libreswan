/*
 * header file for Libreswan library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */
#ifndef _LIBRESWAN_H
#define _LIBRESWAN_H    /* seen it, no need to see it again */

#include "err.h"

#include <stdbool.h>

#include <sys/types.h>
#include <netinet/in.h>

/*
 * When using uclibc, malloc(0) returns NULL instead of success. This is
 * to make it use the inbuilt work-around.
 * See: http://osdir.com/ml/network.freeswan.devel/2003-11/msg00009.html
 */
#ifdef __UCLIBC__
# if !defined(__MALLOC_GLIBC_COMPAT__) && !defined(MALLOC_GLIBC_COMPAT)
#  warning Please compile uclibc with GLIBC_COMPATIBILITY defined
# endif
#endif

/* end of obsolete functions */

/* syntax for passthrough SA */
#ifndef PASSTHROUGHNAME
#define PASSTHROUGHNAME "%passthrough"
#define PASSTHROUGH4NAME        "%passthrough4"
#define PASSTHROUGH6NAME        "%passthrough6"
#define PASSTHROUGHIS   "tun0@0.0.0.0"
#define PASSTHROUGH4IS  "tun0@0.0.0.0"
#define PASSTHROUGH6IS  "tun0@::"
#define PASSTHROUGHTYPE "tun"
#define PASSTHROUGHSPI  0
#define PASSTHROUGHDST  0
#endif

#endif /* _LIBRESWAN_H */
