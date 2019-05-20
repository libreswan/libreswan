/* pf_key debugging facility
 * definitions: linux/net/ipsec/pfkey_v2_parse.c, lib/libbsdpfkey/pfkey.c
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003  Michael Richardson <mcr@freeswan.org>
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
 */

#ifndef _FREESWAN_PFKEY_DEBUG_H
#define _FREESWAN_PFKEY_DEBUG_H

#include "lswlog.h"

/*
 * Debugging levels for pfkey_lib_debug
 */
#define PF_KEY_DEBUG_PARSE_NONE    0
#define PF_KEY_DEBUG_PARSE_PROBLEM 1
#define PF_KEY_DEBUG_PARSE_STRUCT  2
#define PF_KEY_DEBUG_PARSE_FLOW    4
#define PF_KEY_DEBUG_BUILD         8
#define PF_KEY_DEBUG_PARSE_MAX    15

#define DEBUGGING(level, args ...) dbg(args)

#define ERROR(args ...)      libreswan_log("pfkey_lib_debug:" args)

# define MALLOC(size) malloc(size)
# define FREE(obj) free(obj)

#endif
