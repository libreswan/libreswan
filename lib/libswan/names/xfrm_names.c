
/* tables of names for values defined in constants.h
 *
 * Copyright (C) 2022 Andrew Cagney
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

/*
 * GRRR:
 *
 * GLIBC/Linux and MUSL/Linux define sockaddr_in et.al. in
 * <netinet/in.h>, and the generic network code uses this.
 * Unfortunately (cough) the Linux kernel headers also provide
 * definitions of those structures in <linux/in.h> et.al. which,
 * depending on header include order can result in conflicting
 * definitions.  For instance, if sockaddr_in is not defined,
 * <linux/xfrm.h> will include the definition in <linux/in.h> but that
 * will then clash with a later include of <netinet/in.h>.
 *
 * GLIBC/Linux has hacks on hacks to work-around this, not MUSL.
 * Fortunately, including <netinet/in.h> first will force the Linux
 * kernel headers to use that definition.
 *
 * XXX: here this is overkill as there is no convoluted include
 * arrangement.
 */

#include <netinet/in.h>

#include "linux/xfrm.h"		/* local (if configured) or system copy */

#include <linux/rtnetlink.h>

#include "xfrm_names.h"

#include "lswcdefs.h"		/* for ARRAY_PTR() */
#include "enum_names.h"
#include "sparse_names.h"

/* XFRM POLICY direction names */

static const char *const xfrm_policy_name[] = {
#define S(E) [E] = #E
	S(XFRM_POLICY_IN),
	S(XFRM_POLICY_OUT),
	S(XFRM_POLICY_FWD),
#undef S
};

const struct enum_names xfrm_policy_names = {
	XFRM_POLICY_IN, XFRM_POLICY_FWD,
	ARRAY_PTR(xfrm_policy_name),
	"XFRM_POLICY_", /* prefix */
	NULL
};

#define NE(x) { .name = #x, .value = x, }	/* Name Entry -- shorthand for sparse_names */

const struct sparse_names xfrm_type_names = {
	.list = {
		NE(NLMSG_NOOP),
		NE(NLMSG_ERROR),
		NE(NLMSG_DONE),
		NE(NLMSG_OVERRUN),

		NE(XFRM_MSG_NEWSA),
		NE(XFRM_MSG_DELSA),
		NE(XFRM_MSG_GETSA),

		NE(XFRM_MSG_NEWPOLICY),
		NE(XFRM_MSG_DELPOLICY),
		NE(XFRM_MSG_GETPOLICY),

		NE(XFRM_MSG_ALLOCSPI),
		NE(XFRM_MSG_ACQUIRE),
		NE(XFRM_MSG_EXPIRE),

		NE(XFRM_MSG_UPDPOLICY),
		NE(XFRM_MSG_UPDSA),

		NE(XFRM_MSG_POLEXPIRE),

		NE(XFRM_MSG_FLUSHSA),
		NE(XFRM_MSG_FLUSHPOLICY),

		NE(XFRM_MSG_BASE),
		NE(XFRM_MSG_MAX),

		SPARSE_NULL
	},
};

const struct sparse_names rtm_type_names = {
	.list = {

		NE(RTM_NEWLINK),
		NE(RTM_NEWLINK),
		NE(RTM_GETLINK),
		NE(RTM_SETLINK),

		NE(RTM_NEWADDR),
		NE(RTM_DELADDR),
		NE(RTM_GETADDR),

		NE(RTM_NEWLINK),
		NE(RTM_DELLINK),
		NE(RTM_GETLINK),

		NE(RTM_NEWROUTE),
		NE(RTM_DELROUTE),
		NE(RTM_GETROUTE),

		NE(RTM_NEWNEIGH),
		NE(RTM_DELNEIGH),
		NE(RTM_GETNEIGH),

		NE(RTM_NEWRULE),
		NE(RTM_DELRULE),
		NE(RTM_GETRULE),

		/* and many more */

		NE(RTM_BASE),
		NE(RTM_MAX),

		SPARSE_NULL
	},
};
#undef NE
