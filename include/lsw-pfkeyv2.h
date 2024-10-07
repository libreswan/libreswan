/* Wrapper for <net/pfkeyv2.h>, for libreswan
 *
 * Copyright (C) 2018-2022 Andrew Cagney
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

#ifndef LSW_PFKEYV2_H
#define LSW_PFKEYV2_H

#if defined(KERNEL_PFKEYV2)

/*
 * See: https://tools.ietf.org/html/rfc2367
 * See: https://datatracker.ietf.org/doc/html/draft-schilcher-mobike-pfkey-extension-01
 *
 * This header pulls in all the SADB_* macro and sadb_* struct
 * declarations described by RFC 2368 along with any extensions.
 *
 * But what about divergence?
 *
 * RFC 2367, 1.1 Terminology
 *
 *   In either case, the mandatory-to-implement, or MUST, items MUST
 *   be fully implemented as specified here.  If any mandatory item is
 *   not implemented as specified here, that implementation is not
 *   conforming and not compliant with this specification.
 *
 * RFC 2367, 1.7 Name Spaces:
 *
 *   Inclusion of the file <net/pfkeyv2.h> MUST NOT define symbols or
 *   structures in the PF_KEYv2 name space that are not described in
 *   this document without the explicit prior permission of the
 *   authors.  Any symbols or structures in the PF_KEYv2 name space
 *   that are not described in this document MUST start with "SADB_X_"
 *   or "sadb_x_".
 *
 * Things haven't exactly followed this so some tricks are used to
 * signal this to code using these headers:
 *
 * + implementations have replaced/renamed fields (typically reserved)
 * with new structure members.  When this happens a macro definition
 * of the new name is added.
 *
 * + implementations have (arrrg, and for no obvious reason) completely
 * rewritten some structures.  When this happens things are hacked so
 * that it looks like there's an sadb_x structure available.
 *
 * + implementations define SADB_X_EXT_* macro without defining /
 * using the corresponding sadb_x_ext_* structure.  When this happens
 * the SADB_X_EXT_* macro is undefined.
 */

#ifdef __linux__
# include <stdint.h>
# include <linux/pfkeyv2.h>
#else
# include <sys/types.h>
# include <net/pfkeyv2.h>
#endif

/*
 * OpenBSD's ipsec-interface uses IPSP_DIRECTION_{IN,OUT}, which is
 * hidden in <netinet/ip_ipsp.h>, to specify the interface's direction
 * in the sadb_x_ext_iface payload.  Why it didn't use values from
 * PFKEY I don't know.
 */
#ifdef __OpenBSD__
#include <sys/socket.h>
#include <netinet/ip_ipsp.h>
#endif

/*
 * Work-around OpenBSD which defines SADB_X_EXT_SA2 but not struct
 * sadb_x_sa2 (it doesn't even use that structure).
 */

#ifdef __OpenBSD__
# ifdef SADB_X_EXT_SA2
#  if SADB_X_EXT_SA2 != 23
#   error confused
#  endif
#  undef SADB_X_EXT_SA2
# endif
#endif

/*
 * Work-around OpenBSD which completely re-defined struct
 * sadb_x_policy: the fields are not the same; the way it is used is
 * not the same.
 */

#ifdef __OpenBSD__
# ifdef SADB_X_EXT_POLICY
#  if SADB_X_EXT_POLICY != 25
#   error confused
#  endif
#  undef SADB_X_EXT_POLICY
# endif
#endif

/*
 * Work-around OpenBSD gutting struct sadb_address:
 *
 * -> dropped sadb_address_proto
 * -> dropped sadb_address_prefixlen
 *
 * XXX: But why?  Since OpenBSD uses address+mask and not
 * address/prefixlen when specifying child selectors, I'm guessing
 * that the extra seemingly unused fields were simply dropped.
 *
 * The thing is that, even at the time, code was starting to use
 * /prefixlen, and IKEv2 introduced start-end.  The IKEv1 mask was on
 * the way out!
 *
 * The thing is that, even at the time, IKE daemons were using UDP and
 * non-standard ports.  Things this change seems to prohibit.
 */

#ifndef __OpenBSD__
#define sadb_address_prefixlen sadb_address_prefixlen
#define sadb_address_proto sadb_address_proto
#endif

/*
 * Work-around various OSs reusing / renaming fields of existing
 * structures.
 *
 * Use the macro expands to itself hack.
 */

/*
 * struct sadb_x_policy
 *     .sadb_x_policy_reserved
 */

#ifdef __NetBSD__
# ifdef IPSEC_POLICY_FLAG_ORIGIN_KERNEL
#  define sadb_x_policy_flags sadb_x_policy_flags	/* was sadb_x_policy_reserved */
# endif
#endif

#ifdef __FreeBSD__
# define sadb_x_policy_scope sadb_x_policy_scope	/* was sadb_x_policy_reserved */
#endif

/*
 * struct sadb_x_policy
 *    .sadb_x_policy_reserved2
 */

#ifdef __linux__
# define sadb_x_policy_priority sadb_x_policy_priority /* was sadb_x_policy_reserved2 */
#endif

#ifdef __FreeBSD__
/* define sadb_x_policy_ifindex == sadb_x_policy_priority */
# define sadb_x_policy_priority sadb_x_policy_priority	/* was sadb_x_policy_reserved2 */
#endif

/*
 * struct sadb_prop
 *     .sadb_prop_reserved
 */

#ifdef __OpenBSD__
# define sadb_prop_num sadb_prop_num	/* was sadb_prop_reserved */
#endif

/*
 * struct sadb_x_ipsecrequest
 *     .sadb_x_ipsecrequest_reserved1
 *     .sadb_x_ipsecrequest_reserved2
 */

#ifdef __linux__
/* sadb_x_ipsecrequest_reqid is 32-bits not 16-bits; these align it */
# define sadb_x_ipsecrequest_reserved1 sadb_x_ipsecrequest_reserved1
# define sadb_x_ipsecrequest_reserved2 sadb_x_ipsecrequest_reserved2
#endif

#endif /* KERNEL_PFKEYV2 */
#endif
