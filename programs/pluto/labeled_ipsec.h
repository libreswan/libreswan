/* Labeled IPSec
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef _LABELED_IPSEC_H
#define _LABELED_IPSEC_H

#ifdef HAVE_LABELED_IPSEC

/*
 * Security Label Context representations.
 */

/*
 * Length of text of security label should not exceed 256 in most cases,
 * (discussed with kernel and selinux people). ??? "in most cases"!
 * We add one for terminating '\0'.  ??? superstition or guarantee?
 */
#define MAX_SECCTX_LEN 257	/* including '\0'*/

/*
 * sec_ctx: representation in IKE packets, excluding text.
 *
 * See linux26/xfrm.h's struct xfrm_sec_ctx and struct xfrm_user_sec_ctx.
 * For some unexplained reason the fields of those structs are in a different order!
 * We use the order of xfrm_sec_ctx.
 *
 * Must be kept in sync with packet.c's sec_ctx_desc.
 */

struct sec_ctx {
	u_int8_t ctx_doi;
	u_int8_t ctx_alg;	/* LSMs: e.g., selinux == 1 */
	u_int16_t ctx_len;	/* of text label */
};

/*
 * xfrm_user_sec_ctx_ike: representation within struct state.
 * Also passed around between Pluto functions.
 */
struct xfrm_user_sec_ctx_ike {
	struct sec_ctx ctx;
	char sec_ctx_value[MAX_SECCTX_LEN];	/* text label, NUL-terminated */
};

#endif

#endif
