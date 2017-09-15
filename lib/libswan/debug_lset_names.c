/* debug set constants, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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

#include <stddef.h>

#include "lset_names.h"

/*
 * See plutomain.c for what the extra "\0" is all about (hint it is a
 * hack for encoding what to do with flags).
 */

#define I(N,A) [N##_IX] = {			\
		.name = #N,			\
		.flag = A "\0",			\
		.lelem = N,			\
	}

const struct lset_names debug_lset_names = {
	.strip = "debug-",
	.roof = IMPAIR_roof_IX,
	.lelems = {
		I(DBG_RAW, "debug-raw"),
		I(DBG_CRYPT, "debug-crypt"),
		I(DBG_PARSING, "debug-parsing"),
		I(DBG_EMITTING, "debug-emitting"),
		I(DBG_CONTROL, "debug-control"),
		I(DBG_LIFECYCLE, "debug-lifecycle"),
		I(DBG_KERNEL, "debug-kernel"),
		I(DBG_DNS, "debug-dns"),
		I(DBG_OPPO, "debug-oppo"),
		I(DBG_CONTROLMORE, "debug-controlmore"),
		I(DBG_PFKEY, "debug-pfkey"),
		I(DBG_NATT, "debug-nattraversal"),
		I(DBG_X509, "debug-x509"),
		I(DBG_DPD, "debug-dpd"),
		I(DBG_OPPOINFO, "debug-oppoinfo"),
		I(DBG_WHACKWATCH, "debug-whackwatch"),
		I(DBG_PRIVATE, "debug-private"),
		I(IMPAIR_BUST_MI2, "impair-bust-mi2"),
		I(IMPAIR_BUST_MR2, "impair-bust-mr2"),
		I(IMPAIR_SA_CREATION, "impair-sa-creation"),
		I(IMPAIR_DIE_ONINFO, "impair-die-oninfo"),
		I(IMPAIR_JACOB_TWO_TWO, "impair-jacob-two-two"),
		I(IMPAIR_ALLOW_NULL_NULL, "impair-allow-null-null"),
		I(IMPAIR_MAJOR_VERSION_BUMP, "impair-major-version-bump"),
		I(IMPAIR_MINOR_VERSION_BUMP, "impair-minor-version-bump"),
		I(IMPAIR_RETRANSMITS, "impair-retransmits"),
		I(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG, "impair-send-bogus-payload-flag"),
		I(IMPAIR_SEND_BOGUS_ISAKMP_FLAG, "impair-send-bogus-isakmp-flag"),
		I(IMPAIR_SEND_IKEv2_KE, "impair-send-ikev2-ke"),
		I(IMPAIR_SEND_NO_DELETE, "impair-send-no-delete"),
		I(IMPAIR_SEND_NO_IKEV2_AUTH, "impair-send-no-ikev2-auth"),
		I(IMPAIR_SEND_NO_XAUTH_R0, "impair-send-no-xauth-r0"),
		I(IMPAIR_SEND_NO_MAIN_R2, "impair-send-no-main-r2"),
		I(IMPAIR_FORCE_FIPS, "impair-force-fips"),
		I(IMPAIR_SEND_KEY_SIZE_CHECK, "impair-send-key-size-check"),
		I(IMPAIR_SEND_ZERO_GX, "impair-send-zero-gx"),
		I(IMPAIR_SEND_BOGUS_DCOOKIE, "impair-send-bogus-dcookie"),
		I(IMPAIR_OMIT_HASH_NOTIFY_REQUEST, "impair-omit-hash-notify"),
		I(IMPAIR_IGNORE_HASH_NOTIFY_REQUEST, "impair-ignore-hash-notify"),
		I(IMPAIR_IGNORE_HASH_NOTIFY_RESPONSE, "impair-ignore-hash-notify-resp"),
		[IMPAIR_roof_IX] = SENTINEL_LELEM_NAME,
	},
};
