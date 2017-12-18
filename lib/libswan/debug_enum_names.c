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

#include "constants.h"
#include "enum_names.h"
#include "lmod.h"

/*
 * See plutomain.c for what the extra "\0" is all about (hint it is a
 * hack for encoding what to do with flags).
 */

#define D(N,A) [N##_IX] = LELEM(N##_IX) == N ? A "\0" : NULL

static const char *debug_strings[] = {
	D(DBG_RAW, "debug-raw"),
	D(DBG_CRYPT, "debug-crypt"),
	D(DBG_PARSING, "debug-parsing"),
	D(DBG_EMITTING, "debug-emitting"),
	D(DBG_CONTROL, "debug-control"),
	D(DBG_LIFECYCLE, "debug-lifecycle"),
	D(DBG_KERNEL, "debug-kernel"),
	D(DBG_DNS, "debug-dns"),
	D(DBG_OPPO, "debug-oppo"),
	D(DBG_CONTROLMORE, "debug-controlmore"),
	D(DBG_PFKEY, "debug-pfkey"),
	D(DBG_NATT, "debug-nattraversal"),
	D(DBG_X509, "debug-x509"),
	D(DBG_DPD, "debug-dpd"),
	D(DBG_XAUTH, "debug-xauth"),
	D(DBG_RETRANSMITS, "debug-retransmits"),
	D(DBG_OPPOINFO, "debug-oppoinfo"),
	D(DBG_WHACKWATCH, "debug-whackwatch"),
	D(DBG_PRIVATE, "debug-private"),
	D(DBG_ADD_PREFIX, "debug-add-prefix"),
};

const struct enum_names debug_names = {
	DBG_floor_IX, DBG_roof_IX - 1,
	ARRAY_REF(debug_strings),
	"debug-",
	NULL,
};

struct lmod_compat debug_compat[] = {
       { "klips",    DBG_KERNEL },
       { "netkey",    DBG_KERNEL },
       { NULL, LEMPTY, },
};

const struct lmod_info debug_lmod_info = {
	.names = &debug_names,
	.all = DBG_ALL,
	.mask = DBG_MASK,
	.compat = debug_compat,
};

#define I(N,A) [N##_IX - DBG_roof_IX] = LELEM(N##_IX) == N ? A "\0" : NULL

static const char *impair_strings[] = {
	I(IMPAIR_BUST_MI2, "impair-bust-mi2"),
	I(IMPAIR_BUST_MR2, "impair-bust-mr2"),
	I(IMPAIR_DROP_I2, "impair-drop-i2"),
	I(IMPAIR_SA_CREATION, "impair-sa-creation"),
	I(IMPAIR_DIE_ONINFO, "impair-die-oninfo"),
	I(IMPAIR_JACOB_TWO_TWO, "impair-jacob-two-two"),
	I(IMPAIR_ALLOW_NULL_NULL, "impair-allow-null-null"),
	I(IMPAIR_MAJOR_VERSION_BUMP, "impair-major-version-bump"),
	I(IMPAIR_MINOR_VERSION_BUMP, "impair-minor-version-bump"),
	I(IMPAIR_RETRANSMITS, "impair-retransmits"),
	I(IMPAIR_SEND_NO_RETRANSMITS, "impair-send-no-retransmits"),
	I(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG, "impair-send-bogus-payload-flag"),
	I(IMPAIR_SEND_BOGUS_ISAKMP_FLAG, "impair-send-bogus-isakmp-flag"),
	I(IMPAIR_SEND_IKEv2_KE, "impair-send-ikev2-ke"),
	I(IMPAIR_SEND_NO_DELETE, "impair-send-no-delete"),
	I(IMPAIR_SEND_NO_IKEV2_AUTH, "impair-send-no-ikev2-auth"),
	I(IMPAIR_SEND_NO_XAUTH_R0, "impair-send-no-xauth-r0"),
	I(IMPAIR_DROP_XAUTH_R0, "impair-drop-xauth-r0"),
	I(IMPAIR_SEND_NO_MAIN_R2, "impair-send-no-main-r2"),
	I(IMPAIR_FORCE_FIPS, "impair-force-fips"),
	I(IMPAIR_SEND_KEY_SIZE_CHECK, "impair-send-key-size-check"),
	I(IMPAIR_SEND_ZERO_GX, "impair-send-zero-gx"),
	I(IMPAIR_SEND_BOGUS_DCOOKIE, "impair-send-bogus-dcookie"),
	I(IMPAIR_OMIT_HASH_NOTIFY_REQUEST, "impair-omit-hash-notify"),
	I(IMPAIR_IGNORE_HASH_NOTIFY_REQUEST, "impair-ignore-hash-notify"),
	I(IMPAIR_IGNORE_HASH_NOTIFY_RESPONSE, "impair-ignore-hash-notify-resp"),
	I(IMPAIR_IKEv2_EXCLUDE_INTEG_NONE, "impair-ikev2-exclude-integ-none"),
	I(IMPAIR_IKEv2_INCLUDE_INTEG_NONE, "impair-ikev2-include-integ-none"),
	I(IMPAIR_REPLAY_DUPLICATES, "impair-replay-duplicates"),
	I(IMPAIR_REPLAY_FORWARD, "impair-replay-forward"),
	I(IMPAIR_REPLAY_BACKWARD, "impair-replay-backward"),
};

const struct enum_names impair_names = {
	IMPAIR_floor_IX, IMPAIR_roof_IX - 1,
	ARRAY_REF(impair_strings),
	"impair-",
	NULL,
};

const struct lmod_info impair_lmod_info = {
	.names = &impair_names,
	.all = IMPAIR_MASK,
	.mask = IMPAIR_MASK,
};

const struct enum_names debug_and_impair_names = {
	DBG_floor_IX, DBG_roof_IX - 1,
	ARRAY_REF(debug_strings),
	/*
	 * For this enum_names, "short" names will always use the
	 * "debug-" prefix.  The "impair-" prefix in impair_names will
	 * be ignored.
	 */
	"debug-",
	&impair_names,
};
