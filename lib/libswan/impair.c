/* impair constants, for libreswan
 *
 * Copyright (C) 2017-2018 Andrew Cagney
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

#define I(N,A) [N##_IX - DBG_roof_IX] = LELEM(N##_IX) == N ? A "\0" : NULL

static const char *impair_name_strings[IMPAIR_roof_IX - IMPAIR_floor_IX] = {
	I(IMPAIR_BUST_MI2, "impair-bust-mi2"),
	I(IMPAIR_BUST_MR2, "impair-bust-mr2"),
	I(IMPAIR_DROP_I2, "impair-drop-i2"),
	I(IMPAIR_SA_CREATION, "impair-sa-creation"),
	I(IMPAIR_JACOB_TWO_TWO, "impair-jacob-two-two"),
	I(IMPAIR_ALLOW_NULL_NONE, "impair-allow-null-none"),
	I(IMPAIR_MAJOR_VERSION_BUMP, "impair-major-version-bump"),
	I(IMPAIR_MINOR_VERSION_BUMP, "impair-minor-version-bump"),
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

	I(IMPAIR_RETRANSMITS, "impair-retransmits"),
	I(IMPAIR_TIMEOUT_ON_RETRANSMIT, "impair-timeout-on-retransmit"),
	I(IMPAIR_DELETE_ON_RETRANSMIT, "impair-delete-on-retransmit"),
	I(IMPAIR_SUPPRESS_RETRANSMITS, "impair-suppress-retransmits"),

	I(IMPAIR_REPLAY_DUPLICATES, "impair-replay-duplicates"),
	I(IMPAIR_REPLAY_FORWARD, "impair-replay-forward"),
	I(IMPAIR_REPLAY_BACKWARD, "impair-replay-backward"),

	I(IMPAIR_REPLAY_ENCRYPTED, "impair-replay-encrypted"),
	I(IMPAIR_CORRUPT_ENCRYPTED, "impair-corrupt-encrypted"),

	I(IMPAIR_PROPOSAL_PARSER, "impair-proposal-parser"),

	I(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_SA_INIT, "impair-add-unknown-payload-to-sa-init"),
	I(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH, "impair-add-unknown-payload-to-auth"),
	I(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK, "impair-add-unknown-payload-to-auth-sk"),
	I(IMPAIR_UNKNOWN_PAYLOAD_CRITICAL, "impair-unknown-payload-critical"),

	I(IMPAIR_ALLOW_DNS_INSECURE, "impair-allow-dns-insecure"),

	I(IMPAIR_SEND_PKCS7_THINGIE, "impair-send-pkcs7-thingie"),
};

const enum_names impair_names = {
	IMPAIR_floor_IX, IMPAIR_roof_IX - 1,
	ARRAY_REF(impair_name_strings),
	"impair-",
	NULL,
};

const struct lmod_info impair_lmod_info = {
	.names = &impair_names,
	.all = IMPAIR_MASK,
	.mask = IMPAIR_MASK,
};

const char *const impair_help_strings[IMPAIR_roof_IX - IMPAIR_floor_IX] = {

	I(IMPAIR_BUST_MI2, "MAKE MI2 REALLY LARGE"),
	I(IMPAIR_BUST_MR2, "make MR2 really large"),
	I(IMPAIR_DROP_I2, "drop second initiator packet"),
	I(IMPAIR_SA_CREATION, "fail all SA creation"),
	I(IMPAIR_JACOB_TWO_TWO, "cause pluto to send all messages twice."),

	I(IMPAIR_ALLOW_NULL_NONE, "cause pluto to allow esp=null-none and ah=none for testing"),
	I(IMPAIR_MAJOR_VERSION_BUMP, "cause pluto to send an IKE major version that's higher then we support."),
	I(IMPAIR_MINOR_VERSION_BUMP, "cause pluto to send an IKE minor version that's higher then we support."),

	I(IMPAIR_RETRANSMITS, "causes pluto to timeout on first retransmit"),
	I(IMPAIR_TIMEOUT_ON_RETRANSMIT, "causes pluto to 'retry' (switch protocol) on the first retransmit"),
	I(IMPAIR_DELETE_ON_RETRANSMIT, "causes pluto to fail on the first retransmit"),
	I(IMPAIR_SUPPRESS_RETRANSMITS, "causes pluto to never send retransmits (wait the full timeout)"),

	I(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG, "causes pluto to set a RESERVED PAYLOAD flag to test ignoring/zeroing it"),
	I(IMPAIR_SEND_BOGUS_ISAKMP_FLAG, "causes pluto to set a RESERVED ISAKMP flag to test ignoring/zeroing it"),
	I(IMPAIR_SEND_IKEv2_KE, "causes pluto to omit sending the KE payload in IKEv2"),
	I(IMPAIR_SEND_NO_DELETE, "causes pluto to omit sending Notify/Delete messages"),
	I(IMPAIR_SEND_NO_IKEV2_AUTH, "causes pluto to omit sending an IKEv2 IKE_AUTH packet"),
	I(IMPAIR_SEND_NO_XAUTH_R0, "causes pluto to omit sending an XAUTH user/passwd request"),
	I(IMPAIR_DROP_XAUTH_R0, "causes pluto to drop an XAUTH user/passwd request on IKE initiator"),
	I(IMPAIR_SEND_NO_MAIN_R2, "causes pluto to omit sending an last Main Mode response packet"),
	I(IMPAIR_FORCE_FIPS, "causes pluto to believe we are in fips mode, NSS needs its own hack"),
	I(IMPAIR_SEND_KEY_SIZE_CHECK, "causes pluto to omit checking configured ESP key sizes for testing"),
	I(IMPAIR_SEND_ZERO_GX, "causes pluto to send a g^x that is zero, breaking DH calculation"),
	I(IMPAIR_SEND_BOGUS_DCOOKIE, "causes pluto to send a a bogus IKEv2 DCOOKIE"),
	I(IMPAIR_OMIT_HASH_NOTIFY_REQUEST, "causes pluto to omit sending hash notify in IKE_SA_INIT Request"),
	I(IMPAIR_IGNORE_HASH_NOTIFY_REQUEST, "causes pluto to ignore incoming hash notify from IKE_SA_INIT Request"),
	I(IMPAIR_IGNORE_HASH_NOTIFY_RESPONSE, "causes pluto to ignore incoming hash notify from IKE_SA_INIT Response"),
	I(IMPAIR_IKEv2_EXCLUDE_INTEG_NONE, "lets pluto exclude integrity 'none' in proposals"),
	I(IMPAIR_IKEv2_INCLUDE_INTEG_NONE, "lets pluto include integrity 'none' in proposals"),

	I(IMPAIR_REPLAY_DUPLICATES, "replay duplicates of each incoming packet"),
	I(IMPAIR_REPLAY_FORWARD, "replay all earlier packets old-to-new"),
	I(IMPAIR_REPLAY_BACKWARD, "replay all earlier packets new-to-old"),

	I(IMPAIR_REPLAY_ENCRYPTED, "replay encrypted packets"),
	I(IMPAIR_CORRUPT_ENCRYPTED, "corrupts the encrypted packet so that the decryption fails"),

	I(IMPAIR_PROPOSAL_PARSER, "impair algorithm parser - what you see is what you get"),

	I(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_SA_INIT, "add a payload with an unknown type to SA_INIT"),
	I(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH, "add a payload with an unknown type to AUTH"),
	I(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK, "add a payload with an unknown type to AUTH's SK payload"),
	I(IMPAIR_UNKNOWN_PAYLOAD_CRITICAL, "mark the unknown payload as critical"),

	I(IMPAIR_ALLOW_DNS_INSECURE, "allow IPSECKEY lookups without DNSSEC protection"),

	I(IMPAIR_SEND_PKCS7_THINGIE, "send certificates as a PKCS7 thingie"),
};

const struct enum_names impair_help = {
	IMPAIR_floor_IX, IMPAIR_roof_IX - 1,
	ARRAY_REF(impair_help_strings),
	NULL, NULL,
};
