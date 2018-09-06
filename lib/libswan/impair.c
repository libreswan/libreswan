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
 * Initialize both the .name and .help arrays.
 *
 * See plutomain.c why the name has an extra "\0" appended (hint it is
 * a hack for encoding what to do with flags).
 *
 * XXX: since only the --impair ... form is supported, has this all
 * become redundant.
 *
 * So that grepping for IMPAIR.<name> finds this file, the N parameter
 * is the full enum name (IMPAIR_...) and not just the truncated
 * suffix.
 */

struct double_double {
	const char *name[IMPAIR_roof_IX - IMPAIR_floor_IX];
	const char *help[IMPAIR_roof_IX - IMPAIR_floor_IX];
};

static struct double_double impair = {

#define S(N,A,H)							\
	.name[N##_IX - IMPAIR_floor_IX] = A "\0", \
	.help[N##_IX - IMPAIR_floor_IX] = H

       S(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH, "impair-add-unknown-payload-to-auth", "add a payload with an unknown type to AUTH"),
       S(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK, "impair-add-unknown-payload-to-auth-sk", "add a payload with an unknown type to AUTH's SK payload"),
       S(IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_SA_INIT, "impair-add-unknown-payload-to-sa-init", "add a payload with an unknown type to SA_INIT"),
       S(IMPAIR_ALLOW_DNS_INSECURE, "impair-allow-dns-insecure", "allow IPSECKEY lookups without DNSSEC protection"),
       S(IMPAIR_ALLOW_NULL_NONE, "impair-allow-null-none", "cause pluto to allow esp=null-none and ah=none for testing"),
       S(IMPAIR_BUST_MI2, "impair-bust-mi2", "make MI2 really large"),
       S(IMPAIR_BUST_MR2, "impair-bust-mr2", "make MR2 really large"),
       S(IMPAIR_CORRUPT_ENCRYPTED, "impair-corrupt-encrypted", "corrupts the encrypted packet so that the decryption fails"),
       S(IMPAIR_DELETE_ON_RETRANSMIT, "impair-delete-on-retransmit", "causes pluto to fail on the first retransmit"),
       S(IMPAIR_DROP_I2, "impair-drop-i2", "drop second initiator packet"),
       S(IMPAIR_DROP_XAUTH_R0, "impair-drop-xauth-r0", "causes pluto to drop an XAUTH user/passwd request on IKE initiator"),
       S(IMPAIR_FORCE_FIPS, "impair-force-fips", "causes pluto to believe we are in fips mode, NSS needs its own hack"),
       S(IMPAIR_IGNORE_HASH_NOTIFY_REQUEST, "impair-ignore-hash-notify", "causes pluto to ignore incoming hash notify from IKE_SA_INIT Request"),
       S(IMPAIR_IGNORE_HASH_NOTIFY_RESPONSE, "impair-ignore-hash-notify-resp", "causes pluto to ignore incoming hash notify from IKE_SA_INIT Response"),
       S(IMPAIR_IKEv2_EXCLUDE_INTEG_NONE, "impair-ikev2-exclude-integ-none", "lets pluto exclude integrity 'none' in proposals"),
       S(IMPAIR_IKEv2_INCLUDE_INTEG_NONE, "impair-ikev2-include-integ-none", "lets pluto include integrity 'none' in proposals"),
       S(IMPAIR_JACOB_TWO_TWO, "impair-jacob-two-two", "cause pluto to send all messages twice."),
       S(IMPAIR_MAJOR_VERSION_BUMP, "impair-major-version-bump", "cause pluto to send an IKE major version that's higher then we support."),
       S(IMPAIR_MINOR_VERSION_BUMP, "impair-minor-version-bump", "cause pluto to send an IKE minor version that's higher then we support."),
       S(IMPAIR_OMIT_HASH_NOTIFY_REQUEST, "impair-omit-hash-notify", "causes pluto to omit sending hash notify in IKE_SA_INIT Request"),
       S(IMPAIR_PROPOSAL_PARSER, "impair-proposal-parser", "impair algorithm parser - what you see is what you get"),
       S(IMPAIR_REPLAY_BACKWARD, "impair-replay-backward", "replay all earlier packets new-to-old"),
       S(IMPAIR_REPLAY_DUPLICATES, "impair-replay-duplicates", "replay duplicates of each incoming packet"),
       S(IMPAIR_REPLAY_ENCRYPTED, "impair-replay-encrypted", "replay encrypted packets"),
       S(IMPAIR_REPLAY_FORWARD, "impair-replay-forward", "replay all earlier packets old-to-new"),
       S(IMPAIR_RETRANSMITS, "impair-retransmits", "causes pluto to timeout on first retransmit"),
       S(IMPAIR_SA_CREATION, "impair-sa-creation", "fail all SA creation"),
       S(IMPAIR_SEND_BOGUS_DCOOKIE, "impair-send-bogus-dcookie", "causes pluto to send a a bogus IKEv2 DCOOKIE"),
       S(IMPAIR_SEND_BOGUS_ISAKMP_FLAG, "impair-send-bogus-isakmp-flag", "causes pluto to set a RESERVED ISAKMP flag to test ignoring/zeroing it"),
       S(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG, "impair-send-bogus-payload-flag", "causes pluto to set a RESERVED PAYLOAD flag to test ignoring/zeroing it"),

       S(IMPAIR_SEND_NO_KE_PAYLOAD, "impair-send-no-ke-payload", "causes pluto to omit sending the KE payload"),
       S(IMPAIR_SEND_EMPTY_KE_PAYLOAD, "impair-send-empty-ke-payload", "causes pluto to send an empty KE payload"),
       S(IMPAIR_SEND_ZERO_KE_PAYLOAD, "impair-send-zero-ke-payload", "causes pluto to send a KE (g^x) payload that is zero, breaking DH calculation"),

       S(IMPAIR_SEND_KEY_SIZE_CHECK, "impair-send-key-size-check", "causes pluto to omit checking configured ESP key sizes for testing"),
       S(IMPAIR_SEND_NO_DELETE, "impair-send-no-delete", "causes pluto to omit sending Notify/Delete messages"),
       S(IMPAIR_SEND_NO_IKEV2_AUTH, "impair-send-no-ikev2-auth", "causes pluto to omit sending an IKEv2 IKE_AUTH packet"),
       S(IMPAIR_SEND_NO_MAIN_R2, "impair-send-no-main-r2", "causes pluto to omit sending an last Main Mode response packet"),
       S(IMPAIR_SEND_NO_XAUTH_R0, "impair-send-no-xauth-r0", "causes pluto to omit sending an XAUTH user/passwd request"),
       S(IMPAIR_SEND_PKCS7_THINGIE, "impair-send-pkcs7-thingie", "send certificates as a PKCS7 thingie"),
       S(IMPAIR_SUPPRESS_RETRANSMITS, "impair-suppress-retransmits", "causes pluto to never send retransmits (wait the full timeout)"),
       S(IMPAIR_TIMEOUT_ON_RETRANSMIT, "impair-timeout-on-retransmit", "causes pluto to 'retry' (switch protocol) on the first retransmit"),
       S(IMPAIR_UNKNOWN_PAYLOAD_CRITICAL, "impair-unknown-payload-critical", "mark the unknown payload as critical"),

};

const enum_names impair_names = {
	IMPAIR_floor_IX, IMPAIR_roof_IX - 1,
	ARRAY_REF(impair.name),
	"impair-",
	NULL,
};

const struct lmod_info impair_lmod_info = {
	.names = &impair_names,
	.all = IMPAIR_MASK,
	.mask = IMPAIR_MASK,
};
const struct enum_names impair_help = {
	IMPAIR_floor_IX, IMPAIR_roof_IX - 1,
	ARRAY_REF(impair.help),
	NULL, NULL,
};
