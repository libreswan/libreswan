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

struct double_double {
	const char *name[IMPAIR_roof_IX - IMPAIR_floor_IX];
	const char *help[IMPAIR_roof_IX - IMPAIR_floor_IX];
};

static struct double_double impair = {

#define S(N,A,H)							\
	.name[IMPAIR_##N##_IX - DBG_roof_IX] = LELEM(IMPAIR_##N##_IX) == IMPAIR_##N ? A "\0" : NULL, \
	.help[IMPAIR_##N##_IX - DBG_roof_IX] = LELEM(IMPAIR_##N##_IX) == IMPAIR_##N ? H : NULL

       S(ADD_UNKNOWN_PAYLOAD_TO_AUTH, "impair-add-unknown-payload-to-auth", "add a payload with an unknown type to AUTH"),
       S(ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK, "impair-add-unknown-payload-to-auth-sk", "add a payload with an unknown type to AUTH's SK payload"),
       S(ADD_UNKNOWN_PAYLOAD_TO_SA_INIT, "impair-add-unknown-payload-to-sa-init", "add a payload with an unknown type to SA_INIT"),
       S(ALLOW_DNS_INSECURE, "impair-allow-dns-insecure", "allow IPSECKEY lookups without DNSSEC protection"),
       S(ALLOW_NULL_NONE, "impair-allow-null-none", "cause pluto to allow esp=null-none and ah=none for testing"),
       S(BUST_MI2, "impair-bust-mi2", "make MI2 really large"),
       S(BUST_MR2, "impair-bust-mr2", "make MR2 really large"),
       S(CORRUPT_ENCRYPTED, "impair-corrupt-encrypted", "corrupts the encrypted packet so that the decryption fails"),
       S(DELETE_ON_RETRANSMIT, "impair-delete-on-retransmit", "causes pluto to fail on the first retransmit"),
       S(DROP_I2, "impair-drop-i2", "drop second initiator packet"),
       S(DROP_XAUTH_R0, "impair-drop-xauth-r0", "causes pluto to drop an XAUTH user/passwd request on IKE initiator"),
       S(FORCE_FIPS, "impair-force-fips", "causes pluto to believe we are in fips mode, NSS needs its own hack"),
       S(IGNORE_HASH_NOTIFY_REQUEST, "impair-ignore-hash-notify", "causes pluto to ignore incoming hash notify from IKE_SA_INIT Request"),
       S(IGNORE_HASH_NOTIFY_RESPONSE, "impair-ignore-hash-notify-resp", "causes pluto to ignore incoming hash notify from IKE_SA_INIT Response"),
       S(IKEv2_EXCLUDE_INTEG_NONE, "impair-ikev2-exclude-integ-none", "lets pluto exclude integrity 'none' in proposals"),
       S(IKEv2_INCLUDE_INTEG_NONE, "impair-ikev2-include-integ-none", "lets pluto include integrity 'none' in proposals"),
       S(JACOB_TWO_TWO, "impair-jacob-two-two", "cause pluto to send all messages twice."),
       S(MAJOR_VERSION_BUMP, "impair-major-version-bump", "cause pluto to send an IKE major version that's higher then we support."),
       S(MINOR_VERSION_BUMP, "impair-minor-version-bump", "cause pluto to send an IKE minor version that's higher then we support."),
       S(OMIT_HASH_NOTIFY_REQUEST, "impair-omit-hash-notify", "causes pluto to omit sending hash notify in IKE_SA_INIT Request"),
       S(PROPOSAL_PARSER, "impair-proposal-parser", "impair algorithm parser - what you see is what you get"),
       S(REPLAY_BACKWARD, "impair-replay-backward", "replay all earlier packets new-to-old"),
       S(REPLAY_DUPLICATES, "impair-replay-duplicates", "replay duplicates of each incoming packet"),
       S(REPLAY_ENCRYPTED, "impair-replay-encrypted", "replay encrypted packets"),
       S(REPLAY_FORWARD, "impair-replay-forward", "replay all earlier packets old-to-new"),
       S(RETRANSMITS, "impair-retransmits", "causes pluto to timeout on first retransmit"),
       S(SA_CREATION, "impair-sa-creation", "fail all SA creation"),
       S(SEND_BOGUS_DCOOKIE, "impair-send-bogus-dcookie", "causes pluto to send a a bogus IKEv2 DCOOKIE"),
       S(SEND_BOGUS_ISAKMP_FLAG, "impair-send-bogus-isakmp-flag", "causes pluto to set a RESERVED ISAKMP flag to test ignoring/zeroing it"),
       S(SEND_BOGUS_PAYLOAD_FLAG, "impair-send-bogus-payload-flag", "causes pluto to set a RESERVED PAYLOAD flag to test ignoring/zeroing it"),
       S(SEND_IKEv2_KE, "impair-send-ikev2-ke", "causes pluto to omit sending the KE payload in IKEv2"),
       S(SEND_KEY_SIZE_CHECK, "impair-send-key-size-check", "causes pluto to omit checking configured ESP key sizes for testing"),
       S(SEND_NO_DELETE, "impair-send-no-delete", "causes pluto to omit sending Notify/Delete messages"),
       S(SEND_NO_IKEV2_AUTH, "impair-send-no-ikev2-auth", "causes pluto to omit sending an IKEv2 IKE_AUTH packet"),
       S(SEND_NO_MAIN_R2, "impair-send-no-main-r2", "causes pluto to omit sending an last Main Mode response packet"),
       S(SEND_NO_XAUTH_R0, "impair-send-no-xauth-r0", "causes pluto to omit sending an XAUTH user/passwd request"),
       S(SEND_PKCS7_THINGIE, "impair-send-pkcs7-thingie", "send certificates as a PKCS7 thingie"),
       S(SEND_ZERO_GX, "impair-send-zero-gx", "causes pluto to send a g^x that is zero, breaking DH calculation"),
       S(SUPPRESS_RETRANSMITS, "impair-suppress-retransmits", "causes pluto to never send retransmits (wait the full timeout)"),
       S(TIMEOUT_ON_RETRANSMIT, "impair-timeout-on-retransmit", "causes pluto to 'retry' (switch protocol) on the first retransmit"),
       S(UNKNOWN_PAYLOAD_CRITICAL, "impair-unknown-payload-critical", "mark the unknown payload as critical"),

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
