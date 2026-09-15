/* ikev2 notification names, for libreswan
 *
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2026 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include "ietf_constants.h"
#include "enum_names.h"
#include "names.h"

static const char *const v2_notification_error_name[] = {
#define S(E) [E - v2N_ERROR_FLOOR] = #E
	S(v2N_UNSUPPORTED_CRITICAL_PAYLOAD),
	S(v2N_INVALID_IKE_SPI),
	S(v2N_INVALID_MAJOR_VERSION),
	S(v2N_INVALID_SYNTAX),
	S(v2N_INVALID_MESSAGE_ID),
	S(v2N_INVALID_SPI),
	S(v2N_NO_PROPOSAL_CHOSEN),
	S(v2N_INVALID_KE_PAYLOAD),
	S(v2N_AUTHENTICATION_FAILED),
	S(v2N_SINGLE_PAIR_REQUIRED),
	S(v2N_NO_ADDITIONAL_SAS),
	S(v2N_INTERNAL_ADDRESS_FAILURE),
	S(v2N_FAILED_CP_REQUIRED),
	S(v2N_TS_UNACCEPTABLE),
	S(v2N_INVALID_SELECTORS),
	S(v2N_UNACCEPTABLE_ADDRESSES),
	S(v2N_UNEXPECTED_NAT_DETECTED),
	S(v2N_USE_ASSIGNED_HoA),
	S(v2N_TEMPORARY_FAILURE),
	S(v2N_CHILD_SA_NOT_FOUND),
	S(v2N_INVALID_GROUP_ID),
	S(v2N_AUTHORIZATION_FAILED),
	S(v2N_STATE_NOT_FOUND),
	S(v2N_TS_MAX_QUEUE),
	S(v2N_REGISTRATION_FAILED),
#undef S
};

/* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xml#ikev2-parameters-13 */
static const char *const v2_notification_status_name[] = {
#define S(E) [E - v2N_STATUS_FLOOR] = #E
	S(v2N_INITIAL_CONTACT),    /* 16384 */
	S(v2N_SET_WINDOW_SIZE),
	S(v2N_ADDITIONAL_TS_POSSIBLE),
	S(v2N_IPCOMP_SUPPORTED),
	S(v2N_NAT_DETECTION_SOURCE_IP),
	S(v2N_NAT_DETECTION_DESTINATION_IP),
	S(v2N_COOKIE),
	S(v2N_USE_TRANSPORT_MODE),
	S(v2N_HTTP_CERT_LOOKUP_SUPPORTED),
	S(v2N_REKEY_SA),
	S(v2N_ESP_TFC_PADDING_NOT_SUPPORTED),
	S(v2N_NON_FIRST_FRAGMENTS_ALSO),
	S(v2N_MOBIKE_SUPPORTED),
	S(v2N_ADDITIONAL_IP4_ADDRESS),
	S(v2N_ADDITIONAL_IP6_ADDRESS),
	S(v2N_NO_ADDITIONAL_ADDRESSES),
	S(v2N_UPDATE_SA_ADDRESSES),
	S(v2N_COOKIE2),
	S(v2N_NO_NATS_ALLOWED),
	S(v2N_AUTH_LIFETIME),
	S(v2N_MULTIPLE_AUTH_SUPPORTED),
	S(v2N_ANOTHER_AUTH_FOLLOWS),
	S(v2N_REDIRECT_SUPPORTED),
	S(v2N_REDIRECT),
	S(v2N_REDIRECTED_FROM),
	S(v2N_TICKET_LT_OPAQUE),
	S(v2N_TICKET_REQUEST),
	S(v2N_TICKET_ACK),
	S(v2N_TICKET_NACK),
	S(v2N_TICKET_OPAQUE),
	S(v2N_LINK_ID),
	S(v2N_USE_WESP_MODE),
	S(v2N_ROHC_SUPPORTED),
	S(v2N_EAP_ONLY_AUTHENTICATION),
	S(v2N_CHILDLESS_IKEV2_SUPPORTED),
	S(v2N_QUICK_CRASH_DETECTION),
	S(v2N_IKEV2_MESSAGE_ID_SYNC_SUPPORTED),
	S(v2N_IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED),
	S(v2N_IKEV2_MESSAGE_ID_SYNC),
	S(v2N_IPSEC_REPLAY_COUNTER_SYNC),
	S(v2N_SECURE_PASSWORD_METHODS),
	S(v2N_PSK_PERSIST),
	S(v2N_PSK_CONFIRM),
	S(v2N_ERX_SUPPORTED),
	S(v2N_IFOM_CAPABILITY),
	S(v2N_GROUP_SENDER),
	S(v2N_IKEV2_FRAGMENTATION_SUPPORTED),
	S(v2N_SIGNATURE_HASH_ALGORITHMS),
	S(v2N_CLONE_IKE_SA_SUPPORTED),
	S(v2N_CLONE_IKE_SA),
	S(v2N_PUZZLE),
	S(v2N_USE_PPK),
	S(v2N_PPK_IDENTITY),
	S(v2N_NO_PPK_AUTH),
	S(v2N_INTERMEDIATE_EXCHANGE_SUPPORTED),
	S(v2N_IP4_ALLOWED),
	S(v2N_IP6_ALLOWED),
	S(v2N_ADDITIONAL_KEY_EXCHANGE),
	S(v2N_USE_AGGFRAG),
	S(v2N_SUPPORTED_AUTH_METHODS),
	S(v2N_SA_RESOURCE_INFO),
	S(v2N_USE_PPK_INT),
	S(v2N_PPK_IDENTITY_KEY),
	S(v2N_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH),
#undef S
};

static const char *const v2_notification_private_range_40960_40960_name[] = {
#define S(E) [E - v2N_NULL_AUTH] = #E
	S(v2N_NULL_AUTH),		/* 40960, used for mixed OE */
#undef S
};

static const struct enum_names v2_notification_private_40960_40960_names = {
	v2N_NULL_AUTH,
	v2N_NULL_AUTH,
	ARRAY_PTR(v2_notification_private_range_40960_40960_name),
	"v2N_", /* prefix */
	NULL,
};

static const struct enum_names v2_notification_status_names = {
	v2N_STATUS_FLOOR,
	v2N_STATUS_PSTATS_ROOF-1,
	ARRAY_PTR(v2_notification_status_name),
	"v2N_", /* prefix */
	&v2_notification_private_40960_40960_names,
};

const struct enum_names v2_notification_names = {
	v2N_ERROR_FLOOR,
	v2N_ERROR_PSTATS_ROOF-1,
	ARRAY_PTR(v2_notification_error_name),
	"v2N_", /* prefix */
	&v2_notification_status_names
};

const struct names ikev2_notification_names = {
	.enum_names = &v2_notification_names,
};
