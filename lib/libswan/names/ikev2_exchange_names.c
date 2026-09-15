/* tables of ikev2_exchange names, for libreswan
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
#include "names.h"
#include "enum_names.h"

/* https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-1 */
static const char *const ikev2_exchange_name[] = {
#define S(E) [E - IKEv2_EXCHANGE_FLOOR] = #E
	S(ISAKMP_v2_IKE_SA_INIT),
	S(ISAKMP_v2_IKE_AUTH),
	S(ISAKMP_v2_CREATE_CHILD_SA),
	S(ISAKMP_v2_INFORMATIONAL),
	S(ISAKMP_v2_IKE_SESSION_RESUME),
	S(ISAKMP_v2_GSA_AUTH),
	S(ISAKMP_v2_GSA_REGISTRATION),
	S(ISAKMP_v2_GSA_REKEY),
	S(ISAKMP_v2_IKE_INTERMEDIATE),
	S(ISAKMP_v2_IKE_FOLLOWUP_KE),
#undef S
};

const struct enum_names ikev2_exchange_names = {
	IKEv2_EXCHANGE_FLOOR,
	IKEv2_EXCHANGE_ROOF-1,
	ARRAY_PTR(ikev2_exchange_name),
	"ISAKMP_v2_", /* prefix */
	NULL,
};

const struct names ikev2_exchange_nom = {
	.enum_names = &ikev2_exchange_names,
};
