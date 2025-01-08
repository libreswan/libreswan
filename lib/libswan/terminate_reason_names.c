/* delete reason table, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013-2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2014,2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2015-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2015-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 * Copyright (C) 2021 Paul Wouters <paul.wouters@aiven.io>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include "terminate_reason.h"

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"

static const char *terminate_reason_name[] = {
	[REASON_UNKNOWN] = "other",
	[REASON_COMPLETED] = "completed",
	[REASON_EXCHANGE_TIMEOUT] = "exchange-timeout",
	[REASON_CRYPTO_TIMEOUT] = "crypto-timeout",
	[REASON_TOO_MANY_RETRANSMITS] = "too-many-retransmits",
	[REASON_SUPERSEDED_BY_NEW_SA] = "superseeded-by-new-sa",
	[REASON_AUTH_FAILED] = "auth-failed",
	[REASON_TRAFFIC_SELECTORS_FAILED] = "ts-unacceptable",
	[REASON_CRYPTO_FAILED] = "crypto-failed",
	[REASON_DELETED] = "deleted",
};

const struct enum_names terminate_reason_names = {
	TERMINATE_REASON_FLOOR, TERMINATE_REASON_ROOF-1,
	ARRAY_REF(terminate_reason_name),
	.en_prefix = NULL,
};
