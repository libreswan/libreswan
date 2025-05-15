/*
 * Libreswan config file parser (keywords.c)
 * Copyright (C) 2003-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013-2016 Antony Antony <antony@phenome.org>
 * Copyright (C) 2016-2022 Andrew Cagney
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#include "constants.h"
#include "sparse_names.h"

/*
 * Common aliases for YES and NO, add this to a keyword list so all
 * are accepted.
 *
 * This list does not include "0" or "1" as they, for things like
 * yndev have special meanings.
 */

#define YES_NO(YES, NO)				\
		SPARSE("yes",        YES),	\
		SPARSE("no",         NO),	\
		SPARSE("true",       YES),	\
		SPARSE("false",      NO),	\
		SPARSE("on",         YES),	\
		SPARSE("off",        NO),	\
		SPARSE("y",          YES),	\
		SPARSE("n",          NO)

/*
 * Match <BOOLEAN_VALUE> in parser.lex; includes numbers 0/1.
 */

const struct sparse_names yn_option_names = {
	.list = {
		YES_NO(YN_YES, YN_NO),
		/*
		 * These are unique to YN, and probably should be dropped
		 * completely.  Some keywords, such as ipsec-interface,
		 * interpret "1" and "0".
		 */
		SPARSE("1",          YN_YES),
		SPARSE("0",          YN_NO),
		SPARSE_NULL,
	},
};

/*
 * Values for no/yes; excludes numeric values.
 */

const struct sparse_names yn_text_option_names = {
	.list = {
		YES_NO(YN_YES, YN_NO),
		SPARSE_NULL
	},
};

/*
 * Values for yes/no/force, used by fragmentation=
 */

const struct sparse_names ynf_option_names = {
	.list = {
		YES_NO(YNF_YES, YNF_NO),
		SPARSE("force",     YNF_FORCE),
		SPARSE("never",     YNF_NO),
		SPARSE("insist",    YNF_FORCE),
		SPARSE_NULL
	},
};

/*
 * Values for ESP
 */

const struct sparse_names yne_option_names = {
	.list = {
		YES_NO(YNE_YES, YNE_NO),
		SPARSE("either",	YNE_EITHER),
		SPARSE_NULL
	},
};

/*
 * Values for Four-State options, used for ppk=
 */

const struct sparse_names nppi_option_names = {
	.list = {
		SPARSE("never",     NPPI_NEVER),
		SPARSE("permit",    NPPI_PERMIT),
		SPARSE("propose",   NPPI_PROPOSE),
		SPARSE("insist",    NPPI_INSIST),
		SPARSE("always",    NPPI_INSIST),
		YES_NO(NPPI_PROPOSE, NPPI_NEVER),
		SPARSE_NULL
	},
};

/*
 * Values for nat-ikev1-method={drafts,rfc,both,none}
 */

const struct sparse_names nat_ikev1_method_option_names = {
	.list = {
		SPARSE("both",       NATT_BOTH),
		SPARSE("rfc",        NATT_RFC),
		SPARSE("drafts",     NATT_DRAFTS),
		SPARSE("none",       NATT_NONE),
		SPARSE_NULL
	},
};

/*
 * Values for yes/no/auto, used by encapsulation.
 */

const struct sparse_names yna_option_names = {
	.list = {
		YES_NO(YNA_YES, YNA_NO),
		SPARSE("auto",	YNA_AUTO),
		SPARSE_NULL,
	},
};

/*
 * Values for enable-tcp={no, yes, fallback}
 */

const struct sparse_names tcp_option_names = {
	.list = {
		YES_NO(IKE_TCP_ONLY, IKE_TCP_NO),
		SPARSE("fallback", IKE_TCP_FALLBACK),
		SPARSE_NULL
	},
};

const struct sparse_names nic_offload_option_names = {
	.list = {
		SPARSE("no",         NIC_OFFLOAD_NO),
		SPARSE("crypto",     NIC_OFFLOAD_CRYPTO),
		SPARSE("packet",     NIC_OFFLOAD_PACKET),
		SPARSE("yes",        NIC_OFFLOAD_CRYPTO), /* backwards compat */
		SPARSE_NULL
	},
};

/*
 * Values for type={tunnel,transport,etc}
 */

const struct sparse_names type_option_names = {
	.list = {
		SPARSE("tunnel",      KS_TUNNEL),
		SPARSE("transport",   KS_TRANSPORT),
		SPARSE("pass",        KS_PASSTHROUGH),
		SPARSE("passthrough", KS_PASSTHROUGH),
		SPARSE("reject",      KS_REJECT),
		SPARSE("drop",        KS_DROP),
		SPARSE_NULL
	},
};

/*
 * Values for keyexchange= and ikev2=
 *
 * The ikev2= keyword, which was originally very flexible, has been
 * reduced to a boolean.  Retain original keywords for backwards
 * compatibility for now.
 */

const struct sparse_names keyexchange_option_names = {
	.list = {
		SPARSE("ikev1", IKEv1),
		SPARSE("ikev2", IKEv2),
		SPARSE("ike",  IKE_VERSION_ROOF),
		SPARSE_NULL
	},
};

const struct sparse_names ikev2_option_names = {
	.list = {
		YES_NO(YN_YES, YN_NO),
		/* from fo_{never,permit,propose,insist} */
		SPARSE("never",     YN_NO),
		SPARSE("propose",   YN_YES),	/* originally: initiate IKEv2,
						 * but allow downgrade to
						 * IKEv1; accept IKEv1 or
						 * IKEv2 */
		SPARSE("permit",    YN_NO),		/* reverse of propose:
						 * initiate IKEv1, but allow
						 * upgrade to IKEv2; accept
						 * IKEv1 or IKEv2? */
		SPARSE("insist",    YN_YES),
		SPARSE("always",    YN_YES),
		SPARSE_NULL
	},
};

