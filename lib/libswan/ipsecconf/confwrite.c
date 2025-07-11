/*
 * Libreswan config file writer (confwrite.c)
 * Copyright (C) 2004-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013-2015 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

#include "constants.h"
#include "lswlog.h"
#include "lmod.h"
#include "ip_address.h"
#include "sparse_names.h"
#include "encap_proto.h"
#include "lswalloc.h"		/* for ITEMS_FOR_EACH() */

#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/keywords.h"

#include "ipsecconf/keywords.h"
#include "ipsecconf/parser.h"	/* includes parser.tab.h generated by bison; requires keywords.h */

void confwrite_list(FILE *out, char *prefix, int val, const struct keyword_def *k)
{
	char *sep = "";

	for (const struct sparse_name *kev  = k->sparse_names->list; kev->name != NULL; kev++) {
		unsigned int mask = kev->value;

		if (mask != 0 && (val & mask) == mask) {
			fprintf(out, "%s%s%s", sep, prefix, kev->name);
			sep = " ";
		}
	}
}

static void confwrite_value(FILE *out,
			    const char *side, /* never NULL! */
			    const struct keywords_def *keywords,
			    const struct keyword_value *values,
			    unsigned elemsof_values)
{
	ITEMS_FOR_EACH(k, keywords) {

		if (k->keyname == NULL) {
			continue;
		}

#define KV_END_MASK (kv_leftright | kv_both)
		if (side[0] == '\0' && (k->validity & KV_END_MASK) != LEMPTY) {
			/* no side, so skip left|right */
			continue;
		}
		if (side[0] != '\0' && (k->validity & KV_END_MASK) == LEMPTY) {
			/* side requires left|right */
			continue;
		}

		/*
		 * Do not output aliases; the real option will display
		 * value.
		 */
		if (k->validity & kv_alias)
			continue;

#if 0
		printf("#side: %s  %s validity: %08x & %08x=%08x vs %08x\n",
		       side,
		       k->keyname, k->validity, KV_CONTEXT_MASK,
		       k->validity & KV_CONTEXT_MASK, context);
#endif

		passert(k->field < elemsof_values);

		switch (k->type) {
		case kt_also:
		case kt_appendlist:
			if (values[k->field].set)
				fprintf(out, "\t%s%s={%s}\n", side, k->keyname,
					values[k->field].string);
			break;

		case kt_string:
		case kt_appendstring:
			/* these are strings */

			if (values[k->field].set) {
				const char *quote =
					strchr(values[k->field].string, ' ') == NULL ?
						"" : "\"";

				fprintf(out, "\t%s%s=%s%s%s\n", side, k->keyname,
					quote,
					values[k->field].string,
					quote);
			}
			break;

		case kt_sparse_name:
			/* special enumeration */
			if (values[k->field].set) {
				int val = values[k->field].option;
				fprintf(out, "\t%s%s=", side, k->keyname);
				for (const struct sparse_name *kev = k->sparse_names->list;
				     kev->name != NULL; kev++) {
					/* XXX: INT vs UNSIGNED magic? */
					if ((int)kev->value == val) {
						break;
					}
				}
			}
			break;

		case kt_obsolete:
			break;

		case kt_unsigned:
			if (values[k->field].set) {
				fprintf(out, "\t%s%s=%jd\n", side, k->keyname,
					values[k->field].option);
			}
			break;

		case kt_seconds:
			if (values[k->field].set) {
				deltatime_buf d;
				fprintf(out, "\t%s%s=%s\n", side, k->keyname,
					str_deltatime(values[k->field].deltatime, &d));
			}
			break;

		}

	}
}

static void confwrite_side(FILE *out, struct starter_end *end)
{
	const char *side = end->leftright;

	if (end->values[KWS_HOST].string != NULL) {
		fprintf(out, "\t%s=%s\n", side, end->values[KWS_HOST].string);
	}

	if (end->values[KWS_NEXTHOP].string != NULL) {
		fprintf(out, "\t%s=%s\n", side, end->values[KWS_NEXTHOP].string);
	}

	if (end->values[KWS_PROTOPORT].string != NULL) {
		fprintf(out, "\t%sprotoport=%s\n", side,
			end->values[KWS_PROTOPORT].string);
	}

	confwrite_value(out, side, &config_conn_keywords, ARRAY_REF(end->values));
}

static void confwrite_conn(FILE *out, struct starter_conn *conn, bool verbose)
{
	/*
	 * config-write-field: short-cut for writing out a field
	 * (string-valued, indented, on its own line).
	 */
#define cwf(name, value)	{ fprintf(out, "\t" name "=%s\n", (value)); }
	/* conn-keyword-string */
#define ckws(NAME, INDEX)						\
	{								\
		const char *_s = conn->values[KWS_##INDEX].string;	\
		if (_s != NULL) {					\
			fprintf(out, "\t"NAME"=%s\n", _s);		\
		}							\
	}

	if (verbose)
		fprintf(out, "# begin conn %s\n", conn->name);

	fprintf(out, "conn %s\n", conn->name);
	confwrite_side(out, &conn->end[LEFT_END]);
	confwrite_side(out, &conn->end[RIGHT_END]);
	confwrite_value(out, "", &config_conn_keywords, ARRAY_REF(conn->values));

	if (conn->values[KNCF_AUTO].option != 0) {
		name_buf sb;
		cwf("auto", str_sparse_long(&autostart_names, conn->values[KNCF_AUTO].option, &sb));
	}

	if (conn->values[KNCF_PPK].option != NPPI_UNSET) {
		name_buf sb;
		cwf("ppk", str_sparse_long(&nppi_option_names, conn->values[KNCF_PPK].option, &sb));
	}

	if (conn->never_negotiate_shunt != SHUNT_UNSET) {
		name_buf nb;
		cwf("type", str_sparse_long(&never_negotiate_shunt_names,
					    conn->never_negotiate_shunt,
					    &nb));
	} else if (conn->values[KNCF_PHASE2].option != 0) {
		enum encap_proto encap_proto = conn->values[KNCF_PHASE2].option;
		enum type_options satype = conn->values[KNCF_TYPE].option;
		static const char *const noyes[2 /*bool*/] = {"no", "yes"};
		/*
		 * config-write-yn: for writing out optional
		 * yn_options fields.
		 */
#define cwyn(NAME, KNCF)						\
		{							\
			if (conn->values[KNCF].option != YN_UNSET)	\
				cwf(NAME, noyes[conn->values[KNCF].option == YN_YES]); \
		}
		switch (satype) {
		case KS_TUNNEL:
			cwf("type", "tunnel");
			break;
		case KS_TRANSPORT:
			cwf("type", "transport");
			break;
		default:
			break;
		}

		cwyn("compress", KWYN_COMPRESS);
		cwyn("pfs", KWYN_PFS);
		cwyn("ikepad", KNCF_IKEPAD);
		ckws("auth", AUTH);

		if (encap_proto != ENCAP_PROTO_UNSET) {
			/* story is lower-case */
			name_buf eb;
			cwf("phase2", str_enum_short(&encap_proto_story, encap_proto, &eb));
		}

		/* key-exchange= */

		if (conn->values[KWS_KEYEXCHANGE].string != NULL) {
			cwf("keyexchange", conn->values[KWS_KEYEXCHANGE].string);
		} else if (conn->values[KWS_IKEv2].string != NULL) {
			cwf("ikev2", conn->values[KWS_IKEv2].string);
		}

		/* esn= */
		if (conn->values[KNCF_ESN].option != YNE_UNSET) {
			name_buf nb;
			cwf("esn", str_sparse_long(&yne_option_names,
					      conn->values[KNCF_ESN].option, &nb));
		}

		switch (conn->values[KNCF_FRAGMENTATION].option) {
		case YNF_UNSET:
			/* it's the default, do not print anything */
			break;
		case YNF_FORCE:
			cwf("fragmentation", "force");
			break;
		case YNF_NO:
			cwf("fragmentation", "no");
			break;
		case YNF_YES:
			cwf("fragmentation", "yes");
		}

#undef cwyn
	}

	if (verbose)
		fprintf(out, "# end conn %s\n\n", conn->name);
#	undef cwf
}

void confwrite(struct starter_config *cfg, FILE *out, bool setup, char *name, bool verbose)
{
	/* output version number */
	/* fprintf(out, "\nversion 2.0\n\n"); */

	/* output config setup section */
	if (setup) {
		const struct config_setup *setup = config_setup_singleton();
		fprintf(out, "config setup\n");
		confwrite_value(out, "", &config_setup_keywords, ARRAY_REF(setup->values));
		fprintf(out, "\n");
	}

	/* output connections */
	struct starter_conn *conn;
	TAILQ_FOREACH(conn, &cfg->conns, link) {
		if (name == NULL || streq(name, conn->name)) {
			confwrite_conn(out, conn, verbose);
		}
	}
	if (verbose)
		fprintf(out, "# end of config\n");
}
