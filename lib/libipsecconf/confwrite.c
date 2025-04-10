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
			    enum keyword_valid type,
			    keyword_values values)
{
	const struct keyword_def *k;

	for (k = ipsec_conf_keywords; k->keyname != NULL; k++) {
		/* exact match */
		if ((k->validity & (kv_config|kv_conn)) != type) {
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

		/* do not output aliases or things handled elsewhere */
		if (k->validity & (kv_alias | kv_policy | kv_processed))
			continue;

#if 0
		printf("#side: %s  %s validity: %08x & %08x=%08x vs %08x\n",
		       side,
		       k->keyname, k->validity, KV_CONTEXT_MASK,
		       k->validity & KV_CONTEXT_MASK, context);
#endif

		switch (k->type) {
		case kt_also:
		case kt_appendlist:
			if (values[k->field].set)
				fprintf(out, "\t%s%s={%s}\n", side, k->keyname,
					values[k->field].string);
			break;

		case kt_string:
		case kt_appendstring:
		case kt_filename:
		case kt_dirname:
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

		case kt_pubkey:
		case kt_percent:
		case kt_ipaddr:
		case kt_subnet:
		case kt_range:
		case kt_idtype:
		case kt_bitstring:
			/* none of these are valid number/string types */
			break;

		case kt_bool:
			/* special enumeration */
			if (values[k->field].set) {
				fprintf(out, "\t%s%s=%s\n", side,
					k->keyname,
					(values[k->field].option ? "yes" : "no"));
			}
			break;

		case kt_host:
			/* special enumeration */
			if (values[k->field].set) {
				fprintf(out, "\t%s%s=%s\n", side,
					k->keyname, values[k->field].string);
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

		case kt_lset:
			if (values[k->field].set) {
				unsigned long val = values[k->field].option;

				if (val != 0) {
					JAMBUF(buf) {
						jam_lset_short(buf, k->info->names, ",", val);
						fprintf(out, "\t%s%s=\""PRI_SHUNK"\"\n",
							side, k->keyname,
							pri_shunk(jambuf_as_shunk(buf)));
					}
				}
			}
			break;

		case kt_obsolete:
			break;

		case kt_binary:
		case kt_byte:
		case kt_unsigned:
			if (values[k->field].set) {
				fprintf(out, "\t%s%s=%jd\n", side, k->keyname,
					values[k->field].option);
			}
			break;

		case kt_seconds:
		case kt_milliseconds:
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
	switch (end->addrtype) {
	case KH_NOTSET:
		/* nothing! */
		break;

	case KH_DEFAULTROUTE:
		fprintf(out, "\t%s=%%defaultroute\n", side);
		break;

	case KH_ANY:
		fprintf(out, "\t%s=%%any\n", side);
		break;

	case KH_IFACE:
		if (end->values[KW_IP].set)
			fprintf(out, "\t%s=%s\n", side, end->values[KW_IP].string);
		break;

	case KH_OPPO:
		fprintf(out, "\t%s=%%opportunistic\n", side);
		break;

	case KH_OPPOGROUP:
		fprintf(out, "\t%s=%%opportunisticgroup\n", side);
		break;

	case KH_GROUP:
		fprintf(out, "\t%s=%%group\n", side);
		break;

	case KH_IPHOSTNAME:
		fprintf(out, "\t%s=%s\n", side, end->values[KW_IP].string);
		break;

	case KH_IPADDR:
		{
			address_buf as;
			fprintf(out, "\t%s=%s\n",
				side, str_address(&end->addr, &as));
		}
		break;
	}

	switch (end->nexttype) {
	case KH_NOTSET:
		/* nothing! */
		break;

	case KH_DEFAULTROUTE:
		fprintf(out, "\t%snexthop=%%defaultroute\n", side);
		break;

	case KH_IPADDR:
		{
			address_buf as;
			fprintf(out, "\t%snexthop=%s\n",
				side, str_address(&end->nexthop, &as));
		}
		break;

	default:
		break;
	}

	if (end->values[KSCF_PROTOPORT].set)
		fprintf(out, "\t%sprotoport=%s\n", side,
			end->values[KSCF_PROTOPORT].string);

	confwrite_value(out, side, kv_conn, end->values);
}

static void confwrite_conn(FILE *out, struct starter_conn *conn, bool verbose)
{
	/*
	 * config-write-field: short-cut for writing out a field
	 * (string-valued, indented, on its own line).
	 */
#define cwf(name, value)	{ fprintf(out, "\t" name "=%s\n", (value)); }

	if (verbose)
		fprintf(out, "# begin conn %s\n", conn->name);

	fprintf(out, "conn %s\n", conn->name);
	confwrite_side(out, &conn->end[LEFT_END]);
	confwrite_side(out, &conn->end[RIGHT_END]);
	confwrite_value(out, "", kv_conn, conn->values);

	if (conn->values[KNCF_AUTO].option != 0) {
		sparse_buf sb;
		cwf("auto", str_sparse(&autostart_names, conn->values[KNCF_AUTO].option, &sb));
	}

	if (conn->values[KNCF_PPK].option != NPPI_UNSET) {
		sparse_buf sb;
		cwf("ppk", str_sparse(&nppi_option_names, conn->values[KNCF_PPK].option, &sb));
	}

	if (conn->never_negotiate_shunt != SHUNT_UNSET ||
	    conn->values[KNCF_PHASE2].option != 0) {
		enum encap_proto encap_proto = conn->values[KNCF_PHASE2].option;
		enum shunt_policy shunt_policy = conn->never_negotiate_shunt;
		enum type_options satype = conn->values[KNCF_TYPE].option;
		static const char *const noyes[2 /*bool*/] = {"no", "yes"};
		/*
		 * config-write-policy-bit: short-cut for writing out a field that is a policy
		 * bit.
		 *
		 * config-write-policy-bit-flipped: cwpbf() flips the
		 * sense of the bit.
		 *
		 * config-write-yn: for writing out optional
		 * yn_options fields.
		 */
#		define cwpb(name, p)  { cwf(name, noyes[(conn->policy & (p)) != LEMPTY]); }
#		define cwpbf(name, p)  { cwf(name, noyes[(conn->policy & (p)) == LEMPTY]); }
#define cwyn(NAME, KNCF)						\
		{							\
			if (conn->values[KNCF].option != YN_UNSET)		\
				cwf(NAME, noyes[conn->values[KNCF].option == YN_YES]); \
		}
		switch (shunt_policy) {
		case SHUNT_UNSET:
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

			cwyn("compress", KNCF_COMPRESS);
			cwyn("pfs", KNCF_PFS);
			cwyn("ikepad", KNCF_IKEPAD);

			if (conn->end[LEFT_END].values[KNCF_AUTH].option == k_unset ||
			    conn->end[RIGHT_END].values[KNCF_AUTH].option == k_unset) {
				authby_buf ab;
				cwf("authby", str_authby(conn->authby, &ab));
			}

			if (encap_proto != ENCAP_PROTO_UNSET) {
				/* story is lower-case */
				enum_buf eb;
				cwf("phase2", str_enum_short(&encap_proto_story, encap_proto, &eb));
			}

			/* ikev2= */
			{
				const char *v2ps;
				switch (conn->ike_version) {
				case IKEv1:
					v2ps = "no";
					break;
				case IKEv2:
					v2ps = "yes";
					break;
				default:
					v2ps = "UNKNOWN";
					break;
				}
				cwf("ikev2", v2ps);
			}

			/* esn= */
			if (conn->values[KNCF_ESN].option != YNE_UNSET) {
				name_buf nb;
				cwf("esn", str_sparse(&yne_option_names,
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

			break; /* end of case UNSET aka SHUNT_TRAP? */

		case SHUNT_PASS:
			cwf("type", "passthrough");
			break;

		case SHUNT_DROP:
			cwf("type", "drop");
			break;

		case SHUNT_IPSEC:
			cwf("type", "ipsec"); /* can't happen */
			break
;
		case SHUNT_TRAP:
			cwf("type", "trap"); /* can't happen */
			break;

		case SHUNT_NONE:
			cwf("type", "none"); /* can't happen */
			break;

		case SHUNT_HOLD:
			cwf("type", "hold"); /* can't happen */
			break;

		}

#undef cwpb
#undef cwpbf
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
		fprintf(out, "config setup\n");
		confwrite_value(out, "", kv_config, cfg->setup);
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
