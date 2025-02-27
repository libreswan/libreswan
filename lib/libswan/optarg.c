/* getopt parsing, for libreswan
 *
 * Copyright (C) 2023,2024 Andrew Cagney
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

#include <stdlib.h>		/* for exit() */
#include <stdio.h>		/* for output */

#include "optarg.h"

#include "sparse_names.h"
#include "passert.h"
#include "lswlog.h"
#include "ip_info.h"
#include "lmod.h"
#include "names_constant.h"		/* for debug_lmod_info */
#include "timescale.h"
#include "lswversion.h"

int optarg_index = -1;
unsigned verbose;

int optarg_getopt(struct logger *logger, int argc, char **argv, const char *options)
{
	while (true) {
		int c = getopt_long(argc, argv, options, optarg_options, &optarg_index);
		switch (c) {
		case ':':	/* diagnostic already printed by getopt_long */
		case '?':	/* diagnostic already printed by getopt_long */
			llog(RC_LOG|NO_PREFIX, logger, "For usage information: %s --help\n", argv[0]);
			exit(PLUTO_EXIT_FAIL);
		case EOF:
			return EOF;
		case 0:
			/*
			 * Long option already handled by getopt_long.
			 * Not currently used since we always set flag
			 * to NULL.
			 */
			llog_passert(logger, HERE, "unexpected 0 returned by getopt_long()");
		}
		const char *optname = optarg_options[optarg_index].name;
		const char *optmeta = optname + strlen(optname);	/* at '\0?' */
		if (memeq(optmeta, METAOPT_OBSOLETE, 2)) {
			llog(RC_LOG|NO_PREFIX, logger,
			     "warning: option \"--%s\" is obsolete; ignored", optname);
			continue;	/* ignore it! */
		}
		if (memeq(optmeta, METAOPT_RENAME, 2)) {
			llog(RC_LOG, logger,
			     "warning: option \"--%s\" is obsolete; use \"--%s\"", optname, optmeta+2);
		}
		return c;
	}
}

/*
 * XXX: almost identical code lives in plutomain.c
 */

void optarg_fatal(const struct logger *logger, const char *fmt, ...)
{
	/*
	 * Not exit_pluto() or fatal() as pluto isn't yet up and
	 * running?
	 */
	passert(optarg_index >= 0);
	const char *optname = optarg_options[optarg_index].name;
	LLOG_JAMBUF(ERROR_STREAM, logger, buf) {
		if (optarg == NULL) {
			jam(buf, "option --%s invalid: ", optname);
		} else {
			jam(buf, "option --%s '%s' invalid: ", optname, optarg);
		}
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
	}
	/* not exit_pluto as pluto isn't yet up and running? */
	exit(PLUTO_EXIT_FAIL);
}

void optarg_usage(const char *progname)
{
	FILE *stream = stdout;

	char line[72];
	snprintf(line, sizeof(line), "Usage: %s", progname);

	for (const struct option *opt = optarg_options; opt->name != NULL; opt++) {

		const char *nm = opt->name;

		/*
		 * "\0heading"
		 *
		 * A zero length option string.  Assume the meta is a
		 * heading.
		 */
		if (*nm == '\0') {
			/* dump current line */
			fprintf(stream, "%s\n", line);
			jam_str(line, sizeof(line), "\t");
			/* output heading */
			fprintf(stream, "    %s\n", nm + 1);
			continue;
		}

		/* parse '\0...' meta characters */
		const char *meta = nm + strlen(nm);

		if (memeq(meta, METAOPT_RENAME, 2)) {
			/*
			 * Option has been renamed, don't show old
			 * name.
			 */
			continue;
		}

		if (memeq(meta, METAOPT_OBSOLETE, 2)) {
			/*
			 * Option is no longer valid, skip.
			 */
			continue;
		}

		bool nl = false; /* true is sticky */
		if (memeq(meta, METAOPT_NEWLINE, 2)) {
			/*
			 * Option should appear on a new line.
			 */
			nl = true;
			meta += 2; /* skip '\0^' */
		} else if (meta[1] == '<') {
			/*
			 * Looks like the argument to an option, skip
			 * '\0'.
			 */
			meta++; /* skip \0 */
		}

		/* handle entry that forgot the argument */
		const char *argument = (*meta == '\0' ? "<argument>" : meta);

		char chunk[sizeof(line) - 1];
		switch (opt->has_arg) {
		case no_argument:
			snprintf(chunk, sizeof(chunk),  "[--%s]", nm);
			break;
		case optional_argument:
			snprintf(chunk, sizeof(chunk),  "[--%s[=%s]]", nm, argument);
			break;
		case required_argument:
			snprintf(chunk, sizeof(chunk),  "[--%s %s]", nm, argument);
			break;
		default:
			bad_case(opt->has_arg);
		}

		/* enough space? allow for separator, and null? */
		if (strlen(line) + strlen(chunk) + 2 >= sizeof(line)) {
			nl = true;
		}

		if (nl) {
			fprintf(stream, "%s\n", line);
			jam_str(line, sizeof(line), "\t");
		} else {
			add_str(line, sizeof(line), " ");
		}

		add_str(line, sizeof(line), chunk);
	}

	fprintf(stream, "%s\n", line);
	fprintf(stream, "Libreswan %s\n", ipsec_version_code());
}

deltatime_t optarg_deltatime(const struct logger *logger, enum timescale default_timescale)
{
	passert((optarg_options[optarg_index].has_arg == required_argument) ||
		(optarg_options[optarg_index].has_arg == optional_argument && optarg != NULL));
	deltatime_t deltatime;
	diag_t diag = ttodeltatime(optarg, &deltatime, default_timescale);
	if (diag != NULL) {
		optarg_fatal(logger, "%s", str_diag(diag));
	}
	return deltatime;
}

uintmax_t optarg_uintmax(const struct logger *logger)
{
	passert((optarg_options[optarg_index].has_arg == required_argument) ||
		(optarg_options[optarg_index].has_arg == optional_argument && optarg != NULL));
	uintmax_t val;
	err_t err = shunk_to_uintmax(shunk1(optarg), NULL, /*base*/0, &val);
	if (err != NULL) {
		optarg_fatal(logger, "%s", err);
	}
	return val;
}

/*
 * Lookup OPTARG in NAMES.
 *
 * When optional_argument OPTARG is missing, return OPTIONAL (pass
 * optional=0 when required_argument).
 */

uintmax_t optarg_sparse(const struct logger *logger, unsigned optional, const struct sparse_names *names)
{
	if (optarg == NULL) {
		passert(optarg_options[optarg_index].has_arg == optional_argument);
		passert(optional != 0);
		return optional;
	}

	const struct sparse_name *name = sparse_lookup(names, shunk1(optarg));
	if (name == NULL) {
		JAMBUF(buf) {
			jam(buf, "'%s' is not recognised, valid arguments are: ", optarg);
			jam_sparse_names(buf, names, ", ");
			optarg_fatal(logger, PRI_SHUNK, pri_shunk(jambuf_as_shunk(buf)));
		}
	}
	return name->value;
}

/*
 * Addresses.
 */

void optarg_family(struct optarg_family *family, const struct ip_info *info)
{
	if (family != NULL && family->type == NULL) {
		family->type = info;
		family->used_by = optarg_options[optarg_index].name;
	}
}

ip_address optarg_address_dns(const struct logger *logger, struct optarg_family *family)
{
	ip_address address;
	err_t err = ttoaddress_dns(shunk1(optarg), family->type, &address);
	if (err != NULL) {
		optarg_fatal(logger, "%s", err);
	}
	optarg_family(family, address_info(address));
	return address;
}

ip_cidr optarg_cidr_num(const struct logger *logger, struct optarg_family *family)
{
	ip_cidr cidr;
	err_t err = ttocidr_num(shunk1(optarg), family->type, &cidr);
	if (err != NULL) {
		optarg_fatal(logger, "%s", err);
	}
	optarg_family(family, cidr_info(cidr));
	return cidr;
}

ip_address optarg_any(struct optarg_family *family)
{
	optarg_family(family, &ipv4_info);
	return family->type->address.unspec;
}

void optarg_verbose(const struct logger *logger, lset_t start)
{
	verbose++;
	if (verbose == 1) {
		return;
	}

	const lset_t debugging[] = {
		start, DBG_BASE, DBG_ALL, DBG_TMI,
	};

	unsigned i = verbose - 2;
	if (start == LEMPTY) {
		/* skip start */
		i++;
	}

	if (i < elemsof(debugging)) {
		cur_debugging |= debugging[i];
	}

	/* logged when true; log once at end? */
	LDBGP_JAMBUF(DEBUG_STREAM, logger, buf) {
		jam_string(buf, "debugging: ");
		jam_lset(buf, &debug_names, cur_debugging);
	}
}

void optarg_debug_lmod(bool enable, lmod_t *mods)
{
	if (streq(optarg, "list") || streq(optarg, "help") || streq(optarg, "?")) {
		fprintf(stderr, "aliases:\n");
		for (struct lmod_alias *a = debug_lmod_info.aliases;
		     a->name != NULL; a++) {
			JAMBUF(buf) {
				jam(buf, "  %s: ", a->name);
				jam_lset_short(buf, debug_lmod_info.names, "+", a->bits);
				fprintf(stderr, PRI_SHUNK"\n",
					pri_shunk(jambuf_as_shunk(buf)));
			}
		}
		fprintf(stderr, "bits:\n");
		for (long e = next_enum(&debug_names, -1);
		     e != -1; e = next_enum(&debug_names, e)) {
			JAMBUF(buf) {
				jam(buf, "  ");
				jam_enum_short(buf, &debug_names, e);
				enum_buf help;
				if (enum_name(&debug_help, e, &help)) {
					jam(buf, ": ");
					jam_string(buf, help.buf);
				}
				fprintf(stderr, PRI_SHUNK"\n",
					pri_shunk(jambuf_as_shunk(buf)));
			}
		}
		exit(1);
	}

	/* work through the updates */
	if (!lmod_arg(mods, &debug_lmod_info, optarg, enable)) {
		fprintf(stderr, "whack: unrecognized -%s-debug '%s' option ignored\n",
			enable ? "" : "-no", optarg);
	}
}

void optarg_debug(bool enable)
{
	lmod_t mods = {0};
	optarg_debug_lmod(enable, &mods);
	cur_debugging = lmod(cur_debugging, mods);
}

