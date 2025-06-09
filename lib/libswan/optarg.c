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
#include "binaryscale-iec-60027-2.h"

int optarg_index = -1;
unsigned verbose;

int optarg_getopt(struct logger *logger, int argc, char **argv, const char *options)
{
	while (true) {
		int c = getopt_long(argc, argv, options, optarg_options, &optarg_index);
		if (c < 0) {
			return c;
		}
		switch (c) {
		case ':':	/* diagnostic already printed by getopt_long */
		case '?':	/* diagnostic already printed by getopt_long */
			llog(RC_LOG|NO_PREFIX, logger, "For usage information: %s --help", argv[0]);
			exit(PLUTO_EXIT_FAIL);
		}
		const char *optname = optarg_options[optarg_index].name;
		const char *optmeta = optname + strlen(optname);	/* at '\0?' */
		if (memeq(optmeta, METAOPT_IGNORE, 2)) {
			const char *release = optmeta + 2;
			llog(RC_LOG|NO_PREFIX, logger,
			     "warning: ignoring option \"--%s\" that was removed in Libreswan %s", optname, release);
			continue;	/* ignore it! */
		}
		if (memeq(optmeta, METAOPT_FATAL, 2)) {
			const char *release = optmeta + 2;
			optarg_fatal(logger, "option \"--%s\" was removed in Libreswan %s", optname, release);
		}
		if (memeq(optmeta, METAOPT_REPLACE, 2)) {
			/* NEWNAME\nVERSION */
			shunk_t cursor = shunk1(optmeta + 2);
			char delim;
			shunk_t newname = shunk_token(&cursor, &delim, "\n");
			shunk_t release = cursor;
			LLOG_JAMBUF(RC_LOG|NO_PREFIX, logger, buf) {
				jam_string(buf, "warning: option \"--");
				jam_string(buf, optname);
				jam_string(buf, "\" was replaced by \"--");
				jam_shunk(buf, newname);
				jam_string(buf, "\" in libreswan version ");
				jam_shunk(buf, release);
			}
		}
		if (c == 0) {
			/*
			 * Long option already handled by getopt_long.
			 */
			continue;
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
	const struct option *option = &optarg_options[optarg_index];
	LLOG_JAMBUF(ERROR_STREAM, logger, buf) {
		jam_string(buf, "option --");
		jam_string(buf, option->name);
		switch (option->has_arg) {
		case required_argument:
			if (pexpect(optarg != NULL)) {
				jam_string(buf, " '");
				jam_string(buf, optarg);
				jam_string(buf, "'");
			}
			break;
		case optional_argument:
			if (optarg != NULL) {
				jam_string(buf, "='");
				jam_string(buf, optarg);
				jam_string(buf, "'");
			}
			break;
		case no_argument:
			if (pbad(optarg != NULL)) {
				jam_string(buf, " '");
				jam_string(buf, optarg);
				jam_string(buf, "'");
			}
			break;
		}
		jam_string(buf, " invalid, ");
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
	}
	/* not exit_pluto as pluto isn't yet up and running? */
	exit(PLUTO_EXIT_FAIL);
}

struct line {
	char buf[72];
};

static void newline(FILE *stream, struct line *line)
{
	if (!streq(line->buf, "\t")) {
		fprintf(stream, "%s\n", line->buf);
	}
	jam_str(line->buf, sizeof(line->buf), "\t");
}

void optarg_usage(const char *progname, const char *arguments,
		  const char *details)
{
	FILE *stream = stdout;

	struct line line;
	snprintf(line.buf, sizeof(line.buf), "Usage: %s", progname);

	for (const struct option *opt = optarg_options; opt->name != NULL; opt++) {

		const char *nm = opt->name;

		/*
		 * "\0heading"
		 *
		 * A zero length option string.  Assume the meta is a
		 * heading.
		 *
		 * Experimental, is this portable?
		 */
		if (*nm == '\0') {
			newline(stream, &line);
			/* output heading */
			fprintf(stream, "%s\n", nm + 1);
			continue;
		}

		if (startswith(nm, METAOPT_HEADING)) {
			newline(stream, &line);
			/* now print any heading */
			nm += strlen(METAOPT_HEADING);
			if (strlen(nm) > 0) {
				fprintf(stream, "%s\n", nm);
			}
			continue;
		}

		/* parse '\0...' meta characters */
		const char *meta = nm + strlen(nm);

		if (memeq(meta, METAOPT_REPLACE, 2)) {
			/*
			 * Option has been replaced, don't show old
			 * name.
			 */
			continue;
		}

		if (memeq(meta, METAOPT_IGNORE, 2)) {
			/*
			 * Option is no longer valid, skip.
			 */
			continue;
		}

		/* assume an option; more checks? */
		meta++; /* skip \0 */

		/* handle entry that forgot the argument */
		const char *argument = (*meta == '\0' ? "<argument>" : meta);

		char option[sizeof(line) - 1];
		switch (opt->has_arg) {
		case no_argument:
			snprintf(option, sizeof(option),  "[--%s]", nm);
			break;
		case optional_argument:
			snprintf(option, sizeof(option),  "[--%s[=%s]]", nm, argument);
			break;
		case required_argument:
			snprintf(option, sizeof(option),  "[--%s %s]", nm, argument);
			break;
		default:
			bad_case(opt->has_arg);
		}

		/* enough space? allow for separator, and null? */
		if (strlen(line.buf) + strlen(option) + 2 >= sizeof(line)) {
			/* finish current line */
			newline(stream, &line);
		} else if (!streq(line.buf, "\t")) {
			add_str(line.buf, sizeof(line.buf), " ");
		}

		add_str(line.buf, sizeof(line.buf), option);
	}

	if (arguments == NULL || strlen(arguments) == 0) {
		fprintf(stream, "%s\n", line.buf);
	} else if (strlen(line.buf) + strlen(arguments) + 2 >= sizeof(line.buf)) {
		fprintf(stream, "%s\n", line.buf);
		fprintf(stream, "\t%s\n", arguments);
	} else {
		fprintf(stream, "%s %s\n", line.buf, arguments);
	}

	if (details != NULL) {
		fprintf(stream, "%s", details);
	}

	fprintf(stream, "Libreswan %s\n", ipsec_version_code());
	exit(0);
}

/* return a non-empty string */
const char *optarg_nonempty(const struct logger *logger)
{
	const struct option *opt = &optarg_options[optarg_index];
	PEXPECT(logger, opt->has_arg == required_argument);
	if (optarg == NULL) {
		/* should not happen! */
		PEXPECT(logger, opt->has_arg == optional_argument);
		optarg_fatal(logger, "argument is missing");
	}
	if (strlen(optarg) == 0) {
		/* can't magic up a non-empty string so reject */
		optarg_fatal(logger, "must be non-empty");
	}
	return optarg; /* can't be empty, can't be NULL */
}

/* return a non-NULL string */
const char *optarg_empty(const struct logger *logger)
{
	const struct option *opt = &optarg_options[optarg_index];
	if (optarg == NULL) {
		/* turn missing argument into empty string */
		PEXPECT(logger, opt->has_arg == optional_argument);
		return "";
	}
	PEXPECT(logger, (opt->has_arg == optional_argument ||
			 opt->has_arg == required_argument));
	return optarg; /* could be empty, can't be NULL */
}

deltatime_t optarg_deltatime(const struct logger *logger, enum timescale default_timescale)
{
	passert((optarg_options[optarg_index].has_arg == required_argument) ||
		(optarg_options[optarg_index].has_arg == optional_argument && optarg != NULL));
	deltatime_t deltatime;
	diag_t diag = ttodeltatime(shunk1(optarg), &deltatime, default_timescale);
	if (diag != NULL) {
		optarg_fatal(logger, "%s", str_diag(diag));
	}
	return deltatime;
}

uintmax_t optarg_uintmax(const struct logger *logger)
{
	passert((optarg_options[optarg_index].has_arg == required_argument) ||
		(optarg_options[optarg_index].has_arg == optional_argument && optarg != NULL));
	if (streq(optarg, "-1")) {
		return UINTMAX_MAX;
	}

	uintmax_t val;
	err_t err = shunk_to_uintmax(shunk1(optarg), NULL, /*base*/0, &val);
	if (err == NULL) {
		return val;
	}

	optarg_fatal(logger, "%s", err);
}

uintmax_t optarg_udp_bufsize(const struct logger *logger)
{
	uintmax_t u;
	diag_t d = tto_scaled_uintmax(shunk1(optarg), &u, &binary_byte_scales);
	if (d != NULL) {
		/* leaks D; oops */
		optarg_fatal(logger, "%s", str_diag(d));
	}
	/* allow zero as "disable" */
	if (u == 0) {
		return 0;
	}
	/* 64k is max size for UDP (ignoring huge IPv6 packets) */
	if (u > 0xffff) {
		optarg_fatal(logger, "too big, more than 64KiB");
	}
	if (u < 1500) {
		optarg_fatal(logger, "too small, less than 1500");
	}
	return u;
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
		PEXPECT(logger, (optarg_options[optarg_index].has_arg == optional_argument ||
				 optarg_options[optarg_index].has_arg == no_argument));
		PEXPECT(logger, optional != 0);
		return optional;
	}

	PEXPECT(logger, (optarg_options[optarg_index].has_arg == optional_argument ||
			 optarg_options[optarg_index].has_arg == required_argument));
	/* stumble on */

	const struct sparse_name *name = sparse_lookup_by_name(names, shunk1(optarg));
	if (name == NULL) {
		JAMBUF(buf) {
			jam(buf, "'%s' is not recognised; valid arguments are: ", optarg);
			jam_sparse_names(buf, names, ", ");
			optarg_fatal(logger, PRI_SHUNK, pri_shunk(jambuf_as_shunk(buf)));
		}
	}
	return name->value;
}

enum yn_options optarg_yn(const struct logger *logger, enum yn_options optional)
{
	return optarg_sparse(logger, optional, &yn_option_names);
}

enum yne_options optarg_yne(const struct logger *logger, enum yne_options optional)
{
	return optarg_sparse(logger, optional, &yne_option_names);
}

enum yna_options optarg_yna(const struct logger *logger, enum yna_options optional)
{
	return optarg_sparse(logger, optional, &yna_option_names);
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

ip_address optarg_address_num(const struct logger *logger, struct optarg_family *family)
{
	ip_address address;
	err_t err = ttoaddress_num(shunk1(optarg), family->type, &address);
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

void optarg_debug_lmod(enum optarg_debug debug, lmod_t *mods)
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
				name_buf help;
				if (enum_long(&debug_help, e, &help)) {
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
	const struct option *option = &optarg_options[optarg_index];
	if (!ttolmod(shunk1(optarg), mods, &debug_lmod_info, debug == OPTARG_DEBUG_YES)) {
		fprintf(stderr, "whack: unrecognized --%s%s'%s' option ignored\n",
			option->name,
			(option->has_arg == optional_argument ? "=" : " "),
			optarg);
	}
}

void optarg_debug(enum optarg_debug debug)
{
	if (optarg == NULL) {
		cur_debugging = (debug == OPTARG_DEBUG_YES ? DBG_ALL :
				 debug == OPTARG_DEBUG_NO ? DBG_NONE :
				 0);
	} else {
		lmod_t mods = {0};
		optarg_debug_lmod(debug, &mods);
		cur_debugging = lmod(cur_debugging, mods);
	}
}

