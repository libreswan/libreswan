/* Libreswan config file parser keywords processor
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013-2016 Antony Antony <antony@phenome.org>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020, Yulia Kuzovkova <ukuzovkova@gmail.com>
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
 *
 */

#ifndef IPSECCONF_KEYWORDS_H
#define IPSECCONF_KEYWORDS_H

#include "lset.h"	/* for LELEM() */

struct logger;

enum keyword_field {
	KEYWORD_FIELD_UNSET = 0,
	KEYWORD_FIELD_FLOOR = 1,
};

/* these are bits set in a word */
enum keyword_valid_ix {
	KV_LEFTRIGHT_IX,        /* comes in left-FOO and right-FOO
				 * variants */
	KV_BOTH_IX,		/* FOO means left-FOO and right-FOO */
	KV_ALIAS_IX,		/* is an alias for another keyword */
	KV_DUPLICATEOK_IX,	/* within a connection, the item can
				 * be duplicated (notably also=) */
	KV_OPTARG_ONLY_IX,	/* pretend entry does not exist; only
				 * allowed on command line */
};

enum keyword_valid {
        kv_leftright	= LELEM(KV_LEFTRIGHT_IX),
        kv_both		= LELEM(KV_BOTH_IX),
        kv_alias	= LELEM(KV_ALIAS_IX),
        kv_optarg_only	= LELEM(KV_OPTARG_ONLY_IX),
        kv_duplicateok	= LELEM(KV_DUPLICATEOK_IX),
};

enum keyword_type {
	kt_string,              /* value is some string */
	kt_appendstring,        /* value is some string, append duplicates */
	kt_appendlist,          /* value is some list, append duplicates */
	kt_sparse_name,         /* value is from .sparse_name table */
	kt_unsigned,            /* an unsigned integer */
	kt_seconds,             /* deltatime, default in seconds */
	kt_also,		/* i.e., #include */
	kt_obsolete,            /* option that is obsoleted, allow
				 * keyword but warn and ignore */
	kt_nosup,		/* Option is not enabled in build */
};

struct keyword_def {
	const char        *keyname;
	unsigned int validity;          /* has bits from enum keyword_valid (kv_*) */
	enum keyword_type type;
	unsigned int field;             /* one of keyword_*_field */
	const struct sparse_names *sparse_names;
};

/*
 * may contain gaps due to #ifdefs
 */

struct keywords_def {
	unsigned len;
	const struct keyword_def *item;
};

extern const struct keywords_def config_setup_keywords;
extern const struct keywords_def config_conn_keywords;

void check_ipsec_conf_keywords(struct logger *logger);

#endif /* _KEYWORDS_H_ */
