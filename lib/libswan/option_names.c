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
	{ "yes",        YES },                  \
       { "no",         NO },			\
       { "true",       YES },			\
       { "false",      NO },			\
       { "on",         YES },			\
       { "off",        NO },			\
       { "y",          YES },			\
       { "n",          NO }

/* match <BOOLEAN_VALUE> in parser.lex */
const struct sparse_name yn_option_names[] = {
	YES_NO(YN_YES, YN_NO),
	/*
	 * These are unique to YN, and probably should be dropped
	 * completely.  Some keywords, such as yndev, interpret "1"
	 * and "0".
	 */
	{ "1",          YN_YES, },
	{ "0",          YN_NO, },
	SPARSE_NULL,
};

/*
 * Values for yes/no/force, used by fragmentation=
 */
const struct sparse_name ynf_option_names[] = {
	YES_NO(YNF_YES, YNF_NO),
	{ "force",     YNF_FORCE },
	{ "never",     YNF_NO },
	{ "insist",    YNF_FORCE },
	SPARSE_NULL
};
