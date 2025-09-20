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

#include "ipsecconf/keywords.h"
#include "ipsecconf/config_setup.h"
#include "ipsecconf/config_conn.h"
#include "lswlog.h"
#include "lswalloc.h"

enum config_section { CONFIG_SETUP, CONFIG_CONN };

static void check_config_keywords(struct logger *logger,
				  const enum config_section section,
				  size_t config_keyword_roof,
				  const struct keywords_def *keywords)
{
	if (LDBGP(DBG_TMI, logger)) {
		ITEMS_FOR_EACH(k, keywords) {
			if (k->keyname == NULL) {
				continue;
			}
			unsigned i = (k - keywords->item);
			LDBG_log(logger, "[%u] %s", i, k->keyname);
		}
	}

	/* table contains ALIAS and OBSOLETE keywords at the end */
	pexpect(keywords->len >= config_keyword_roof);

	enum { BLANK, NAME, ALIAS, OBSOLETE } group = BLANK;

	ITEMS_FOR_EACH(k, keywords) {

		bool ok = true;
		unsigned ki = (k - keywords->item);

		switch (group) {
		case BLANK:
			if (ki > 0) {
				group = NAME;
			}
			break;
		case NAME:
			if (k->validity & kv_alias) {
				group = ALIAS;
				break;
			}
			if (k->field == KEYWORD_FIELD_UNSET) {
				group = OBSOLETE;
				break;
			}
			break;
		case ALIAS:
			if (k->field == KEYWORD_FIELD_UNSET) {
				group = OBSOLETE;
				break;
			}
			break;
		case OBSOLETE:
			break;
		}

		ok &= pexpect(group == BLANK ? ki == 0 :
			      group == NAME ? ki < config_keyword_roof :
			      group == ALIAS ? ki < keywords->len :
			      group == OBSOLETE ? ki < keywords->len :
			      false);

		ok &= pexpect(group == BLANK ? k->field == 0 :
			      group == NAME ? k->field == ki :
			      group == ALIAS ? k->field > 0 && k->field < config_keyword_roof :
			      group == OBSOLETE ? k->field == 0 :
			      false);

		ok &= pexpect(group == BLANK ? k->keyname == NULL :
			      group == NAME ? k->keyname != NULL :
			      group == ALIAS ? (k->keyname != NULL &&
						/* aliases point back to a real NAME */
						keywords->item[k->field].keyname != NULL) :
			      group == OBSOLETE ? k->keyname != NULL :
			      false);

		ok &= pexpect(group == BLANK ? k->validity == LEMPTY :
			      group == NAME ? true :
			      group == ALIAS ? ((k->validity & kv_alias) &&
						/* alias has same validity as real keyword */
						keywords->item[k->field].validity == (k->validity & ~kv_alias)) :
			      group == OBSOLETE ? k->validity == LEMPTY :
			      false);

		ok &= pexpect(group == BLANK ? k->type == 0 :
			      group == NAME ? k->type != kt_obsolete :
			      group == ALIAS ? k->type != kt_obsolete :
			      group == OBSOLETE ? k->type == kt_obsolete :
			      false);

		ok &= pexpect(group == BLANK ? k->sparse_names == NULL :
			      group == NAME ? (k->sparse_names != NULL) == (k->type == kt_sparse_name) :
			      group == ALIAS ? (k->sparse_names != NULL) == (k->type == kt_sparse_name) :
			      group == OBSOLETE ? k->sparse_names == NULL :
			      false);

		switch (section) {
		case CONFIG_SETUP:
			ok &= pexpect((k->validity & (kv_leftright | kv_both)) == LEMPTY);
			break;
		case CONFIG_CONN:
			break;
		}

		if (!ok) {
			llog_pexpect(logger, HERE, "[%u:%u] '%s' (follows '%s') expecting %s-%s",
				     ki, k->field,
				     k->keyname,
				     (ki > 0 ? keywords->item[ki-1].keyname : "???"),
				     (section == CONFIG_SETUP ? "setup" :
				      section == CONFIG_CONN ? "conn" :
				      "???"),
				     (group == BLANK ? "blank" :
				      group == NAME ? "name" :
				      group == ALIAS ? "alias" :
				      group == OBSOLETE ? "obsolete" :
				      "???"));
			break;
		}
	}
}

void check_ipsec_conf_keywords(struct logger *logger)
{
	static bool checked;
	if (checked) {
		return;
	}
	checked = true;

	check_config_keywords(logger, CONFIG_SETUP, CONFIG_SETUP_KEYWORD_ROOF, &config_setup_keywords);
	check_config_keywords(logger, CONFIG_CONN, CONFIG_CONN_KEYWORD_ROOF, &config_conn_keywords);
}
