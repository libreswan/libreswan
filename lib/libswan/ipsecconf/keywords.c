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
#include "lswlog.h"
#include "lswalloc.h"

#include "ipsecconf/config_conn.h"
#include "ipsecconf/config_setup.h"

enum config_section { CONFIG_SETUP, CONFIG_CONN };

static void check_config_keywords(struct logger *logger,
				  const enum config_section section,
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

	enum { NAME, ALIAS, OBSOLETE } group = NAME;

	ITEMS_FOR_EACH(k, keywords) {

		/*
		 * Ignore gaps, happens when #ifdefs are at play.
		 */

		if (k->keyname == NULL) {
			continue;
		}

		bool ok = true;
		unsigned i = (k - keywords->item);

		switch (group) {
		case NAME:
			if (k->validity & kv_alias) {
				group = ALIAS;
				break;
			}
			if (k->field == KNCF_OBSOLETE) {
				group = OBSOLETE;
				break;
			}
			break;
		case ALIAS:
			if (k->field == KNCF_OBSOLETE) {
				group = OBSOLETE;
				break;
			}
			break;
		case OBSOLETE:
			break;
		}

		ok &= pexpect(k->validity & kv_alias ? group == ALIAS :
			      group == NAME || group == OBSOLETE);
		ok &= pexpect(k->field == KNCF_OBSOLETE ? group == OBSOLETE :
			      group == NAME || group == ALIAS);
		ok &= pexpect(k->type == kt_obsolete ? group == OBSOLETE :
			      group == NAME || group == ALIAS);

		ok &= pexpect(group == NAME ? i == k->field : i > k->field);
		ok &= pexpect(group == OBSOLETE ? k->sparse_names == NULL : true);

		switch (section) {
		case CONFIG_SETUP:
			ok &= pexpect((k->field >= CONFIG_SETUP_KEYWORD_FLOOR &&
				       k->field < CONFIG_SETUP_KEYWORD_ROOF) ||
				      k->field == KNCF_OBSOLETE);
			ok &= pexpect((k->validity & (kv_leftright | kv_both)) == LEMPTY);
			break;
		case CONFIG_CONN:
			ok &= pexpect((k->field >= CONFIG_CONN_KEYWORD_FLOOR &&
				       k->field < CONFIG_CONN_KEYWORD_ROOF) ||
				      k->field == KNCF_OBSOLETE);
			break;
		}

		/* above checked k->field in range; check things,
		 * notably aliases, point back to a real NAME */
		ok &= pexpect(k->field < keywords->len);
		ok &= pexpect(group == OBSOLETE ? keywords->item[k->field].keyname == NULL/*entry 0*/ :
			      keywords->item[k->field].keyname != NULL);
		ok &= pexpect(group == OBSOLETE ? keywords->item[k->field].field == 0/*entry 0*/ :
			      keywords->item[k->field].field == k->field);
		ok &= pexpect(group == OBSOLETE ? keywords->item[k->field].validity == 0/*entry 0*/ :
			      keywords->item[k->field].validity == (k->validity & ~kv_alias));

		if (!ok) {
			llog_pexpect(logger, HERE, "[%u:%u] '%s' (follows '%s') expecting %s-%s",
				     i, k->field,
				     k->keyname,
				     (i > 0 ? keywords->item[i-1].keyname : "???"),
				     (section == CONFIG_SETUP ? "setup" :
				      section == CONFIG_CONN ? "conn" :
				      "???"),
				     (group == NAME ? "name" :
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

	check_config_keywords(logger, CONFIG_SETUP, &config_setup_keywords);
	check_config_keywords(logger, CONFIG_CONN, &config_conn_keywords);
}
