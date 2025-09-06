/* ipsec redirect ..., for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2014-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019-2023 Andrew Cagney <cagney@gnu.org>
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

#include "whack_redirect.h"

#include "whack.h"
#include "show.h"
#include "jambuf.h"

#include "ikev2_redirect.h"

void jam_whack_redirect(struct jambuf *buf, const struct whack_message *wm)
{
	if (wm->redirect_to != NULL) {
		jam_string(buf, " redirect-to=");
		jam_string(buf, wm->redirect_to);
	}
	if (wm->global_redirect != 0) {
		jam_string(buf, " redirect_to=");
		jam_sparse_long(buf, &yna_option_names, wm->global_redirect);
	}
}

void whack_active_redirect(const struct whack_message *wm, struct show *s)
{
	struct logger *logger = show_logger(s);
	/*
	 * We are redirecting all peers of one or all connections.
	 *
	 * Whack's --redirect-to is ambitious - is it part of an ADD
	 * or a global op?  Checking .whack_add.
	 */
	find_and_active_redirect_states(wm->name, wm->redirect_to, logger);
}

void whack_global_redirect(const struct whack_message *wm, struct show *s)
{
	set_global_redirect(wm->global_redirect,
			    wm->redirect_to,
			    show_logger(s));
}
