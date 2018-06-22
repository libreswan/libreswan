/* peer logging declarations, for libreswan
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2004 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2017 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef _PLUTO_PEERLOG_H
#define _PLUTO_PEERLOG_H

#include <libreswan.h>

#include "lswlog.h"

struct connection;

extern bool log_to_perpeer;         /* should log go to per-IP file? */
extern char *peerlog_basedir;

void peerlog_init(void);

/* close of all per-peer logging */
void peerlog_close(void);

/* free all per-peer log resources */
void perpeer_logfree(struct connection *c);

/* log to the peers */
void peerlog(struct connection *cur_connection, const char *buf);

#endif /* _PLUTO_PEERLOG_H */
