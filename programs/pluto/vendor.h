/* Libreswan ISAKMP VendorID
 *
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
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

#ifndef _VENDOR_H_
#define _VENDOR_H_

#include "known_vendorid.h"
#include "packet.h"		/* for pb_stream */
#include "shunk.h"

struct msg_digest;
struct connection;
struct logger;

void init_vendorid(struct logger *logger);

void handle_vendorid(struct msg_digest *md, shunk_t vid,
		     bool ikev2, struct logger *logger);

bool out_v1VID(struct pbs_out *outs, unsigned int vid);

bool out_v1VID_set(struct pbs_out *outs, const struct connection *c);

bool vid_is_oppo(const char *vid, size_t len);

bool emit_v2V(struct pbs_out *outs, const char *vid);
bool emit_v2VID(struct pbs_out *outs, enum known_vendorid);

#endif /* _VENDOR_H_ */
