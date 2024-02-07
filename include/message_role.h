/* message role, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019-2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#ifndef MESSAGE_ROLE_H
#define MESSAGE_ROLE_H

/*
 * The IKEv2 message role.  Is this message a request or a response
 * (to a request) as determined by the IKEv2 "R (Response)" flag.
 *
 * Since either end can initiate a request either end can set the
 * R(Response) flag.
 *
 * During a CHILD_SA exchange it is the request initiator (receives
 * the MESSAGE_RESPONSE) and request responder (receives the
 * MESSAGE_REQUEST), and not the original (IKE SA) initiator /
 * responder that determine how crypto material is carved up.
 */

enum message_role {
#define MESSAGE_ROLE_FLOOR NO_MESSAGE
	NO_MESSAGE = 0,
	MESSAGE_REQUEST = 1, /* MSG_R missing */
	MESSAGE_RESPONSE = 2, /* MSR_R present */
#define MESSAGE_ROLE_ROOF (MESSAGE_RESPONSE+1)
};

extern const struct enum_names message_role_names;

#endif
