/* Server thread pool, for libreswan
 *
 * Copyright (C) 2004-2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008,2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
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

/*
 * This is an internal interface between the main thread and the
 * helper threads (thread pool).
 *
 * The helper threads performs the heavy lifting, such as
 * cryptographic functions, for pluto.  It does this to avoid bogging
 * down the main thread with cryptography, increasing throughput.
 */

#ifndef HELPERS_H
#define HELPERS_H

struct help_request;

#define alloc_help_request(WHAT, DISCARD_CONTENT, OWNER)		\
	({								\
		static const struct refcnt_base help_request_base = {	\
			.what = WHAT,					\
			.discard_content = DISCARD_CONTENT,		\
		};							\
		struct help_request *request_ =				\
			alloc_thing(struct help_request, WHAT);		\
		refcnt_init(request_, &request_->refcnt,		\
			    &help_request_base, OWNER, HERE);		\
		request_;						\
	})

enum helper_id {
	INLINE_HELPER_ID = -1,
	UNASSIGNED_HELPER_ID = 0,
	FIRST_HELPER_ID = 1,
};

typedef void (helper_cb)(struct help_request *request,
			 const struct logger *logger);
typedef helper_cb *(helper_fn)(struct help_request *request,
			       const struct logger *logger,
			       enum helper_id id);

void request_help_where(struct refcnt *request,
			helper_fn *helper,
			struct logger *logger,
			where_t where);
#define request_help(REQUEST, HELPER, LOGGER)			\
	{							\
		struct help_request *request_ = REQUEST;	\
		request_help_where(&request_->refcnt,		\
				   HELPER, LOGGER, HERE);	\
	}

void start_helpers(uintmax_t nhelpers, struct logger *logger);
void stop_helpers(void (*all_server_helpers_stopped)(void), struct logger *logger);
void free_help_requests(struct logger *logger);
unsigned nhelpers(void);

#endif
