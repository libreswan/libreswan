/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 *
 * Copyright (C) 1999-2001  D. Hugh Redelmeier
 * Copyright (C) 2019-2020 Andrew Cagney <cagney@gnu.org>
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

#ifndef ID_H
#define ID_H

#include "ietf_constants.h"	/* for enum ike_id_type */
#include "chunk.h"
#include "err.h"
#include "ip_address.h"
#include "jambuf.h"		/* for typedef jam_bytes_fn */
#include "verbose.h"

struct id {
	enum ike_id_type kind;

	/* used for ID_IPV4_ADDR, ID_IPV6_ADDR */
	ip_address ip_addr;

	/* used for ID_FQDN, ID_USER_FQDN, ID_KEY_ID, ID_DER_ASN_DN */
	shunk_t name;

	/* when non-NULL, delete */
	void *scratch;
};

struct id_list {
	struct id id;
	struct id_list *next;
};

extern const struct id empty_id;	/* ID_NONE */

/*
 * parsing.
 */

err_t atoid(const char *src, struct id *id);

/*
 * Formatting.
 *
 * The primitive jam_id_bytes() only outputs printable ASCII.  This
 * means that the two calls:
 *
 *     jam_id_bytes(jam_raw_bytes)
 *     jam_id_bytes(jam_sanitized_bytes)
 *
 * are equivalent (the latter would never encounter a character
 * needing sanitizing).
 *
 * Hence str_id() is implemented using jam_id_bytes(jam_raw_bytes).
 * However, callers will often specify jam_sanitized_bytes() just to
 * be sure.
 *
 * However, it isn't good for shell commands et.al..  Use
 * jam_shell_quoted_bytes(), for instance, to apply additional
 * escaping.
 */

typedef struct {
	char buf[512];
} id_buf;

size_t jam_id_bytes(struct jambuf *buf, const struct id *id, jam_bytes_fn *jam_bytes);
const char *str_id_bytes(const struct id *id, jam_bytes_fn *jam_bytes, id_buf *buf);

size_t jam_id(struct jambuf *buf, const struct id *id);
const char *str_id(const struct id *id, id_buf *buf);

/*
 * Operations.
 */

struct id clone_id(const struct id *id, const char *why);
extern void free_id_content(struct id *id); /* also blats ID */

extern bool id_is_any(const struct id *a);
extern bool id_eq(const struct id *a, const struct id *b);
extern bool same_id(const struct id *a, const struct id *b); /* fuzzy */
#define MAX_WILDCARDS	15
extern bool match_id(const struct id *a, const struct id *b,
		     int *wildcards, struct verbose verbose);
extern bool id_has_wildcards(const struct id *id);
#define id_is_ipaddr(id) ((id)->kind == ID_IPV4_ADDR || (id)->kind == ID_IPV6_ADDR)

/* returns ID Type; and points body at Identification Data */
enum ike_id_type id_to_payload(const struct id *id, const ip_address *host, shunk_t *body);

#endif
