/* Libreswan command interface to Pluto
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2004-2006  Michael Richardson <mcr@xelerance.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>
#include <stdarg.h>

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "whack.h"
#include "lswlog.h"
#include "ip_info.h"

/*
 * Pack and unpack bytes
 */

static bool pack_raw(struct whackpacker *wp,
		     void **bytes, size_t nr_bytes,
		     const char *what)
{
	if (wp->str_next + nr_bytes > wp->str_roof) {
		DBGF(DBG_TMI, "%s: buffer overflow for '%s'",
		    __func__, what);
		return false; /* would overflow buffer */
	}
	memcpy(wp->str_next, *bytes, nr_bytes);
	wp->str_next += nr_bytes;
	return true;
}

static bool unpack_raw(struct whackpacker *wp,
		       void **bytes, size_t nr_bytes,
		       const char *what)
{
	uint8_t *end = wp->str_next + nr_bytes;
	if (end > wp->str_roof) {
		/* overflow */
		DBGF(DBG_TMI, "%s: buffer overflow for '%s'; needing %zu bytes",
		    __func__, what, nr_bytes);
		return false;
	}
	*bytes = wp->str_next;
	wp->str_next = end;
	return true;
}

/*
 * Pack and unpack a memory hunks.
 *
 * Notes:
 *
 * - to prevent the hunk pointer going across the wire, it is set to
 *   NULL after packing
 *
 * - the unpacked pointer points into the whack message do don't free
 *   it
 *
 * - zero length pointers are converted to NULL pointers
 */

#define PACK_HUNK(WP, HUNK, WHAT)					\
	{								\
		if (hunk_isempty(*HUNK)) {				\
			HUNK->ptr = NULL; /* be safe */			\
			return true;					\
		}							\
		if (!pack_raw(WP, (void**)&(HUNK)->ptr,			\
			      HUNK->len, WHAT)) {			\
			return false;					\
		}							\
		HUNK->ptr = NULL; /* kill pointer being sent on wire! */ \
		return true;						\
	}

#define UNPACK_HUNK(WP, HUNK, WHAT)					\
	{								\
		if (HUNK->len == 0) {					\
			/* expect wire-pointer to be NULL */		\
			pexpect(HUNK->ptr == NULL);			\
			HUNK->ptr = NULL;				\
			return true;					\
		}							\
		if (!unpack_raw(WP, (void**)&(HUNK)->ptr,		\
				HUNK->len, WHAT)) {			\
			return false;					\
		}							\
		return true;						\
	}

static bool pack_chunk(struct whackpacker *wp, chunk_t *chunk, const char *what)
{
	PACK_HUNK(wp, chunk, what);
}

static bool unpack_chunk(struct whackpacker *wp, chunk_t *chunk, const char *what)
{
	UNPACK_HUNK(wp, chunk, what);
}

static bool pack_shunk(struct whackpacker *wp, shunk_t *shunk, const char *what)
{
	PACK_HUNK(wp, shunk, what);
}

static bool unpack_shunk(struct whackpacker *wp, shunk_t *shunk, const char *what)
{
	UNPACK_HUNK(wp, shunk, what);
}

/*
 * Pack and unpack a nul-terminated string to a whack messages
 *
 * Notes:
 *
 * - to prevent the string pointer going across the wire, it is set to
 *   NULL after packing
 *
 * - the unpacked pointer stored in *P points into the whack message
 *   do don't free it
 *
 * - NULL pointers are converted to ""
 */

static bool pack_string(struct whackpacker *wp, char **p, const char *what)
{
	const char *s = (*p == NULL ? "" : *p); /* note: NULL becomes ""! */
	size_t len = strlen(s) + 1;

	if (wp->str_roof - wp->str_next < (ptrdiff_t)len) {
		DBGF(DBG_TMI, "%s: buffer overflow for '%s'",
		    __func__, what);
		return false; /* would overflow buffer */
	}

	strcpy((char *)wp->str_next, s);
	wp->str_next += len;
	*p = NULL; /* kill pointer being sent on wire! */
	return true;
}

static bool unpack_string(struct whackpacker *wp, char **p, const char *what)
{
	/* expect wire-pointer to be NULL */
	pexpect(*p == NULL);

	uint8_t *end = memchr(wp->str_next, '\0', (wp->str_roof - wp->str_next) );
	if (end == NULL) {
		DBGF(DBG_TMI, "%s: buffer overflow for '%s'; missing NUL",
		    __func__, what);
		return false; /* fishy: no end found */
	}

	unsigned char *s = (wp->str_next == end ? NULL : wp->str_next);

	DBGF(DBG_TMI, "%s: '%s' is %ld bytes", __func__, what, (long int)(end - wp->str_next));

	*p = (char *)s;
	wp->str_next = end + 1;
	return true;
}

/*
 * IP pointers.
 */

static bool pack_ip_info(struct whackpacker *wp UNUSED,
			 const struct ip_info **info,
			 const char *what UNUSED)
{
	/* spell out conversions */
	enum ip_version v = (*info == NULL ? 0 : (*info)->ip_version);
	*info = (const void*)(uintptr_t)(unsigned)v;
	return true;
}

static bool unpack_ip_info(struct whackpacker *wp UNUSED,
			   const struct ip_info **info,
			   const char *what UNUSED)
{
	/* spell out conversions */
	*info = ip_version_info((unsigned)(uintptr_t)(const void*)*info);
	return true;
}

static bool pack_ip_protocol(struct whackpacker *wp UNUSED,
			     const struct ip_protocol **protocol,
			     const char *what UNUSED)
{
	/* spell out conversions */
	*protocol = (const void*)(uintptr_t)(unsigned)(*protocol)->ipproto;
	return true;
}

static bool unpack_ip_protocol(struct whackpacker *wp UNUSED,
			       const struct ip_protocol **protocol,
			       const char *what UNUSED)
{
	/* spell out conversions */
	*protocol = protocol_from_ipproto((unsigned)(uintptr_t)(const void*)*protocol);
	return *protocol != NULL;
}

static bool pack_constant_string(struct whackpacker *wp UNUSED,
				 const char **string,
				 const char *constant,
				 const char *what)
{
	if (*string != NULL) {
		DBGF(DBG_TMI, "%s: '%s' was: %s (%s)", __func__, what, *string, constant);
		passert(streq(*string, constant));
		*string = NULL;
	} else {
		/*
		 * For instance, when whack sends constrol messages
		 * such as "status" the whack_end .leftright field is
		 * still NULL.
		 *
		 * The unpack will set the field, oops.
		 */
		DBGF(DBG_TMI, "%s: '%s' was null (%s)", __func__, what, constant);
	}
	return true;
}

static bool unpack_constant_string(struct whackpacker *wp UNUSED,
				 const char **string,
				 const char *constant,
				 const char *what)
{
	pexpect(*string == NULL);
	*string = constant;
	DBGF(DBG_TMI, "%s: '%s' is %s", __func__, what, *string);
	return true;
}

/*
 * in and out/
 */
struct pickler {
	bool (*string)(struct whackpacker *wp, char **p, const char *what);
	bool (*shunk)(struct whackpacker *wp, shunk_t *s, const char *what);
	bool (*chunk)(struct whackpacker *wp, chunk_t *s, const char *what);
	bool (*raw)(struct whackpacker *wp, void **bytes, size_t nr_bytes, const char *what);
	bool (*ip_info)(struct whackpacker *wp, const struct ip_info **info, const char *what);
	bool (*ip_protocol)(struct whackpacker *wp, const struct ip_protocol **protocol, const char *what);
	bool (*constant_string)(struct whackpacker *wp, const char **p, const char *leftright, const char *what);
};

const struct pickler pickle_packer = {
	.string = pack_string,
	.shunk = pack_shunk,
	.chunk = pack_chunk,
	.raw = pack_raw,
	.ip_info = pack_ip_info,
	.ip_protocol = pack_ip_protocol,
	.constant_string = pack_constant_string,
};

const struct pickler pickle_unpacker = {
	.string = unpack_string,
	.shunk = unpack_shunk,
	.chunk = unpack_chunk,
	.raw = unpack_raw,
	.ip_info = unpack_ip_info,
	.ip_protocol = unpack_ip_protocol,
	.constant_string = unpack_constant_string,
};

#define PICKLE_STRING(FIELD) pickle->string(wp, FIELD, #FIELD)
#define PICKLE_CHUNK(FIELD) pickle->chunk(wp, FIELD, #FIELD)
#define PICKLE_SHUNK(FIELD) pickle->shunk(wp, FIELD, #FIELD)
#define PICKLE_THINGS(THINGS, NR) pickle->raw(wp, (void**)(THINGS), NR*sizeof((THINGS)[0][0]), #THINGS)
#define PICKLE_CONSTANT_STRING(FIELD, VALUE) pickle->constant_string(wp, FIELD, VALUE, #FIELD)
#define PICKLE_IP_INFO(FIELD) pickle->ip_info(wp, FIELD, #FIELD)

#if 0
#define PICKLE_CIDR(CIDR) \
	((CIDR)->is_set ? pickle->ip_info(wp, &((CIDR)->info), #CIDR) : true)
#else
#define PICKLE_CIDR(CIDR) true
#endif

static bool pickle_whack_end(struct whackpacker *wp,
			     const char *leftright,
			     struct whack_end *end,
			     const struct pickler *pickle)
{
	return (PICKLE_CONSTANT_STRING(&end->leftright, leftright),
		PICKLE_STRING(&end->id) &&
		PICKLE_STRING(&end->cert) &&
		PICKLE_STRING(&end->pubkey) &&
		PICKLE_STRING(&end->ckaid) &&
		PICKLE_STRING(&end->ca) &&
		PICKLE_STRING(&end->groups) &&
		PICKLE_STRING(&end->updown) &&
		PICKLE_STRING(&end->virt) &&
		PICKLE_STRING(&end->xauth_username) &&
		PICKLE_STRING(&end->host_addr_name) &&
		PICKLE_CIDR(&end->host_vtiip) &&
		PICKLE_CIDR(&end->ifaceip) &&
		PICKLE_STRING(&end->addresspool) &&
		PICKLE_STRING(&end->subnet) &&
		PICKLE_STRING(&end->sourceip) &&
		PICKLE_STRING(&end->groundhogday) &&
		true);
}

static bool pickle_whack_message(struct whackpacker *wp, const struct pickler *pickle)
{
	return (PICKLE_STRING(&wp->msg->name) && /* first */
		pickle_whack_end(wp, "left", &wp->msg->left, pickle) &&
		pickle_whack_end(wp, "right",&wp->msg->right, pickle) &&
		PICKLE_STRING(&wp->msg->keyid) &&
		PICKLE_STRING(&wp->msg->ike) &&
		PICKLE_STRING(&wp->msg->esp) &&
		PICKLE_STRING(&wp->msg->connalias) &&
		PICKLE_STRING(&wp->msg->string1) &&
		PICKLE_STRING(&wp->msg->string2) &&
		PICKLE_STRING(&wp->msg->string3) &&
		PICKLE_STRING(&wp->msg->dnshostname) &&
		PICKLE_STRING(&wp->msg->modecfg_dns) &&
		PICKLE_STRING(&wp->msg->modecfg_domains) &&
		PICKLE_STRING(&wp->msg->modecfg_banner) &&
		PICKLE_STRING(&wp->msg->conn_mark_both) &&
		PICKLE_STRING(&wp->msg->conn_mark_in) &&
		PICKLE_STRING(&wp->msg->conn_mark_out) &&
		PICKLE_STRING(&wp->msg->vti_iface) &&
		PICKLE_STRING(&wp->msg->remote_host) &&
		PICKLE_STRING(&wp->msg->global_redirect_to) &&
		PICKLE_STRING(&wp->msg->redirect_to) &&
		PICKLE_STRING(&wp->msg->accept_redirect_to) &&
		PICKLE_STRING(&wp->msg->active_redirect_dests) &&
		PICKLE_CHUNK(&wp->msg->keyval) &&
		PICKLE_THINGS(&wp->msg->impairments, wp->msg->nr_impairments) &&
		PICKLE_STRING(&wp->msg->sec_label) &&
		PICKLE_IP_INFO(&wp->msg->host_afi) &&
		PICKLE_IP_INFO(&wp->msg->child_afi) &&
		PICKLE_STRING(&wp->msg->dpd_timeout) &&
		PICKLE_STRING(&wp->msg->dpd_delay) &&
		true);
}

/**
 * Pack a message to be sent to whack
 *
 * @param wp The whack message
 * @return err_t
 */
err_t pack_whack_msg(struct whackpacker *wp)
{
	/* Pack strings */

	wp->str_next = wp->msg->string;
	wp->str_roof = &wp->msg->string[sizeof(wp->msg->string)];
	if (!pickle_whack_message(wp, &pickle_packer)) {
		return "too many bytes of strings or key to fit in message to pluto";
	}
	return NULL;
}

/**
 * Unpack a message whack received
 *
 * @param wp The whack message
 * @return err_t
 */
bool unpack_whack_msg(struct whackpacker *wp, struct logger *logger)
{
	if (wp->str_next > wp->str_roof) {
		llog(RC_BADWHACKMESSAGE, logger,
			    "ignoring truncated message from whack: got %d bytes; expected %zu",
			    wp->n, sizeof(wp->msg));
		return false;
	}

	if (!pickle_whack_message(wp, &pickle_unpacker)) {
		llog(RC_BADWHACKMESSAGE, logger,
			    "message from whack contains bad string or key");
		return false;
	}

	return true;
}

void clear_end(const char *leftright, struct whack_end *e)
{
	static const struct whack_end zero_end;	/* zeros and NULL pointers */
	*e = zero_end;
	e->leftright = leftright;
}

int whack_get_value(char *buf, size_t bufsize)
{
	int len;
	int try;

	fflush(stdout);

	try = 3;
	len = 0;
	while (try > 0 && len == 0) {
		fprintf(stderr, "Enter username:   ");

		memset(buf, 0, bufsize);

		if (fgets(buf, bufsize, stdin) != buf) {
			if (errno == 0) {
				fprintf(stderr,
					"Cannot read username from standard in\n");
				exit(RC_WHACK_PROBLEM);
			} else {
				perror("fgets value");
				exit(RC_WHACK_PROBLEM);
			}
		}

		/* send the value to pluto, including \0, but fgets adds \n */
		len = strlen(buf);
		if (len == 0)
			fprintf(stderr, "answer was empty, retry\n");

		try--;
	}

	if (len ==  0)
		exit(RC_WHACK_PROBLEM);

	return len;
}

/* Get password from user.  Truncate it to fit in buf. */
/* ??? the function getpass(3) is obsolete! */
size_t whack_get_secret(char *buf, size_t bufsize)
{
	fflush(stdout);
	assert(bufsize > 0);	/* room for terminal NUL */

	char *secret = getpass("Enter passphrase: ");
	/* jam_str would be good but it requires too much library */
	size_t len = strlen(secret) + 1;
	size_t trunc_len = len <= bufsize ? len : bufsize;

	memcpy(buf, secret, trunc_len);
	buf[trunc_len-1] = '\0';	/* force NUL termination */
	memset(secret, 0, len);	/* scrub secret from RAM */
	return trunc_len;
}
