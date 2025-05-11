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

#include <stdbool.h>
#include <stddef.h>

#include "whack.h"
#include "lswlog.h"
#include "ip_info.h"

/*
 * Pack and unpack bytes
 */

static bool pack_bytes(struct whackpacker *wp,
		       const void *bytes, size_t nr_bytes,
		       const char *what,
		       struct logger *logger)
{
	size_t space = wp->str_roof - wp->str_next;
	if (space < nr_bytes) {
		llog(RC_LOG, logger, "buffer overflow for '%s', space for %zu bytes but need %zu",
		     what, space, nr_bytes);
		return false; /* would overflow buffer */
	}
	memcpy(wp->str_next, bytes, nr_bytes);
	wp->str_next += nr_bytes;
	return true;
}

static bool pack_raw(struct whackpacker *wp,
		     void **bytes, size_t nr_bytes,
		     const char *what,
		     struct logger *logger)
{
	if (!pack_bytes(wp, (*bytes), nr_bytes, what, logger)) {
		return false;
	}
	(*bytes) = NULL;
	return true;
}

static bool unpack_raw(struct whackpacker *wp,
		       void **bytes, size_t nr_bytes,
		       const char *what,
		       struct logger *logger)
{
	size_t space = wp->str_roof - wp->str_next;
	if (space < nr_bytes) {
		/* overflow */
		llog(RC_LOG, logger, "buffer overflow for '%s'; have %zu bytes but expecting %zu",
		     what, space, nr_bytes);
		return false;
	}
	(*bytes) = wp->str_next;
	wp->str_next += nr_bytes;
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
			      HUNK->len, WHAT, logger)) {		\
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
				HUNK->len, WHAT, logger)) {		\
			return false;					\
		}							\
		return true;						\
	}

static bool pack_chunk(struct whackpacker *wp, chunk_t *chunk, const char *what, struct logger *logger)
{
	PACK_HUNK(wp, chunk, what);
}

static bool unpack_chunk(struct whackpacker *wp, chunk_t *chunk, const char *what, struct logger *logger)
{
	UNPACK_HUNK(wp, chunk, what);
}

static bool pack_shunk(struct whackpacker *wp, shunk_t *shunk, const char *what, struct logger *logger)
{
	PACK_HUNK(wp, shunk, what);
}

static bool unpack_shunk(struct whackpacker *wp, shunk_t *shunk, const char *what, struct logger *logger)
{
	UNPACK_HUNK(wp, shunk, what);
}

/*
 * Pack and unpack possibly NULL, NUL-terminated strings.
 *
 * Notes:
 *
 * - On the wire, the pointer contains the number of bytes including
 *   the trailing NUL.  So zero is a NULL pointer, and one is an empty
 *   string.
 *
 * - to prevent the string pointer going across the wire, it is set to
 *   the number of bytes
 *
 * - the unpacked pointer stored in *P points into the whack message
 *   do don't free it
 */

static bool pack_string(struct whackpacker *wp, char **p, const char *what, struct logger *logger)
{
	if ((*p) == NULL) {
		/* NULL pointer encoded as zero bytes */
		(*p) = NULL;
		return true;
	}

	size_t nr_bytes = strlen((*p)) + 1;
	if (!pack_bytes(wp, (*p), nr_bytes, what, logger)) {
		return false;
	}

	(*p) = (void*)nr_bytes;
	return true;
}

static bool unpack_string(struct whackpacker *wp, char **p, const char *what, struct logger *logger)
{
	if ((*p) == NULL) {
		/* unpack NULL as NULL */
		return true;
	}

	/* p carries the string length */
	size_t nr_bytes = (ptrdiff_t)(*p);
	void *s = NULL;
	if (!unpack_raw(wp, &s, nr_bytes, what, logger)) {
		return false;
	}

	*p = s;
	if ((*p)[nr_bytes-1] != '\0') {
		llog(RC_LOG, logger, "%s lost its terminating NUL", what);
		return false;
	}

	return true;
}

/*
 * IP pointers.
 */

static bool pack_ip_info(struct whackpacker *wp UNUSED,
			 const struct ip_info **info,
			 const char *what UNUSED,
			 struct logger *logger UNUSED)
{
	/* spell out conversions */
	enum ip_version v = (*info == NULL ? 0 : (*info)->ip_version);
	*info = (const void*)(uintptr_t)(unsigned)v;
	return true;
}

static bool unpack_ip_info(struct whackpacker *wp UNUSED,
			   const struct ip_info **info,
			   const char *what UNUSED,
			   struct logger *logger UNUSED)
{
	/* spell out conversions */
	*info = ip_version_info((unsigned)(uintptr_t)(const void*)*info);
	return true;
}

static bool pack_ip_protocol(struct whackpacker *wp UNUSED,
			     const struct ip_protocol **protocol,
			     const char *what UNUSED,
			     struct logger *logger UNUSED)
{
	/* spell out conversions */
	*protocol = (const void*)(uintptr_t)(unsigned)(*protocol)->ipproto;
	return true;
}

static bool unpack_ip_protocol(struct whackpacker *wp UNUSED,
			       const struct ip_protocol **protocol,
			       const char *what UNUSED,
			       struct logger *logger UNUSED)
{
	/* spell out conversions */
	*protocol = protocol_from_ipproto((unsigned)(uintptr_t)(const void*)*protocol);
	return *protocol != NULL;
}

static bool pack_constant_string(struct whackpacker *wp UNUSED,
				 const char **string,
				 const char *constant,
				 const char *what,
				 struct logger *logger)
{
	if (*string != NULL) {
		ldbgf(DBG_TMI, logger, "%s: '%s' was: %s (%s)", __func__, what, *string, constant);
		passert(streq(*string, constant));
		*string = NULL;
	} else {
		/*
		 * For instance, when whack sends control messages
		 * such as "status" the whack_end .leftright field is
		 * still NULL.
		 *
		 * The unpack will set the field, oops.
		 */
		ldbgf(DBG_TMI, logger, "%s: '%s' was null (%s)", __func__, what, constant);
	}
	return true;
}

static bool unpack_constant_string(struct whackpacker *wp UNUSED,
				   const char **string,
				   const char *constant,
				   const char *what,
				   struct logger *logger)
{
	pexpect(*string == NULL);
	*string = constant;
	ldbgf(DBG_TMI, logger, "%s: '%s' is %s", __func__, what, *string);
	return true;
}

/*
 * in and out/
 */
struct pickler {
	bool (*string)(struct whackpacker *wp, char **p, const char *what, struct logger *logger);
	bool (*shunk)(struct whackpacker *wp, shunk_t *s, const char *what, struct logger *logger);
	bool (*chunk)(struct whackpacker *wp, chunk_t *s, const char *what, struct logger *logger);
	bool (*raw)(struct whackpacker *wp, void **bytes, size_t nr_bytes, const char *what, struct logger *logger);
	bool (*ip_info)(struct whackpacker *wp, const struct ip_info **info, const char *what, struct logger *logger);
	bool (*ip_protocol)(struct whackpacker *wp, const struct ip_protocol **protocol, const char *what, struct logger *logger);
	bool (*constant_string)(struct whackpacker *wp, const char **p, const char *leftright, const char *what, struct logger *logger);
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

#define PICKLE_STRING(FIELD) pickle->string(wp, FIELD, #FIELD, logger)
#define PICKLE_CHUNK(FIELD) pickle->chunk(wp, FIELD, #FIELD, logger)
#define PICKLE_SHUNK(FIELD) pickle->shunk(wp, FIELD, #FIELD, logger)
#define PICKLE_THINGS(THINGS, NR) pickle->raw(wp, (void**)(THINGS), NR*sizeof((THINGS)[0][0]), #THINGS, logger)
#define PICKLE_CONSTANT_STRING(FIELD, VALUE) pickle->constant_string(wp, FIELD, VALUE, #FIELD, logger)
#define PICKLE_IP_INFO(FIELD) pickle->ip_info(wp, FIELD, #FIELD, logger)

#if 0
#define PICKLE_CIDR(CIDR) \
	((CIDR)->is_set ? pickle->ip_info(wp, &((CIDR)->info), #CIDR) : true)
#else
#define PICKLE_CIDR(CIDR) true
#endif

static bool pickle_whack_end(struct whackpacker *wp,
			     const char *leftright,
			     struct whack_end *end,
			     const struct pickler *pickle,
			     struct logger *logger)
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
		PICKLE_STRING(&end->xauthusername) &&
		PICKLE_STRING(&end->host_addr_name) &&
		PICKLE_STRING(&end->interface_ip) &&
		PICKLE_STRING(&end->vti) &&
		PICKLE_STRING(&end->addresspool) &&
		PICKLE_STRING(&end->ikeport) &&
		PICKLE_STRING(&end->subnet) &&
		PICKLE_STRING(&end->subnets) &&
		PICKLE_STRING(&end->sourceip) &&
		PICKLE_STRING(&end->sendcert) &&
		true);
}

static bool pickle_whack_message(struct whackpacker *wp,
				 const struct pickler *pickle,
				 struct logger *logger)
{
	return (PICKLE_STRING(&wp->msg->name) && /* first */
		pickle_whack_end(wp, "left", &wp->msg->end[LEFT_END], pickle, logger) &&
		pickle_whack_end(wp, "right",&wp->msg->end[RIGHT_END], pickle, logger) &&
		PICKLE_STRING(&wp->msg->ike) &&
		PICKLE_STRING(&wp->msg->esp) &&
		PICKLE_STRING(&wp->msg->connalias) &&
		PICKLE_STRING(&wp->msg->dnshostname) &&
		PICKLE_STRING(&wp->msg->modecfgdns) &&
		PICKLE_STRING(&wp->msg->modecfgdomains) &&
		PICKLE_STRING(&wp->msg->modecfgbanner) &&
		PICKLE_STRING(&wp->msg->mark) &&
		PICKLE_STRING(&wp->msg->mark_in) &&
		PICKLE_STRING(&wp->msg->mark_out) &&
		PICKLE_STRING(&wp->msg->vti_interface) &&
		PICKLE_STRING(&wp->msg->ipsec_interface) &&
		PICKLE_STRING(&wp->msg->remote_host) &&
		PICKLE_STRING(&wp->msg->ppk_ids) &&
		PICKLE_STRING(&wp->msg->redirect_to) &&
		PICKLE_STRING(&wp->msg->accept_redirect_to) &&
		PICKLE_STRING(&wp->msg->keyid) &&
		PICKLE_STRING(&wp->msg->pubkey) &&
		PICKLE_THINGS(&wp->msg->impairments.list, wp->msg->impairments.len) &&
		PICKLE_STRING(&wp->msg->sec_label) &&
		PICKLE_IP_INFO(&wp->msg->host_afi) &&
		PICKLE_IP_INFO(&wp->msg->child_afi) &&
		PICKLE_STRING(&wp->msg->dpdtimeout) &&
		PICKLE_STRING(&wp->msg->dpddelay) &&
		PICKLE_STRING(&wp->msg->nflog_group) &&
		PICKLE_STRING(&wp->msg->reqid) &&
		PICKLE_STRING(&wp->msg->sendca) &&
		PICKLE_STRING(&wp->msg->remote_peer_type) &&
		true);
}

/**
 * Pack a message to be sent to whack
 *
 * @param wp The whack message
 * @return err_t
 */
err_t pack_whack_msg(struct whackpacker *wp, struct logger *logger)
{
	if (wp->msg->basic.magic != 0) {
		ldbg(logger, "whack magic forced to %u", wp->msg->basic.magic);
	} else if (wp->msg->basic.whack_status ||
		   wp->msg->basic.whack_shutdown) {
		wp->msg->basic.magic = WHACK_BASIC_MAGIC;
		ldbg(logger, "whack magic is %u (WHACK_BASIC_MAGIC)", wp->msg->basic.magic);
	} else {
		wp->msg->basic.magic = whack_magic();
		ldbg(logger, "whack magic is %u (WHACK_MAGIC)", wp->msg->basic.magic);
	}

	/* Pack strings */

	wp->str_next = wp->msg->string;
	wp->str_roof = &wp->msg->string[sizeof(wp->msg->string)];
	if (!pickle_whack_message(wp, &pickle_packer, logger)) {
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
	/* sanity check message */
	if (wp->msg->basic.magic == WHACK_BASIC_MAGIC) {
		/* must at least contain .whack_shutdown */
		size_t min_bytes = (offsetof(struct whack_message, basic.whack_shutdown) +
				    sizeof(wp->msg->basic.whack_shutdown));
		if (wp->n < min_bytes) {
			llog(RC_BADWHACKMESSAGE, logger,
			     "ignoring runt message from whack: got %zu bytes", wp->n);
			return false;
		}

		/*
		 * Note: since old libreswans (4.x, 5.0) never set
		 * .magic to WHACK_BASIC_MAGIC, a 5.1+ libreswan will
		 * never see a non-zero .whack_shutdown_legacy[]
		 * except when set by a 5.1+ whack.  Hence, there's no
		 * point in checking its contents.
		 */
#if 0
		FOR_EACH_ELEMENT(b, wp->msg->basic.whack_shutdown_legacy) {
			wp->msg->basic.whack_shutdown |= (*b);
		}
#endif

		/* wipe everything beyond basic values */
		memset((unsigned char*)wp->msg + sizeof(struct whack_basic), 0,
		       sizeof(struct whack_message) - sizeof(struct whack_basic));

		return true;
	}

	if (wp->msg->basic.magic != whack_magic()) {
		llog(RC_BADWHACKMESSAGE, logger,
		     "ignoring message from whack with bad magic %u; should be %u; Mismatched versions of userland tools.",
		     wp->msg->basic.magic, whack_magic());
		return false;
	}

	/*
	 * Determine the bounds of the trailing string array.  Message
	 * must at least extend to strings array.
	 */
	wp->str_next = wp->msg->string;
	wp->str_roof = (unsigned char *)wp->msg + wp->n;
	if (wp->str_next > wp->str_roof) {
		llog(RC_BADWHACKMESSAGE, logger,
		     "ignoring truncated message from whack: got %zu bytes; expected %zu",
		     wp->n, sizeof(wp->msg));
		return false;
	}

	if (!pickle_whack_message(wp, &pickle_unpacker, logger)) {
		llog(RC_BADWHACKMESSAGE, logger,
		     "message from whack contains bad string or key");
		return false;
	}

	return true;
}
