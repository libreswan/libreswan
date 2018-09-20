/* Libreswan command interface to Pluto
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2004-2006  Michael Richardson <mcr@xelerance.com>
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include <libreswan.h>
#include <stdarg.h>

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "whack.h"
#include "lswlog.h"

/**
 * Pack a string to a whack messages
 *
 * @param wp
 * @param p a string
 * @return bool True if operation was successful
 */
static bool pack_str(struct whackpacker *wp, char **p)
{
	const char *s = (*p == NULL ? "" : *p); /* note: NULL becomes ""! */
	size_t len = strlen(s) + 1;

	if (wp->str_roof - wp->str_next < (ptrdiff_t)len) {
		return FALSE; /* fishy: no end found */
	} else {
		strcpy((char *)wp->str_next, s);
		wp->str_next += len;
		*p = NULL; /* don't send pointers on the wire! */
		return TRUE;
	}
}

/**
 * Unpack the next string from a whack message
 *
 * @param wp Whack Message
 * @param p pointer to a string pointer; the string pointer will point to the next string in *wp.
 * @return bool TRUE if operation successful
 *
 * Note that the string still resides in the whach message.
 */
static bool unpack_str(struct whackpacker *wp, char **p)
{
	unsigned char *end;

	end = memchr(wp->str_next, '\0', (wp->str_roof - wp->str_next) );

	if (end == NULL) {
		return FALSE; /* fishy: no end found */
	} else {
		unsigned char *s = (wp->str_next == end ? NULL : wp->str_next);

		*p = (char *)s;
		wp->str_next = end + 1;
		return TRUE;
	}
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

	if (!pack_str(wp, &wp->msg->name) ||			/* string 1 */
	    !pack_str(wp, &wp->msg->left.id) ||			/* string 2 */
	    !pack_str(wp, &wp->msg->left.pubkey) ||		/* string 3 */
	    !pack_str(wp, &wp->msg->left.ca) ||			/* string 4 */
	    !pack_str(wp, &wp->msg->left.groups) ||		/* string 5 */
	    !pack_str(wp, &wp->msg->left.updown) ||		/* string 6 */
	    !pack_str(wp, &wp->msg->left.virt) ||		/* string 7 */
	    !pack_str(wp, &wp->msg->right.id) ||		/* string 8 */
	    !pack_str(wp, &wp->msg->right.pubkey) ||		/* string 9 */
	    !pack_str(wp, &wp->msg->right.ca) ||		/* string 10 */
	    !pack_str(wp, &wp->msg->right.groups) ||		/* string 11 */
	    !pack_str(wp, &wp->msg->right.updown) ||		/* string 12 */
	    !pack_str(wp, &wp->msg->right.virt) ||		/* string 13 */
	    !pack_str(wp, &wp->msg->keyid) ||			/* string 14 */

	    !pack_str(wp, &wp->msg->ike) ||			/* string 16 */
	    !pack_str(wp, &wp->msg->esp) ||			/* string 17 */
	    !pack_str(wp, &wp->msg->left.xauth_username) ||	/* string 18 */
	    !pack_str(wp, &wp->msg->right.xauth_username) ||	/* string 19 */
	    !pack_str(wp, &wp->msg->connalias) ||		/* string 20 */
	    !pack_str(wp, &wp->msg->left.host_addr_name) ||	/* string 21 */
	    !pack_str(wp, &wp->msg->right.host_addr_name) ||	/* string 22 */
	    !pack_str(wp, &wp->msg->string1) ||			/* string 23 */
	    !pack_str(wp, &wp->msg->string2) ||			/* string 24 */
	    !pack_str(wp, &wp->msg->string3) ||			/* string 25 */
	    !pack_str(wp, &wp->msg->dnshostname) ||		/* string 26 */
#ifdef HAVE_LABELED_IPSEC
	    !pack_str(wp, &wp->msg->policy_label) ||		/* string 27 */
#endif
	    !pack_str(wp, &wp->msg->modecfg_dns) ||		/* string 28 */
	    !pack_str(wp, &wp->msg->modecfg_domains) ||		/* string 28 */
	    !pack_str(wp, &wp->msg->modecfg_banner) ||		/* string 29 */
	    !pack_str(wp, &wp->msg->conn_mark_both) ||		/* string 30 */
	    !pack_str(wp, &wp->msg->conn_mark_in) ||		/* string 31 */
	    !pack_str(wp, &wp->msg->conn_mark_out) ||		/* string 32 */
	    !pack_str(wp, &wp->msg->vti_iface) ||		/* string 33 */
	    !pack_str(wp, &wp->msg->remote_host) ||		/* string 33 */
	    wp->str_roof - wp->str_next < (ptrdiff_t)wp->msg->keyval.len)	/* key */
	{
		return "too many bytes of strings or key to fit in message to pluto";
	}

	/*
	 * Like pack_str, but for the keyval chunk.
	 * - already checked that there is room for the chunk
	 * - memcpy wants valid pointers, even if the length is 0.
	 */
	if (wp->msg->keyval.len != 0)
		memcpy(wp->str_next, wp->msg->keyval.ptr, wp->msg->keyval.len);
	wp->msg->keyval.ptr = NULL;	/* don't send pointers on the wire! */
	wp->str_next += wp->msg->keyval.len;

	return NULL;
}

/**
 * Unpack a message whack received
 *
 * @param wp The whack message
 * @return err_t
 */
err_t unpack_whack_msg(struct whackpacker *wp)
{
	err_t ugh = NULL;

	if (wp->str_next > wp->str_roof) {
		ugh = builddiag(
			"ignoring truncated message from whack: got %d bytes; expected %u",
			(int) wp->n, (unsigned) sizeof(wp->msg));
	} else if (!unpack_str(wp, &wp->msg->name) ||			/* string 1 */
	    !unpack_str(wp, &wp->msg->left.id) ||		/* string 2 */
	    !unpack_str(wp, &wp->msg->left.pubkey) ||		/* string 3 */
	    !unpack_str(wp, &wp->msg->left.ca) ||		/* string 4 */
	    !unpack_str(wp, &wp->msg->left.groups) ||		/* string 5 */
	    !unpack_str(wp, &wp->msg->left.updown) ||		/* string 6 */
	    !unpack_str(wp, &wp->msg->left.virt) ||		/* string 7 */
	    !unpack_str(wp, &wp->msg->right.id) ||		/* string 8 */
	    !unpack_str(wp, &wp->msg->right.pubkey) ||		/* string 9 */
	    !unpack_str(wp, &wp->msg->right.ca) ||		/* string 10 */
	    !unpack_str(wp, &wp->msg->right.groups) ||		/* string 11 */
	    !unpack_str(wp, &wp->msg->right.updown) ||		/* string 12 */
	    !unpack_str(wp, &wp->msg->right.virt) ||		/* string 13 */
	    !unpack_str(wp, &wp->msg->keyid) ||			/* string 14 */

	    !unpack_str(wp, &wp->msg->ike) ||			/* string 16 */
	    !unpack_str(wp, &wp->msg->esp) ||			/* string 17 */
	    !unpack_str(wp, &wp->msg->left.xauth_username) ||	/* string 18 */
	    !unpack_str(wp, &wp->msg->right.xauth_username) ||	/* string 19 */
	    !unpack_str(wp, &wp->msg->connalias) ||		/* string 20 */
	    !unpack_str(wp, &wp->msg->left.host_addr_name) ||	/* string 21 */
	    !unpack_str(wp, &wp->msg->right.host_addr_name) ||	/* string 22 */
	    !unpack_str(wp, &wp->msg->string1) ||		/* string 23 */
	    !unpack_str(wp, &wp->msg->string2) ||		/* string 24 */
	    !unpack_str(wp, &wp->msg->string3) ||		/* string 25 */
	    !unpack_str(wp, &wp->msg->dnshostname) ||		/* string 26 */
#ifdef HAVE_LABELED_IPSEC
	    !unpack_str(wp, &wp->msg->policy_label) ||		/* string 27 */
#endif
	    !unpack_str(wp, &wp->msg->modecfg_dns) ||		/* string 28 */
	    !unpack_str(wp, &wp->msg->modecfg_domains) ||	/* string 28 */
	    !unpack_str(wp, &wp->msg->modecfg_banner) ||	/* string 29 */
	    !unpack_str(wp, &wp->msg->conn_mark_both) ||	/* string 30 */
	    !unpack_str(wp, &wp->msg->conn_mark_in) ||		/* string 31 */
	    !unpack_str(wp, &wp->msg->conn_mark_out) ||		/* string 32 */
	    !unpack_str(wp, &wp->msg->vti_iface) ||		/* string 33 */
	    !unpack_str(wp, &wp->msg->remote_host) ||		/* string 33 */
	    wp->str_roof - wp->str_next != (ptrdiff_t)wp->msg->keyval.len)
	{
		ugh = "message from whack contains bad string or key";
	} else {
		wp->msg->keyval.ptr = wp->str_next;
	}

	return ugh;
}

void clear_end(struct whack_end *e)
{
	static const struct whack_end zero_end;	/* zeros and NULL pointers */

	*e = zero_end;
	e->host_port = IKE_UDP_PORT; /* XXX should really use ike_port ? */
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

