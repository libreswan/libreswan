/* error logging functions
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson
 * Copyright (C) 2006-2010 Bart Trojanowski
 * Copyright (C) 2008-2012 Paul Wouters
 * Copyright (C) 2008-2010 David McCullough.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013,2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>     /* used only if MSG_NOSIGNAL not defined */
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswconf.h"
#include "lswfips.h"
#include "lswlog.h"

#include "defs.h"
#include "log.h"
#include "peerlog.h"
#include "server.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "kernel.h"             /* needs connections.h */
#include "whack.h"              /* needs connections.h */
#include "timer.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "ike_alg_integ.h"
#include "plutoalg.h"
/* for show_virtual_private: */
#include "virtual.h"	/* needs connections.h */
#include "crypto.h"

#include <libaudit.h>

#include "db_ops.h"

#include "pluto_stats.h"

#if __GNUC__ >= 7
	/*
	 * GCC 7+ warns about the following calls that truncate a string using
	 * snprintf().  But here we are truncating the log message for a reason.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

static bool log_to_audit = FALSE;		/* audit log messages for kernel */

void linux_audit_init(void)
{
	libreswan_log("Linux audit support [enabled]");
	/* test and log if audit is enabled on the system */
	int audit_fd;
	audit_fd = audit_open();
	if (audit_fd < 0) {
		if (errno == EINVAL || errno == EPROTONOSUPPORT ||
			errno == EAFNOSUPPORT) {
			loglog(RC_LOG_SERIOUS,
				"Warning: kernel has no audit support");
		} else {
			loglog(RC_LOG_SERIOUS,
				"FATAL: audit_open() failed : %s",
				strerror(errno));
			exit_pluto(PLUTO_EXIT_AUDIT_FAIL);
		}
	} else {
		log_to_audit = TRUE;
	}
	close(audit_fd);
	libreswan_log("Linux audit activated");
}

static void do_linux_audit(const int type, const char *message, const char *addr,
			   const int result)
{
	int audit_fd, rc;

	audit_fd = audit_open();
	if (audit_fd < 0) {
		loglog(RC_LOG_SERIOUS,
		       "FATAL (SOON): audit_open() failed : %s",
		       strerror(errno));
		exit_pluto(PLUTO_EXIT_AUDIT_FAIL);
	}

	/*
	 * audit_log_user_message() - log a general user message
	 *
	 * audit_fd - The fd returned by audit_open
	 * type - type of message, ex: AUDIT_USYS_CONFIG, AUDIT_USER_LOGIN
	 * message - the message text being sent
	 * hostname - the hostname if known, NULL if unknown
	 * addr - The network address of the user, NULL if unknown
	 * tty - The tty of the user, if NULL will attempt to figure out
	 * result - 1 is "success" and 0 is "failed"
	 *
	 * We log the remoteid instead of hostname
	 */

	rc = audit_log_user_message(audit_fd, type, message, NULL, addr, NULL, result);
	close(audit_fd);
	if (rc < 0) {
		loglog(RC_LOG_SERIOUS,
			"FATAL: audit log failed: %s",
			strerror(errno));
		exit_pluto(PLUTO_EXIT_AUDIT_FAIL);
	}
}

void linux_audit(const int type, const char *message, const char *addr,
		 const int result)
{
	if (!log_to_audit) {
		return;
	}
	do_linux_audit(type, message, addr, result);
}

/*
 * any admin/network strings but go through audit_encode_nv_string()
 */
void linux_audit_conn(const struct state *st, enum linux_audit_kind op)
{
	if (!log_to_audit) {
		return;
	}

	char raddr[ADDRTOT_BUF];
	char laddr[ADDRTOT_BUF];
	char audit_str[AUDIT_LOG_SIZE];
	char cipher_str[AUDIT_LOG_SIZE];
	char spi_str[AUDIT_LOG_SIZE];
	struct connection *const c = st->st_connection;
	bool initiator = FALSE;
	char head[IDTOA_BUF];
	char integname[IDTOA_BUF];
	char prfname[IDTOA_BUF];
	struct esb_buf esb;
	/* we need to free() this */
	char *conn_encode = audit_encode_nv_string("conn-name", c->name,0);

	zero(&cipher_str);	/* OK: no pointer fields */
	zero(&spi_str);	/* OK: no pointer fields */

	switch (op) {
	case LAK_PARENT_START:
	case LAK_PARENT_DESTROY:
		initiator = (st->st_original_role == ORIGINAL_INITIATOR) || IS_PHASE1_INIT(st->st_state);
		snprintf(head, sizeof(head), "op=%s direction=%s %s connstate=%lu ike-version=%s auth=%s",
			op == LAK_PARENT_START ? "start" : "destroy",
			initiator ? "initiator" : "responder",
			conn_encode,
			st->st_serialno,
			st->st_ikev2 ? "2.0" : "1",
			st->st_ikev2 ? ((c->policy & POLICY_PSK) ? "PRESHARED_KEY" : "RSA_SIG") :
				enum_show_shortb(&oakley_auth_names,
					st->st_oakley.auth, &esb));

		snprintf(prfname, sizeof(prfname), "%s",
			 st->st_oakley.ta_prf->prf_ike_audit_name);

		if (st->st_oakley.ta_integ == &ike_alg_integ_none) {
			if (!st->st_ikev2) {
				/* IKE takes integ from prf, except of course gcm */
				/* but IANA doesn't define gcm for IKE, only for ESP */
				jam_str(integname, sizeof(integname), prfname);
			} else {
				snprintf(integname, sizeof(integname), "none");
			}
		} else if (st->st_oakley.ta_integ != NULL) {
			snprintf(integname, sizeof(integname), "%s_%zu",
				st->st_oakley.ta_integ->integ_ike_audit_name,
				st->st_oakley.ta_integ->integ_output_size *
				BITS_PER_BYTE);
		} else {
			/*
			 * XXX: dead code path?
			 */
			if (!st->st_ikev2) {
				/* IKE takes integ from prf, except of course gcm */
				/* but IANA doesn't define gcm for IKE, only for ESP */
				jam_str(integname, sizeof(integname), prfname);
			} else {
				snprintf(integname, sizeof(integname), "none");
			}
		}

		snprintf(cipher_str, sizeof(cipher_str),
			"cipher=%s ksize=%d integ=%s prf=%s pfs=%s",
			st->st_oakley.ta_encrypt->encrypt_ike_audit_name,
			st->st_oakley.enckeylen,
			integname, prfname,
			st->st_oakley.ta_dh->common.name);
		break;

	case LAK_CHILD_START:
	case LAK_CHILD_DESTROY:
	{
		snprintf(head, sizeof(head), "op=%s %s connstate=%lu, satype=%s samode=%s",
			op == LAK_CHILD_START ? "start" : "destroy",
			conn_encode,
			st->st_serialno,
			st->st_esp.present ? "ipsec-esp" : (st->st_ah.present ? "ipsec-ah" : "ipsec-policy"),
			c->policy & POLICY_TUNNEL ? "tunnel" : "transport");

		/*
		 * XXX: Instead of IKEv1_ESP_ID, this should use
		 * ->common.fqn or ->common.officname; however that
		 * means changing the output.  So leave it roughly as
		 * is for now.
		 */

		const struct ipsec_proto_info *pi;
		const struct encrypt_desc *encrypt;
		const struct integ_desc *integ;
		unsigned enckeylen;

		if (st->st_esp.present) {
			pi = &st->st_esp;
			encrypt = st->st_esp.attrs.transattrs.ta_encrypt;
			integ = st->st_esp.attrs.transattrs.ta_integ;
			enckeylen = st->st_esp.attrs.transattrs.enckeylen;
		} else if (st->st_ah.present) {
			pi = &st->st_ah;
			encrypt = NULL;
			integ = st->st_ah.attrs.transattrs.ta_integ;
			enckeylen = 0;
		} else {
			pi = &st->st_esp;	/* hack: will yield zero SPIs, I think */
			encrypt = NULL;
			integ = NULL;
			enckeylen = 0;
		}
		snprintf(cipher_str, sizeof(cipher_str), "cipher=%s ksize=%u integ=%s",
			 (encrypt == NULL ? "none" :
			  encrypt->encrypt_kernel_audit_name),
			 enckeylen,
			 (integ == NULL ? "none" :
			  integ->integ_kernel_audit_name));

		/* note: each arg appears twice because it is printed two ways */
		snprintf(spi_str, sizeof(spi_str),
			"in-spi=%" PRIu32 "(0x%08" PRIu32 ") out-spi=%" PRIu32 "(0x%08" PRIu32 ") in-ipcomp=%" PRIu32 "(0x%08" PRIu32 ") out-ipcomp=%" PRIu32 "(0x%08" PRIu32 ")",
			ntohl(pi->attrs.spi),
			ntohl(pi->attrs.spi),
			ntohl(pi->our_spi),
			ntohl(pi->our_spi),
			ntohl(st->st_ipcomp.attrs.spi),	/* zero if missing */
			ntohl(st->st_ipcomp.attrs.spi),	/* zero if missing */
			ntohl(st->st_ipcomp.our_spi),	/* zero if missing */
			ntohl(st->st_ipcomp.our_spi));	/* zero if missing */
		break;
	}
	default:
		bad_case(op);
	}
	free(conn_encode); /* allocated by audit_encode_nv_string() */

	addrtot(&c->spd.this.host_addr, 0, laddr, sizeof(laddr));
	addrtot(&c->spd.that.host_addr, 0, raddr, sizeof(raddr));

	snprintf(audit_str, sizeof(audit_str), "%s %s %s laddr=%s",
		head,
		cipher_str,
		spi_str,
		laddr);

	linux_audit((op == LAK_CHILD_START || op == LAK_CHILD_DESTROY) ?
			AUDIT_CRYPTO_IPSEC_SA : AUDIT_CRYPTO_IKE_SA,
		audit_str, raddr, AUDIT_RESULT_OK);
}
#if __GNUC__ >= 7
#pragma GCC diagnostic pop
#endif
