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
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#include "sysdep.h"
#include "constants.h"
#include "lswconf.h"
#include "fips_mode.h"

#include "defs.h"
#include "log.h"
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
#include "crypto.h"
#include "ip_address.h" /* for jam_address */


#include "pluto_stats.h"

#ifndef USE_LINUX_AUDIT
void linux_audit_conn(const struct state *st UNUSED, enum linux_audit_kind op UNUSED)
{
	return;
}
#else

#include <libaudit.h>

void linux_audit_init(int do_audit, struct logger *logger)
{
	llog(RC_LOG, logger, "Linux audit support [enabled]");
	/* test and log if audit is enabled on the system */
	int audit_fd;
	audit_fd = audit_open();
	if (audit_fd < 0) {
		if (errno == EINVAL || errno == EPROTONOSUPPORT ||
			errno == EAFNOSUPPORT) {
			llog(RC_LOG_SERIOUS, logger,
				    "Warning: kernel has no audit support");
			close(audit_fd);
			log_to_audit = false;
			return;
		} else {
			fatal_errno(PLUTO_EXIT_AUDIT_FAIL, logger, errno,
				    "audit_open() failed");
		}
	} else {
		if (do_audit)
			log_to_audit = true;
	}
	close(audit_fd);
	if (do_audit)
		llog(RC_LOG, logger, "Linux audit activated");
}

static void linux_audit(const int type, const char *message, const char *laddr, const int result,
			struct logger *logger)
{
	int audit_fd, rc;

	audit_fd = audit_open();
	if (audit_fd < 0) {
		fatal_errno(PLUTO_EXIT_AUDIT_FAIL, logger, errno,
			    "audit_open() failed");
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

	rc = audit_log_user_message(audit_fd, type, message, NULL, laddr, NULL, result);
	close(audit_fd);
	if (rc < 0) {
		fatal_errno(PLUTO_EXIT_AUDIT_FAIL, logger, errno,
			    "audit log failed");
	}
}

/*
 * any admin/network strings but go through audit_encode_nv_string()
 */
void linux_audit_conn(const struct state *st, enum linux_audit_kind op)
{
	if (!log_to_audit) {
		return;
	}

	char audit_str[AUDIT_LOG_SIZE];
	struct jambuf buf = ARRAY_AS_JAMBUF(audit_str);
	struct connection *const c = st->st_connection;
	/* we need to free() this */
	char *conn_encode = audit_encode_nv_string("conn-name", c->name, 0);

	switch (op) {
	case LAK_PARENT_START:
	case LAK_PARENT_DESTROY:
	case LAK_PARENT_FAIL:
	{
		/* head */
		jam(&buf, "op=%s direction=%s %s connstate=%lu ike-version=%s",
		    op == LAK_PARENT_DESTROY ? "destroy" : "start", /* fail to start logged under op=start */
		    (st->st_sa_role == SA_INITIATOR ? "initiator" :
		     st->st_sa_role == SA_RESPONDER ? "responder" :
		     "????"),
		    conn_encode,
		    st->st_serialno,
		    (st->st_ike_version == IKEv2) ? "2.0" : "1");

		jam(&buf, " auth=");
		if (st->st_ike_version == IKEv2 ||
		    op == LAK_PARENT_FAIL) {
			/*
			 * XXX: is this reliable; it's the intent not
			 * result.  Is local correct?
			 */
			struct authby authby = c->local->host.config->authby;
			jam_string(&buf, ((authby.psk) ? "PRESHARED_KEY" :
					  (authby.rsasig) ? "RSA_SIG" :
					  (authby.rsasig_v1_5) ? "RSA_SIG" :
					  (authby.ecdsa) ? "ECDSA" : "unknown"));
		} else {
			jam_enum_short(&buf, &oakley_auth_names, st->st_oakley.auth);
		}

		jam(&buf, " cipher=%s ksize=%d",
		    (st->st_oakley.ta_encrypt == NULL ? "none"
		     : st->st_oakley.ta_encrypt->encrypt_ike_audit_name),
		    st->st_oakley.enckeylen);

		const char *prfname = (st->st_oakley.ta_prf == NULL ? "none"
				       : st->st_oakley.ta_prf->prf_ike_audit_name);
		jam(&buf, " integ=");
		if (st->st_oakley.ta_integ == &ike_alg_integ_none) {
			/*
			 * XXX: dead code path?  IKEv1 can't do
			 * INTEG==NONE; "none"'s name is "none".
			 */
			if (st->st_ike_version == IKEv1) {
				/* IKE takes integ from prf, except of course gcm */
				/* but IANA doesn't define gcm for IKE, only for ESP */
				jam_string(&buf, prfname);
			} else {
				jam(&buf, "none");
			}
		} else if (st->st_oakley.ta_integ != NULL) {
			/*
			 * XXX: merge bit-size into audit_name?
			 */
			jam(&buf, "%s_%zu",
			    st->st_oakley.ta_integ->integ_ike_audit_name,
			    st->st_oakley.ta_integ->integ_output_size * BITS_IN_BYTE);
		} else {
			/*
			 * XXX: dead code path?  Integ is never NULL?
			 */
			if (st->st_ike_version == IKEv1) {
				/* IKE takes integ from prf, except of course gcm */
				/* but IANA doesn't define gcm for IKE, only for ESP */
				jam_string(&buf, prfname);
			} else {
				jam(&buf, "none");
			}
		}

		jam(&buf, " prf=%s", prfname); /* could be "none" */
		jam(&buf, " pfs=%s", (st->st_oakley.ta_dh == NULL ? "none"
				      : st->st_oakley.ta_dh->common.fqn));

		/* XXX: empty SPI to keep tests happy */
		jam(&buf, " ");
		break;
	}
	case LAK_CHILD_START:
	case LAK_CHILD_DESTROY:
	case LAK_CHILD_FAIL:
	{
		/* head */
		jam(&buf, "op=%s %s connstate=%lu, satype=%s",
		    op == LAK_CHILD_DESTROY ? "destroy" : "start", /* fail uses op=start */
		    conn_encode,
		    st->st_serialno,
		    st->st_esp.protocol == &ip_protocol_esp ? "ipsec-esp" : st->st_ah.protocol == &ip_protocol_ah ? "ipsec-ah" : "ipsec-policy");
		jam_string(&buf, " samode=");
		jam_enum_short(&buf, &encap_mode_story, c->config->child_sa.encap_mode);

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

		if (st->st_esp.protocol == &ip_protocol_esp) {
			pi = &st->st_esp;
			encrypt = st->st_esp.trans_attrs.ta_encrypt;
			integ = st->st_esp.trans_attrs.ta_integ;
			enckeylen = st->st_esp.trans_attrs.enckeylen;
		} else if (st->st_ah.protocol == &ip_protocol_ah) {
			pi = &st->st_ah;
			encrypt = NULL;
			integ = st->st_ah.trans_attrs.ta_integ;
			enckeylen = 0;
		} else {
			pi = &st->st_esp;	/* hack: will yield zero SPIs, I think */
			encrypt = NULL;
			integ = NULL;
			enckeylen = 0;
		}
		jam(&buf, " cipher=%s ksize=%u integ=%s",
		    (encrypt == NULL ? "none" : encrypt->encrypt_kernel_audit_name),
		    enckeylen,
		    (integ == NULL ? "none" : integ->integ_kernel_audit_name));

		/* note: each arg appears twice because it is printed two ways */
		jam(&buf, " in-spi=%" PRIu32 "(0x%08" PRIu32 ") out-spi=%" PRIu32 "(0x%08" PRIu32 ") in-ipcomp=%" PRIu32 "(0x%08" PRIu32 ") out-ipcomp=%" PRIu32 "(0x%08" PRIu32 ")",
		    ntohl(pi->outbound.spi),
		    ntohl(pi->outbound.spi),
		    ntohl(pi->inbound.spi),
		    ntohl(pi->inbound.spi),
		    ntohl(st->st_ipcomp.outbound.spi),	/* zero if missing */
		    ntohl(st->st_ipcomp.outbound.spi),	/* zero if missing */
		    ntohl(st->st_ipcomp.inbound.spi),	/* zero if missing */
		    ntohl(st->st_ipcomp.inbound.spi));	/* zero if missing */
		break;
	}
	default:
		bad_case(op);
	}
	free(conn_encode); /* allocated by audit_encode_nv_string() */

	/* note laddr_buf and laddr at same scope */
	address_buf laddr_buf;
	const char *laddr = str_address(&c->local->host.addr, &laddr_buf);

	jam(&buf, " raddr=");
	jam_address(&buf, &c->remote->host.addr);

	linux_audit((op == LAK_CHILD_START || op == LAK_CHILD_DESTROY || op == LAK_CHILD_FAIL) ?
			AUDIT_CRYPTO_IPSEC_SA : AUDIT_CRYPTO_IKE_SA,
			audit_str, laddr,
		    (op == LAK_PARENT_FAIL || op == LAK_CHILD_FAIL) ? AUDIT_RESULT_FAIL : AUDIT_RESULT_OK,
		    st->logger);
}
#if __GNUC__ >= 7
#pragma GCC diagnostic pop
#endif
#endif
