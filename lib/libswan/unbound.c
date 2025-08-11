/*
 * Use libunbound to use DNSSEC supported resolving.
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2017-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019-2019 Stepan Broz <stepan@izitra.cz>
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

#ifndef USE_DNSSEC
# error this file should only be compiled when using DNSSEC
#endif

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <event2/event.h>	/* deb:libevent-dev */
#include <unbound.h>		/* rpm:unbound-devel deb:libunbound-dev */
#include <unbound-event.h>	/* ditto */

#include "lswglob.h"
#include "dnssec.h"
#include "constants.h"
#include "lswlog.h"
#include "ip_info.h"

static struct ub_ctx *dns_ctx = NULL;

void unbound_ctx_free(void)
{
	if (dns_ctx != NULL) {
		ub_ctx_delete(dns_ctx);
		dns_ctx = NULL;
	}
}

static void add_trust_anchors(unsigned count, char **files,
			      struct lswglob_context *context UNUSED,
			      struct logger *logger)
{
	for (unsigned i = 0; i < count; i++) {
		const char *file = files[i];
		int ugh = ub_ctx_add_ta_file(dns_ctx, file);
		if (ugh != 0) {
			llog(RC_LOG, logger, "ignored trusted key file %s: %s",
			     file,  ub_strerror(ugh));
		} else {
			ldbg(logger, "added contents of trusted key file %s to unbound resolver context", file);
		}
	}
}

static void unbound_ctx_config(bool do_dnssec, const char *rootfile,
			       const char *trusted,
			       struct logger *logger)
{
	int ugh;

	if (LDBGP(DBG_BASE, logger)) {
		ub_ctx_debuglevel(dns_ctx, 5);
		LDBG_log(logger, "unbound context created - setting debug level to 5");
	}

	/* lookup from /etc/hosts before DNS lookups as people expect that */
	ugh = ub_ctx_hosts(dns_ctx, "/etc/hosts");
	if (ugh != 0) {
		llog(RC_LOG, logger,
			    "error reading hosts: %s: %s",
			    ub_strerror(ugh), strerror(errno));
	} else {
		ldbg(logger, "/etc/hosts lookups activated");
	}

	/*
	 * Use /etc/resolv.conf as forwarding cache - we expect people
	 * to reconfigure this file if they need to work around DHCP DNS
	 * obtained servers.
	 */
	/*
	 * ??? ub_ctx_resolvconf is not currently documented to set errno.
	 * Private communications with W.C.A. Wijngaards 2017 October:
	 * "Is errno is meaningful after a failed call to libunbound?"
	 * "Yes it is.  Specifically for the error-to-read-file case.
	 *  Not other cases (eg. socket errors happen too far away in the code)."
	 */
	errno = 0;
	ugh = ub_ctx_resolvconf(dns_ctx, "/etc/resolv.conf");
	if (ugh != 0) {
		int e = errno;	/* protect value from ub_strerror */

		llog(RC_LOG, logger,
			    "error reading /etc/resolv.conf: %s: [errno: %s]",
			    ub_strerror(ugh), strerror(e));
	} else {
		ldbg(logger, "/etc/resolv.conf usage activated");
	}

	/*
	 * Limit outgoing ports to those allowed by common SELinux policy
	 */
	errno = 0;
	ugh = ub_ctx_set_option(dns_ctx, "outgoing-port-avoid:", "0-65535");
	if (ugh != 0) {
		llog(RC_LOG, logger,
			    "error setting outgoing-port-avoid: %s: %s",
			    ub_strerror(ugh), strerror(errno));
	} else {
		ldbg(logger, "outgoing-port-avoid set 0-65535");
	}

	errno = 0;
	ugh = ub_ctx_set_option(dns_ctx, "outgoing-port-permit:", "32768-60999");
		if (ugh != 0) {
		llog(RC_LOG, logger,
			    "error setting outgoing-port-permit: %s: %s",
			    ub_strerror(ugh), strerror(errno));
	} else {
		ldbg(logger, "outgoing-port-permit set 32768-60999");
	}

	if (!do_dnssec) {
		/* No DNSSEC - nothing more to configure */
		ldbg(logger, "dnssec validation disabled by configuration");
		return;
	}

	/* Only DNSSEC related configuration from here */
	if (rootfile == NULL) {
		if (trusted == NULL) {
			llog(RC_LOG, logger,
				    "dnssec-enable=yes but no dnssec-rootkey-file or trust anchors specified.");
			llog(RC_LOG, logger,
				    "WARNING: DNSSEC validation disabled");
			return;
		} else {
			llog(RC_LOG, logger,
				    "dnssec-enable=yes but no dnssec-rootkey-file specified. Additional trust anchor file MUST include a root trust anchor or DNSSEC validation will be disabled");
		}
	} else {
		ldbg(logger, "loading dnssec root key from:%s", rootfile);
		errno = 0;
		ugh = ub_ctx_add_ta_file(dns_ctx, rootfile);
		if (ugh != 0) {
			int e = errno;	/* protect value from ub_strerror */

			llog(RC_LOG, logger,
				    "error adding dnssec root key: %s [errno: %s]",
				    ub_strerror(ugh), strerror(e));
			llog(RC_LOG, logger,
				    "WARNING: DNSSEC validation disabled");
		}
	}

	if (trusted == NULL) {
		ldbg(logger, "no additional dnssec trust anchors defined via dnssec-trusted= option");
		return;
	}

	if (!lswglob(trusted, "trusted anchor", add_trust_anchors,
		     /*lswglob_context*/NULL, logger)) {
		llog(RC_LOG, logger, "no trust anchor files matched '%s'", trusted);
	}
}

/*
 * initialize a ub_ctx for asynchronous calls using libevent from pluto.
 *  only call once
 */
diag_t unbound_event_init(struct event_base *eb, bool do_dnssec,
			  const char *rootfile, const char *trusted,
			  struct logger *logger)
{
	PASSERT(logger, dns_ctx == NULL); /* block re-entry to the function */
	dns_ctx = ub_ctx_create_event(eb);
	if (dns_ctx == NULL) {
		return diag("failed to initialize unbound libevent ABI, please recompile libunbound with libevent support or recompile libreswan without USE_DNSSEC");
	}
	unbound_ctx_config(do_dnssec, rootfile, trusted, logger);
	return NULL;
}

/*
 * initialize a ub_ct for blocking dns calls. Do not call from pluto.
 * Call this function once directly, such as addconn.
 * dns_ctx is static in this file. call unbound_ctx_free() to free it.
 */
void unbound_sync_init(bool do_dnssec, const char *rootfile,
		       const char *trusted, struct logger *logger)
{
	PASSERT(logger, dns_ctx == NULL); /* block re-entry to the function */
	dns_ctx = ub_ctx_create();
	PASSERT(logger, dns_ctx != NULL);
	unbound_ctx_config(do_dnssec, rootfile, trusted, logger);
}

/*
 * synchronous blocking resolving - simple replacement of ttoaddress_dns()
 * src_len == 0 means "apply strlen"
 * af == AF_UNSPEC means default to AF_INET(A/IPv4)
 */
bool unbound_resolve(const char *src, const struct ip_info *afi,
		     ip_address *ipaddr, const struct logger *logger)
{
	/* 28 = AAAA record, 1 = A record */
	const int qtype = (afi == &ipv6_info) ? 28/*AAAA*/ : 1/*A*/;

	PASSERT(logger, dns_ctx != NULL);

	if (strlen(src) == 0) {
		return diag("empty hostname in host lookup");
	}

	struct ub_result *result;
	int ugh = ub_resolve(dns_ctx, src, qtype, 1 /* CLASS IN */, &result);
	if (ugh != 0) {
		llog(RC_LOG, logger, "unbound error: %s", ub_strerror(ugh));
		ub_resolve_free(result);
		return false;
	}

	if (result->bogus) {
		llog(ERROR_STREAM, logger, "%s failed DNSSEC validation", result->qname);
		ub_resolve_free(result);
		return false;
	}

	if (!result->havedata) {
		if (result->secure) {
			ldbg(logger, "validated reply proves '%s' does not exist",
				src);
		} else {
			ldbg(logger, "failed to resolve '%s' (%s)", src,
				result->bogus ? "BOGUS" : "insecure");
		}
		ub_resolve_free(result);
		return false;
	}

	if (!result->secure) {
		ldbg(logger, "%s lookup was not protected by DNSSEC!", result->qname);
	}

	if (LDBGP(DBG_TMI, logger)) {
		int i = 0;
		LDBG_log(logger, "The result has:");
		LDBG_log(logger, "qname: %s", result->qname);
		LDBG_log(logger, "qtype: %d", result->qtype);
		LDBG_log(logger, "qclass: %d", result->qclass);
		if (result->canonname) {
			LDBG_log(logger, "canonical name: %s", result->canonname);
		}
		LDBG_log(logger, "DNS rcode: %d", result->rcode);

		for (i = 0; result->data[i] != NULL; i++) {
			LDBG_log(logger, "result data element %d has length %d",
				 i, result->len[i]);
		}
		LDBG_log(logger, "result has %d data element(s)", i);
	}

	/* XXX: for now pick the first one and return that */
	PASSERT(logger, result->data != NULL);
	PASSERT(logger, result->data[0] != NULL);
	PASSERT(logger, result->len != NULL);

	/*
	 * XXX: data_to_address() only requires the length >=
	 * address-length.
	 */
	diag_t diag = data_to_address(result->data[0], (size_t)result->len[0], afi, ipaddr);
	if (diag != NULL) {
		llog_pexpect(logger, HERE, "invalid dns address record: %s",
			     str_diag(diag));
		pfree_diag(&diag);
		ub_resolve_free(result);
		return false;
	}

	ldbg(logger, "success for %s lookup", afi->ip_name);
	return true;
}

struct ub_ctx * get_unbound_ctx(void)
{
	return dns_ctx;
}
