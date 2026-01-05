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

#ifndef USE_UNBOUND
# error this file should only be compiled when using UNBOUND
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
#include "lswalloc.h"
#include "dnssec.h"
#include "constants.h"
#include "lswlog.h"
#include "ip_info.h"

static lswglob_match_cb add_trust_anchors;

struct lswglob_context {
	struct ub_ctx *ub;
};

static void add_trust_anchors(unsigned count, char **files,
			      struct lswglob_context *context,
			      const struct logger *logger)
{
	struct ub_ctx *ub_ctx = context->ub;
	for (unsigned i = 0; i < count; i++) {
		const char *file = files[i];
		int ugh = ub_ctx_add_ta_file(ub_ctx, file);
		if (ugh != 0) {
			llog(RC_LOG, logger, "ignored trusted key file %s: %s",
			     file,  ub_strerror(ugh));
		} else {
			ldbg(logger, "added contents of trusted key file %s to unbound resolver context", file);
		}
	}
}

void unbound_ctx_config(struct ub_ctx *ub_ctx,
			const struct dnssec_config *config,
			const struct logger *logger)
{
	int ugh;

	if (LDBGP(DBG_BASE, logger)) {
		ub_ctx_debuglevel(ub_ctx, 5);
		LDBG_log(logger, "unbound context created - setting debug level to 5");
	}

	/* lookup from /etc/hosts before DNS lookups as people expect that */
	ugh = ub_ctx_hosts(ub_ctx, "/etc/hosts");
	if (ugh != 0) {
		llog(WARNING_STREAM, logger, "UNBOUND could not load /etc/hosts: %s",
		     ub_strerror(ugh));
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
	ugh = ub_ctx_resolvconf(ub_ctx, "/etc/resolv.conf");
	if (ugh != 0) {
		/* ub_ctx_resolvconf() attempts to preserve errno */
		int e = errno;
		llog_errno(WARNING_STREAM, logger, e,
			   "UNBOUND: could not load /etc/resolv.conf: %s; ",
			   ub_strerror(ugh));
	} else {
		ldbg(logger, "UNBOUND: /etc/resolv.conf usage activated");
	}

	/*
	 * Limit outgoing ports to those allowed by common SELinux policy
	 */
	const char *outgoing_port_avoid = "0-65535";
	ugh = ub_ctx_set_option(ub_ctx, "outgoing-port-avoid:", outgoing_port_avoid);
	if (ugh != 0) {
		llog(WARNING_STREAM, logger, "UNBOUND: could not set outgoing-port-avoid=%s: %s",
		     outgoing_port_avoid, ub_strerror(ugh));
	} else {
		ldbg(logger, "UNBOUND: set outgoing-port-avoid=%s", outgoing_port_avoid);
	}

	const char *outgoing_port_permit = "32768-60999";
	ugh = ub_ctx_set_option(ub_ctx, "outgoing-port-permit:", outgoing_port_permit);
	if (ugh != 0) {
		llog(WARNING_STREAM, logger, "UNBOUND: could not set outgoing-port-permit=%s: %s",
		     outgoing_port_permit, ub_strerror(ugh));
	} else {
		ldbg(logger, "UNBOUND: set outgoing-port-permit=%s", outgoing_port_permit);
	}

	if (!config->enable) {
		/* No DNSSEC - nothing more to configure */
		ldbg(logger, "UNBOUND: dnssec validation disabled by configuration");
		return;
	}

	/* Only DNSSEC related configuration from here */

	if (config->rootkey_file == NULL) {
		llog(WARNING_STREAM, logger,
		     "UNBOUND: DNSSEC validation disabled, dnssec-enable=yes but no dnssec-rootkey-file was specified");
		return;
	}

	ldbg(logger, "UNBOUND: loading dnssec root key from: %s", config->rootkey_file);
	ugh = ub_ctx_add_ta_file(ub_ctx, config->rootkey_file);
	if (ugh != 0) {
		llog(WARNING_STREAM, logger,
		     "UNBOUND: DNSSEC validation disabled, adding dnssec root key failed: %s; ",
		     ub_strerror(ugh));
	}

	if (config->anchors == NULL) {
		ldbg(logger, "UNBOUND: no additional dnssec trust anchors defined via dnssec-trusted= option");
	} else {
		ldbg(logger, "UNBOUND: adding additional trust anchors matching: %s", config->anchors);
		struct lswglob_context lswglob_context = {
			.ub = ub_ctx,
		};
		if (!lswglob(config->anchors, "trusted anchor", add_trust_anchors,
			     &lswglob_context, logger)) {
			llog(RC_LOG, logger, "UNBOUND: no trust anchor files matched '%s'", config->anchors);
		}
	}
}

/*
 * synchronous blocking resolving - simple replacement of ttoaddress_dns()
 * af == AF_UNSPEC means default to AF_INET(A/IPv4)
 */
static diag_t unbound_sync_resolve_1(struct ub_ctx *dns_ctx,
				     const char *src, const struct ip_info *afi,
				     ip_address *ipaddr,
				     struct verbose verbose)
{
	/* 28 = AAAA record, 1 = A record */
	const int qtype = (afi == &ipv6_info) ? 28/*AAAA*/ : 1/*A*/;

	vassert(dns_ctx != NULL);

	struct ub_result *result = NULL;
	int ugh = ub_resolve(dns_ctx, src, qtype, 1 /* CLASS IN */, &result);
	if (ugh != 0) {
		vexpect(result == NULL);
		return diag("unbound error: %s", ub_strerror(ugh));
	}

	vexpect(result != NULL);

	if (result->bogus) {
		diag_t d = diag("domain '%s' is bogus: %s", src, result->why_bogus);
		ub_resolve_free(result);
		return d;
	}

	if (!result->havedata) {
		name_buf rcode; /*same-scope-as-rcode*/
		str_sparse_short(&dnssec_rcode_stories, result->rcode, &rcode);
		diag_t d =
			(result->secure && result->rcode == 0 ? diag("domain '%s' does not exist, proved by validated reply", src) :
			 result->secure ? diag("domain '%s' does not exist, proved by validated reply: %s (rcode %d)",
					       src, rcode.buf, result->rcode) :
			 result->nxdomain ? diag("domain '%s' does not exist: %s (rcode %d)",
						 src, rcode.buf, result->rcode) :
			 diag("domain '%s' has no data: %s (rcode %d)",
			      src, rcode.buf, result->rcode));
		ub_resolve_free(result);
		return d;
	}

	if (!result->secure) {
		vdbg("%s lookup was not protected by DNSSEC!", result->qname);
	}

	if (LDBGP(DBG_TMI, verbose.logger)) {
		int i = 0;
		LDBG_log(verbose.logger, "The result has:");
		LDBG_log(verbose.logger, "qname: %s", result->qname);
		LDBG_log(verbose.logger, "qtype: %d", result->qtype);
		LDBG_log(verbose.logger, "qclass: %d", result->qclass);
		if (result->canonname) {
			LDBG_log(verbose.logger, "canonical name: %s", result->canonname);
		}
		LDBG_log(verbose.logger, "DNS rcode: %d", result->rcode);

		for (i = 0; result->data[i] != NULL; i++) {
			LDBG_log(verbose.logger, "result data element %d has length %d",
				 i, result->len[i]);
		}
		LDBG_log(verbose.logger, "result has %d data element(s)", i);
	}

	/* XXX: for now pick the first one and return that */
	vassert(result->data != NULL);
	vassert(result->data[0] != NULL);
	vassert(result->len != NULL);

	/*
	 * XXX: data_to_address() only requires the length >=
	 * address-length.
	 */
	diag_t diag = data_to_address(result->data[0], (size_t)result->len[0], afi, ipaddr);
	ub_resolve_free(result);

	if (diag != NULL) {
		return diag_diag(&diag, "domain '%s' has invalid dns address record, ", src);
	}

	return NULL;
}


diag_t unbound_sync_resolve(const char *src,
			    const struct ip_info *afi,
			    ip_address *ipaddr,
			    struct verbose verbose)
{
	/*
	 * Initialize a ub_ctx for blocking dns calls.
	 */
	struct ub_ctx *dns_ctx = ub_ctx_create();
	vassert(dns_ctx != NULL);
	unbound_ctx_config(dns_ctx, dnssec_config_singleton(verbose.logger), verbose.logger);

	diag_t d = unbound_sync_resolve_1(dns_ctx, src, afi, ipaddr, verbose);

	ub_ctx_delete(dns_ctx);
	return d;
}
