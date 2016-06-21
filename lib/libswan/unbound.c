/*
 * Use libunbound to use DNSSEC supported resolving.
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
 */
#ifndef DNSSEC
# error this file should only be compiled when using DNSSEC
#endif

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <libreswan.h>
#include <arpa/inet.h>
#include "constants.h"
#include "lswlog.h"
#include <unbound.h>	/* from unbound devel */
#include "dnssec.h"
#include <errno.h>

/* DNSSEC root key */
static const char rootanchor[] =
	". IN DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=";

struct ub_ctx *unbound_init(void)
{
	int ugh;

	/* create unbound resolver context */
	struct ub_ctx *dnsctx = ub_ctx_create();

	if (dnsctx == NULL) {
		libreswan_log("error: could not create unbound context");
		return NULL;
	}
	DBG(DBG_DNS,
		ub_ctx_debuglevel(dnsctx, 5);
		DBG_log("unbound context created - setting debug level to 5");
		);

	/* lookup from /etc/hosts before DNS lookups as people expect that */
	ugh = ub_ctx_hosts(dnsctx, "/etc/hosts");
	if (ugh != 0) {
		libreswan_log("error reading hosts: %s: %s",
			ub_strerror(ugh), strerror(errno));
		ub_ctx_delete(dnsctx);
		return NULL;
	}
	DBG(DBG_DNS,
		DBG_log("/etc/hosts lookups activated");
		);

	/*
	 * Use /etc/resolv.conf as forwarding cache - we expect people to
	 * reconfigure this file if they need to work around DHCP DNS obtained
	 * servers
	 */
	ugh = ub_ctx_resolvconf(dnsctx, "/etc/resolv.conf");
	if (ugh != 0) {
		libreswan_log("error reading resolv.conf: %s: %s",
			ub_strerror(ugh), strerror(errno));
		ub_ctx_delete(dnsctx);
		return NULL;
	}
	DBG(DBG_DNS,
		DBG_log("/etc/resolv.conf usage activated");
		);

	/*
	 * add trust anchors to libunbound context - make this configurable
	 * later
	 */
	DBG(DBG_DNS,
		DBG_log("Loading root key:%s", rootanchor);
		);
#ifdef UNBOUND_VERSION_MAJOR
	ugh = ub_ctx_add_ta(dnsctx, rootanchor);
#else
	/* for unbound < 1.4.21 */
	ugh = ub_ctx_add_ta(dnsctx, (char*) rootanchor);
#endif
	if (ugh != 0) {
		libreswan_log("error adding the DNSSEC root key: %s: %s",
			ub_strerror(ugh), strerror(errno));
		ub_ctx_delete(dnsctx);
		return NULL;
	}

	return dnsctx;
}

/*
 * synchronous blocking resolving - simple replacement of ttoaddr()
 * src_len == 0 means "apply strlen"
 * af == AF_UNSPEC means "try both families"
 */
bool unbound_resolve(struct ub_ctx *dnsctx, char *src, size_t srclen, int af,
		ip_address *ipaddr)
{
	/* 28 = AAAA record, 1 = A record */
	const int qtype = (af == AF_INET6) ? 28 : 1;
	struct ub_result *result;

	passert(dnsctx != NULL);

	if (srclen == 0) {
		srclen = strlen(src);
		if (srclen == 0) {
			libreswan_log("empty hostname in host lookup");
			return FALSE;
		}
	}

	{
		int ugh = ub_resolve(dnsctx, src, qtype, 1 /* CLASS IN */,
				&result);
		if (ugh != 0) {
			libreswan_log("unbound error: %s", ub_strerror(ugh));
			ub_resolve_free(result);
			return FALSE;
		}
	}

	if (result->bogus) {
		libreswan_log("ERROR: %s failed DNSSEC validation!",
			result->qname);
		ub_resolve_free(result);
		return FALSE;
	}
	if (!result->havedata) {
		if (result->secure) {
			DBG(DBG_DNS,
				DBG_log("Validated reply proves '%s' does not exist",
					src);
				);
		} else {
			DBG(DBG_DNS,
				DBG_log("Failed to resolve '%s' (%s)", src,
					result->bogus ? "BOGUS" : "insecure");
				);
		}
		ub_resolve_free(result);
		return FALSE;
	} else if (!result->bogus) {
		if (!result->secure) {
			DBG(DBG_DNS,
				DBG_log("warning: %s lookup was not protected by DNSSEC!",
					result->qname);
				);
		}
	}

#if 0
	{
		int i = 0;
		DBG_log("The result has:");
		DBG_log("qname: %s", result->qname);
		DBG_log("qtype: %d", result->qtype);
		DBG_log("qclass: %d", result->qclass);
		if (result->canonname)
			DBG_log("canonical name: %s", result->canonname);
		DBG_log("DNS rcode: %d", result->rcode);

		for (i = 0; result->data[i] != NULL; i++) {
			DBG_log("result data element %d has length %d",
				i, result->len[i]);
		}
		DBG_log("result has %d data element(s)", i);
	}
#endif

	/* XXX: for now pick the first one and return that */
	passert(result->data[0] != NULL);
	{
		char dst[INET6_ADDRSTRLEN];
		err_t err = tnatoaddr(
			inet_ntop(af, result->data[0], dst,
				(af == AF_INET) ? INET_ADDRSTRLEN :
					INET6_ADDRSTRLEN),
			0, af, ipaddr);
		ub_resolve_free(result);
		if (err == NULL) {
			DBG(DBG_DNS,
				DBG_log("success for %s lookup",
					(af == AF_INET) ? "IPv4" : "IPv6");
				);
			return TRUE;
		} else {
			libreswan_log("tnatoaddr failed in unbound_resolve()");
			return FALSE;
		}
	}
}
