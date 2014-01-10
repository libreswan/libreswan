/*
 * Use libunbound to use DNSSEC supported resolving.
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
#error this file should only be compiled when using USE_DNSSEC
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

#include <unbound.h>
#include "dnssec.h"

#include <errno.h>

/* DNSSEC root key */
static char *rootanchor =
	". IN DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=";

/* DNSSEC DLV key, see http://dlv.isc.org/ */
static char *dlvanchor =
	"dlv.isc.org. IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5ymX4BI/oQ+cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URkY62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboMQKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VStTDN0YUuWrBNh";

int unbound_init(struct ub_ctx *dnsctx)
{
	int ugh;

	/* create unbound resolver context */
	dnsctx = ub_ctx_create();
	if (!dnsctx) {
		libreswan_log("error: could not create unbound context\n");
		return 0;
	}
	DBG(DBG_DNS,
	    ub_ctx_debuglevel(dnsctx, 5);
	    DBG_log("unbound context created - setting debug level to 5\n"));

	/* lookup from /etc/hosts before DNS lookups as people expect that */
	if ( (ugh = ub_ctx_hosts(dnsctx, "/etc/hosts")) != 0) {
		libreswan_log("error reading hosts: %s: %s\n",
			      ub_strerror(ugh), strerror(errno));
		return 0;
	}
	DBG(DBG_DNS, DBG_log("/etc/hosts lookups activated\n"));

	/*
	 * Use /etc/resolv.conf as forwarding cache - we expect people to reconfigure this
	 * file if they need to work around DHCP DNS obtained servers
	 */
	if ( (ugh = ub_ctx_resolvconf(dnsctx, "/etc/resolv.conf")) != 0) {
		libreswan_log("error reading resolv.conf: %s: %s\n",
			      ub_strerror(ugh), strerror(errno));
		return 0;
	}
	DBG(DBG_DNS, DBG_log("/etc/resolv.conf usage activated\n"));

	/* add trust anchors to libunbound context - make this configurable later */
	DBG(DBG_DNS, DBG_log("Loading root key:%s\n", rootanchor));
	ugh = ub_ctx_add_ta(dnsctx, rootanchor);
	if (ugh != 0) {
		libreswan_log("error adding the DNSSEC root key: %s: %s\n",
			ub_strerror(ugh), strerror(errno));
		return 0;
	}

	/* Enable DLV */
	DBG(DBG_DNS, DBG_log("Loading dlv key:%s\n", dlvanchor));
	ugh = ub_ctx_set_option(dnsctx, "dlv-anchor:", dlvanchor);
	if (ugh != 0) {
		libreswan_log("error adding the DLV key: %s: %s\n",
			ub_strerror(ugh), strerror(errno));
		return 0;
	}

	return 1;
}

/* synchronous blocking resolving - simple replacement of ttoaddr()
 * src_len 0 means "apply strlen"
 * af 0 means "try both families
 */
int unbound_resolve(struct ub_ctx *dnsctx, char *src, size_t srclen, int af,
		    ip_address *ipaddr)
{
	const int qtype = (af == AF_INET6) ? 28 : 1; /* 28 = AAAA record, 1 = A record */
	struct ub_result *result;

	passert(dnsctx != NULL);

	if (srclen == 0) {
		srclen = strlen(src);
		if (srclen == 0) {
			libreswan_log("empty hostname in host lookup\n");
			ub_resolve_free(result);
			return 0;
		}
	}

	{
		int ugh = ub_resolve(dnsctx, src, qtype, 1 /* CLASS IN */,
				     &result);
		if (ugh != 0) {
			libreswan_log("unbound error: %s", ub_strerror(ugh));
			ub_resolve_free(result);
			return 0;
		}
	}

	if (result->bogus) {
		libreswan_log("ERROR: %s failed DNSSEC valdation!\n",
			      result->qname);
		ub_resolve_free(result);
		return 0;
	}
	if (!result->havedata) {
		if (result->secure) {
			DBG(DBG_DNS,
			    DBG_log("Validated reply proves '%s' does not exist\n",
				    src));
		} else {
			DBG(DBG_DNS,
			    DBG_log("Failed to resolve '%s' (%s)\n", src,
				    (result->bogus) ? "BOGUS" : "insecure"));
		}
		ub_resolve_free(result);
		return 0;

	} else if (!result->bogus) {
		if (!result->secure) {
			DBG(DBG_DNS,
			    DBG_log("warning: %s lookup was not protected by DNSSEC!\n",
				    result->qname));
		}
	}

#if 0
	{
		int i = 0;
		DBG_log("The result has:\n");
		DBG_log("qname: %s\n", result->qname);
		DBG_log("qtype: %d\n", result->qtype);
		DBG_log("qclass: %d\n", result->qclass);
		if (result->canonname)
			DBG_log("canonical name: %s\n", result->canonname);
		DBG_log("DNS rcode: %d\n", result->rcode);

		for (i = 0; result->data[i] != NULL; i++) {
			DBG_log("result data element %d has length %d\n",
				i, result->len[i]);
		}
		DBG_log("result has %d data element(s)\n", i);
	}
#endif

	/* XXX: for now pick the first one and return that */
	passert(result->data[0] != NULL);
	{
		char dst[INET6_ADDRSTRLEN];
		err_t err = tnatoaddr(inet_ntop(af, result->data[0], dst,
						(af ==
						 AF_INET) ? INET_ADDRSTRLEN :
						INET6_ADDRSTRLEN),
				      0, af, ipaddr);
		ub_resolve_free(result);
		if (err == NULL) {
			DBG(DBG_DNS,
			    DBG_log("success for %s lookup",
				    (af == AF_INET) ? "IPv4" : "IPv6"));
			return 1;
		} else {
			libreswan_log("tnatoaddr failed in unbound_resolve()");
			return 0;
		}
	}
}

#ifdef UNBOUND_MAIN
#include <stdio.h>

int main(int argc, char *argv[])
{

	struct ub_ctx *test;
	ip_address *addr;

	unbound_resolve(&test, "libreswan.org", 0, 0, &addr);

}
#endif
