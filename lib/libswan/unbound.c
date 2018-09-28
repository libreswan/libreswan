/*
 * Use libunbound to use DNSSEC supported resolving.
 *
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
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
#include <libreswan.h>
#include <arpa/inet.h>
#include <errno.h>
#include <glob.h>
#include <event2/event.h>
#include <unbound.h>	/* from unbound devel */
#include <unbound-event.h> /* from unbound devel */

#include "dnssec.h"
#include "constants.h"
#include "lswlog.h"

static struct ub_ctx *dns_ctx = NULL;

void unbound_ctx_free(void)
{
	if (dns_ctx != NULL) {
		ub_ctx_delete(dns_ctx);
		dns_ctx = NULL;
	}
}

static int globugh_ta(const char *epath, int eerrno)
{
	LOG_ERRNO(eerrno, "problem with trusted anchor file \"%s\"", epath);
	return 1;	/* stop glob */
}

static void unbound_ctx_config(bool do_dnssec, const char *rootfile, const char *trusted)
{
	int ugh;

	if (DBGP(DBG_DNS)) {
		ub_ctx_debuglevel(dns_ctx, 5);
		DBG_log("unbound context created - setting debug level to 5");
	};

	/* lookup from /etc/hosts before DNS lookups as people expect that */
	ugh = ub_ctx_hosts(dns_ctx, "/etc/hosts");
	if (ugh != 0) {
		loglog(RC_LOG_SERIOUS, "error reading hosts: %s: %s",
			ub_strerror(ugh), strerror(errno));
	} else {
		DBG(DBG_DNS, DBG_log("/etc/hosts lookups activated"));
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

		loglog(RC_LOG_SERIOUS, "error reading /etc/resolv.conf: %s: [errno: %s]",
			ub_strerror(ugh), strerror(e));
	} else {
		DBG(DBG_DNS, DBG_log("/etc/resolv.conf usage activated"));
	}

	if (!do_dnssec) {
		/* No DNSSEC - nothing more to configure */
		DBG(DBG_DNS, DBG_log("dnssec validation disabled by configuration"));
	}

	if (rootfile == NULL) {
		if (trusted != NULL) {
			loglog(RC_LOG_SERIOUS, "dnssec-enable=yes but no dnssec-rootkey-file or trust anchors specified.");
			loglog(RC_LOG_SERIOUS, "WARNING: DNSSEC validation disabled");
		}
	} else {
		DBG(DBG_DNS, DBG_log("Loading dnssec root key from:%s", rootfile));
		errno = 0;
		ugh = ub_ctx_add_ta_file(dns_ctx, rootfile);
		if (ugh != 0) {
			int e = errno;	/* protect value from ub_strerror */

			loglog(RC_LOG_SERIOUS, "error adding dnssec root key: %s [errno: %s]",
				ub_strerror(ugh), strerror(e));
			loglog(RC_LOG_SERIOUS, "WARNING: DNSSEC validation likely broken!");
		}
	}

	if (trusted == NULL) {
		DBG(DBG_DNS, DBG_log("No additional dnssec trust anchors defined via dnssec-trusted= option"));
	} else {
		glob_t globbuf;
		char **fnp;
		int r = glob(trusted, GLOB_ERR, globugh_ta, &globbuf);

		switch (r) {
		case 0:	/* success */
			for (fnp = globbuf.gl_pathv; fnp != NULL && *fnp != NULL; fnp++) {
				ugh = ub_ctx_add_ta_file(dns_ctx, *fnp);
				if (ugh != 0) {
					loglog(RC_LOG_SERIOUS, "Ignored trusted key file %s: %s",
						*fnp,  ub_strerror(ugh));
				} else {
					DBG(DBG_DNS, DBG_log("Added contents of trusted key file %s to unbound resolver context",
						*fnp));
				}
			}
			break;

		case GLOB_NOSPACE:
			loglog(RC_LOG_SERIOUS, "out of space processing dnssec-trusted= argument: %s",
				trusted);
			break;

		case GLOB_ABORTED:
			/* already logged by globugh_ta */
			break;

		case GLOB_NOMATCH:
			loglog(RC_LOG_SERIOUS, "no trust anchor files matched '%s'", trusted);
			break;

		default:
			loglog(RC_LOG_SERIOUS, "trusted key file '%s': unknown glob error %d",
				trusted, r);
			break;
		}
		globfree(&globbuf);
	}
}

/*
 * initialize a ub_ctx for asynchronous calls using libevent from pluto.
 *  only call once
 */
bool unbound_event_init(struct event_base *eb, bool do_dnssec,
			const char *rootfile, const char *trusted)
{
	passert(dns_ctx == NULL); /* block re-entry to the function */
	dns_ctx = ub_ctx_create_event(eb);
	if (dns_ctx == NULL) {
		loglog(RC_LOG_SERIOUS, "Failed to initialize unbound libevent ABI, please recompile libunbound with libevent support or recompile libreswan without USE_DNSSEC");
		return FALSE;
	}
	unbound_ctx_config(do_dnssec, rootfile, trusted);
	return TRUE;
}

/*
 * initialize a ub_ct for blocking dns calls. Do not call from pluto.
 * Call this function once directly, such as addconn.
 * dns_ctx is static in this file. call unbound_ctx_free() to free it.
 */
void unbound_sync_init(bool do_dnssec, const char *rootfile,
			const char *trusted)
{
	if (!do_dnssec)
		return;

	passert(dns_ctx == NULL); /* block re-entry to the function */
	dns_ctx = ub_ctx_create();
	passert(dns_ctx != NULL);
	unbound_ctx_config(do_dnssec, rootfile, trusted);
}

/*
 * synchronous blocking resolving - simple replacement of ttoaddr()
 * src_len == 0 means "apply strlen"
 * af == AF_UNSPEC means "try both families"
 */
bool unbound_resolve(char *src, size_t srclen, int af, ip_address *ipaddr)
{
	/* 28 = AAAA record, 1 = A record */
	const int qtype = (af == AF_INET6) ? 28 : 1;
	struct ub_result *result;

	passert(dns_ctx != NULL);

	if (srclen == 0) {
		srclen = strlen(src);
		if (srclen == 0) {
			libreswan_log("empty hostname in host lookup");
			return FALSE;
		}
	}

	{
		int ugh = ub_resolve(dns_ctx, src, qtype, 1 /* CLASS IN */,
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

struct ub_ctx * get_unbound_ctx(void)
{
	return dns_ctx;
}
