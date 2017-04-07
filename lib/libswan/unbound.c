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
#include <sys/stat.h>
#include <libreswan.h>
#include <arpa/inet.h>
#include "constants.h"
#include "lswlog.h"
#include <unbound.h>	/* from unbound devel */
#include "dnssec.h"
#include <errno.h>
#include <glob.h>

struct ub_ctx *unbound_init(bool do_dnssec, const char *rootfile, const char *trusted)
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
	if (!do_dnssec) {
		/* nothing more to configure */
		libreswan_log("DNSSEC validation disabled by configuration");
		return dnsctx;
	}

	if (rootfile == NULL) {
		libreswan_log("dnssec enabled but no dnssec-rootkey-file specified?");
		return dnsctx;
	} else {
		DBG(DBG_DNS, DBG_log("Loading DNSSEC ROOT key from:%s", rootfile));
		ugh = ub_ctx_add_ta_autr(dnsctx, rootfile);
		if (ugh != 0) {
			libreswan_log("error adding DNSSEC ROOT key: %s: %s",
				ub_strerror(ugh), strerror(errno));
			libreswan_log("WARNING: DNSSEC validation likely broken!");
		}
	}

	if (trusted == NULL) {
		libreswan_log("No additional DNSSEC trust anchors defined via dnssec-trusted= option");
	} else {
		if (strchr(trusted, '*') == NULL) {
			struct stat buf;
			int ugh;
			stat(trusted, &buf);
			if (S_ISREG(buf.st_mode)) {
				ugh = ub_ctx_add_ta_file(dnsctx, trusted);
				if (ugh != 0) {
					libreswan_log("Ignored trusted key file %s: %s",
						trusted,  ub_strerror(ugh));
				} else {
					libreswan_log("Added contents of trusted key file %s to unbound resolved context",
						trusted);
				}
			} else if (S_ISDIR(buf.st_mode)) {
				libreswan_log("PAUL: Add dir + globbing support");
			} else {
				libreswan_log("ignored trusted key '%s': not a regular file or directory",
					trusted);
			}

		} else {
			glob_t globbuf;
			char **fnp;
	                int r = glob(trusted, GLOB_ERR, NULL, &globbuf);

			if (r != 0) {
				switch(r) {
					case GLOB_NOSPACE:
						libreswan_log("out of space procesing dnssec-trusted= argument:%s",
							trusted);
						globfree(&globbuf);
						return dnsctx;
					case GLOB_ABORTED:
						break; /* already logged */
					case GLOB_NOMATCH:
						libreswan_log("no trust anchor files matched '%s'", trusted);
						break;
					default:
						libreswan_log("trusted keys: unknown glob error %d",
							r);
						globfree(&globbuf);
						return dnsctx;
				}
			}

			for (fnp = globbuf.gl_pathv; fnp != NULL && *fnp != NULL; fnp++) {
				ugh = ub_ctx_add_ta_file(dnsctx, *fnp);
				if (ugh != 0) {
					libreswan_log("Ignored trusted key file %s: %s",
						*fnp,  ub_strerror(ugh));
				} else {
					libreswan_log("Added contents of trusted key file %s to unbound resolved context",
						*fnp);
				}
			}
			globfree(&globbuf);
		}
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
