
/*
 * We should not need to include any DNSSEC keys, but we do not (yet) want to depend on that.
 * These keys are valid now (2012 Q1) and should remain valid for many years
 */

#ifndef _DNSSEC_H
# define _DNSSEC_H

#include <unbound.h>

extern int unbound_init(struct ub_ctx *dnsctx);
extern int unbound_resolve(struct ub_ctx *dnsctx, char *src, size_t srclen,
			   int af, ip_address *ipaddr);

#endif
