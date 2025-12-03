#ifndef _DNSSEC_H
# define _DNSSEC_H

#include <stdbool.h>

#include "diag.h"

#include "ip_address.h"

struct logger;
struct event_base;
struct ub_ctx;

struct dnssec_config {
	bool enable;
	const char *rootkey_file;
	const char *anchors;
};

void unbound_ctx_config(struct ub_ctx *dns_ctx,
			const struct dnssec_config *config,
			const struct logger *logger);

extern void unbound_ctx_free(void);
extern void unbound_sync_init(const struct dnssec_config *config,
			      struct logger *logger);
extern diag_t unbound_event_init(struct event_base *eb,
				 const struct dnssec_config *config,
				 struct logger *logger);
extern bool unbound_resolve(const char *src, const struct ip_info *afi,
			    ip_address *ipaddr, const struct logger *logger);

extern struct ub_ctx *get_unbound_ctx(void);

/*
 * returned in callback of ub_resolve_event
 * with sec: 0 if insecure, 1 if bogus, 2 if DNSSEC secure.
 * Note these constants are only for ub_resolve_event.
 * Other resolve functions may have different values for secure.
 * Pluto locally use DNSSEC_SECURE et el..
 *
 *  Separate from this is ub_result.secure, which is true or false,
 *  returned by ub_resolve or ub_resove_async
 */
enum lswub_resolve_event_secure_kind {
	UB_EVENT_INSECURE	= 0,
	UB_EVENT_BOGUS		= 1,
	UB_EVENT_SECURE		= 2,
};

#endif
