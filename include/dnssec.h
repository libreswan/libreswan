#ifndef _DNSSEC_H
# define _DNSSEC_H

#include <stdbool.h>

#include "ip_address.h"
#include "diag.h"

struct logger;
struct event_base;

extern void unbound_ctx_free(void);
extern void unbound_sync_init(bool do_dnssec, const char *rootfile,
			      const char *trusted, struct logger *logger);

extern diag_t unbound_event_init(struct event_base *eb, bool do_dnssec,
				 const char *rootfile, const char *trusted,
				 struct logger *logger);

extern bool unbound_resolve(char *src, const struct ip_info *afi,
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
