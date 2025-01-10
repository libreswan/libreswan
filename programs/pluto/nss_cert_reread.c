
#include "nss_cert_reread.h"
#include "connections.h"
#include "constants.h"
#include "defs.h"
#include "keys.h"
#include "log.h"
#include "nss_cert_load.h"
#include "whack.h"

static void reread_end_cert(struct host_end_config *host_end_config,
			    struct logger *logger)
{
	if (host_end_config->cert.nss_cert == NULL) {
		dbg("no cert exists for %s; nothing to do",
		    host_end_config->leftright);
		return;
	}

	const char *nickname = cert_nickname(&host_end_config->cert);
	if (nickname == NULL) {
		llog(RC_BADID, logger,
		     "reloading %scert failed: cannot be reread due to unknown nickname",
		     host_end_config->leftright);
		return;
	}

	CERTCertificate *new_cert = get_cert_by_nickname_from_nss(nickname, logger); /* must free/save */
	if (new_cert == NULL) {
		llog(RC_LOG, logger,
		     "reloading %scert='%s' failed: not found in the NSS database",
		     host_end_config->leftright, nickname);
		return;
	}

	CERTCertificate *old_cert = host_end_config->cert.nss_cert; /* must free/save */
	host_end_config->cert.nss_cert = NULL;

	diag_t diag = add_end_cert_and_preload_private_key(new_cert, host_end_config,
							   true/*preserve existing ca?!?*/,
							   logger);
	if (diag != NULL) {
		llog(RC_BADID, logger, "reloading %scert='%s' failed: %s",
		     host_end_config->leftright, nickname, str_diag(diag));
		pfree_diag(&diag);
		CERT_DestroyCertificate(new_cert);
		host_end_config->cert.nss_cert = old_cert;
		return;
	}

	CERT_DestroyCertificate(old_cert);
	host_end_config->cert.nss_cert = new_cert;

	llog(RC_LOG, logger,
	     "reloaded %scert='%s'",
	     host_end_config->leftright, cert_nickname(&host_end_config->cert));
}

static void reread_cert(struct connection *c, struct logger *logger)
{
	dbg("rereading certificate(s) for connection '%s'", c->name);

	connection_attach(c, logger);

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		struct host_end_config *host_end_config =
			&c->root_config->end[end].host;
		reread_end_cert(host_end_config, c->logger);
	}

	connection_detach(c, logger);
}


/* reread all left/right certificates from NSS DB */
void reread_cert_connections(struct logger *logger)
{
	struct connection_filter cf = {
		.search = {
			.order = NEW2OLD,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (next_connection(&cf)) {
		struct connection *c = cf.c;
		if (c->root_config != NULL) {
			reread_cert(c, logger);
		}
	}
}
