
#include "nss_cert_reread.h"
#include "connections.h"
#include "constants.h"
#include "defs.h"
#include "keys.h"
#include "log.h"
#include "nss_cert_load.h"
#include "whack.h"

static void reread_end_cert(struct end *dst, struct logger *logger)
{
	if (dst->cert.nss_cert == NULL) {
		dbg("no cert exists for %s; nothing to do", dst->config->leftright);
		return;
	}

	const char *nickname = cert_nickname(&dst->cert);
	if (nickname == NULL) {
		llog(RC_BADID, logger,
		     "certificate cannot reread due to unknown nickname");
		return;
	}

	CERTCertificate *new_cert = get_cert_by_nickname_from_nss(nickname, logger); /* must free/save */
	if (new_cert == NULL) {
		llog(RC_LOG, logger,
		     "%s certificate '%s' not found in the NSS database",
		     dst->config->leftright, nickname);
		return;
	}

	CERTCertificate *old_cert = dst->cert.nss_cert; /* must free/save */
	dst->cert.nss_cert = NULL;

	diag_t diag = add_end_cert_and_preload_private_key(new_cert, dst,
							   true/*preserve existing ca?!?*/,
							   logger);
	if (diag != NULL) {
		llog_diag(RC_BADID, logger, &diag,
			 "rereading certificate failed for nickname '%s': ", nickname);
		CERT_DestroyCertificate(new_cert);
		dst->cert.nss_cert = old_cert;
		return;
	}

	CERT_DestroyCertificate(old_cert);
	dst->cert.nss_cert = new_cert;

	llog(RC_COMMENT, logger,
	     "certificate %scert=%s has been reloaded",
	     dst->config->leftright, cert_nickname(&dst->cert));
}

static void reread_cert(struct connection *c, struct logger *logger)
{
	dbg("rereading certificate(s) for connection '%s'", c->name);
	struct end *dst;

	/* XXX: something better? */
	close_any(&c->logger->global_whackfd);
	c->logger->global_whackfd = fd_dup(logger->global_whackfd, HERE);

	dst = &c->spd.this;
	reread_end_cert(dst, c->logger);

	dst = &c->spd.that;
	reread_end_cert(dst, c->logger);

	/* XXX: something better? */
	close_any(&c->logger->global_whackfd);
}


/* reread all left/right certificates from NSS DB */
void reread_cert_connections(struct logger *logger)
{
	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (struct connection *c = connections; c != NULL; c = c->ac_next) {
		reread_cert(c, logger);
	}
}
