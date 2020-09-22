
#include "nss_cert_reread.h"
#include "connections.h"
#include "constants.h"
#include "defs.h"
#include "keys.h"
#include "log.h"
#include "nss_cert_load.h"
#include "whack.h"

static inline cert_t backup_cert(struct end *dst)
{
	cert_t backup;

	backup.ty = dst->cert.ty;
	backup.u.nss_cert = dst->cert.u.nss_cert;

	return backup;
}

/* Reread a certificate from the NSS database */
static bool nss_reread_cert(struct end *dst, struct logger *logger)
{
	const char *nickname = cert_nickname(&dst->cert);
	if (nickname == NULL) {
		log_message(RC_BADID, logger,
			    "certificate cannot reread due to unknown nickname");
		return false;
	}

	CERTCertificate *cert = get_cert_by_nickname_from_nss(nickname, logger);
	if (cert == NULL) {
		log_message(RC_LOG, logger,
			    "%s certificate '%s' not found in the NSS database",
			    dst->leftright, nickname);
		return false;
	}

	diag_t diag = add_end_cert_and_preload_private_key(cert, dst, logger);
	if (diag != NULL) {
		log_diag(RC_BADID, logger, &diag,
			 "rereading certificate failed for nickname '%s': ", nickname);
		return false;
	}

	return true;
}

static void reread_end_cert(struct end *dst, struct logger *logger)
{
	if (dst->cert.u.nss_cert == NULL) {
		dbg("no cert exists for %s; nothing to do", dst->leftright);
	} else {
		cert_t old_cert = backup_cert(dst);

		if (!nss_reread_cert(dst, logger)) {
			dst->cert.ty = old_cert.ty;
			dst->cert.u.nss_cert = old_cert.u.nss_cert;
			return;
		}

		log_message(RC_COMMENT, logger,
			    "certificate %scert=%s has been reloaded",
			    dst->leftright, cert_nickname(&dst->cert));
		if (old_cert.u.nss_cert != NULL)
			CERT_DestroyCertificate(old_cert.u.nss_cert);
	}
}

void reread_cert(struct fd *whackfd, struct connection *c)
{
	struct end *dst;

	dbg("rereading certificate(s) for connection '%s'", c->name);
	struct logger logger[1] = { CONNECTION_LOGGER(c, whackfd), };

	dst = &c->spd.this;
	reread_end_cert(dst, logger);

	dst = &c->spd.that;
	reread_end_cert(dst, logger);
}
