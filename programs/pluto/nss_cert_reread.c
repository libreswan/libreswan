#include <nss.h>

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
static bool nss_reread_cert(struct fd *whackfd, struct end *dst, const char *connstr)
{
	const char *nickname;
	enum whack_pubkey_type pubkey_type;

	nickname = cert_nickname(&dst->cert);
	if (nickname == NULL) {
		log_global(RC_BADID, whackfd, "connection '%s' certificate cannot reread due to unknown nickname",
				connstr);
		return false;
	}

	pubkey_type = WHACK_PUBKEY_CERTIFICATE_NICKNAME;
	if (!load_end_cert_and_preload_secret(whackfd, dst->leftright,
					      nickname, pubkey_type, dst)) {
		log_global(RC_BADID, whackfd, "connection '%s' rereading certificate failed for nickname '%s'",
				connstr, nickname);
		return false;
	}

	return true;
}

static void reread_end_cert(struct fd *whackfd, struct end *dst, const char *connstr)
{
	cert_t old_cert;

	if (dst->cert.u.nss_cert == NULL) {
		dbg("No cert exists for %s of %s; nothing to do", dst->leftright, connstr);
	} else {
		old_cert = backup_cert(dst);

		if (!nss_reread_cert(whackfd, dst, connstr)) {
			dst->cert.ty = old_cert.ty;
			dst->cert.u.nss_cert = old_cert.u.nss_cert;
			return;
		}

		whack_comment(whackfd, "connection '%s' certificate %scert=%s has been reloaded",
				connstr, dst->leftright, cert_nickname(&dst->cert));
		if (old_cert.u.nss_cert != NULL)
			CERT_DestroyCertificate(old_cert.u.nss_cert);
	}
}

void reread_cert(struct fd *whackfd, struct connection *c)
{
	struct end *dst;

	dbg("rereading certificate(s) for connection '%s'", c->name);

	dst = &c->spd.this;
	reread_end_cert(whackfd, dst, c->name);

	dst = &c->spd.that;
	reread_end_cert(whackfd, dst, c->name);
}
