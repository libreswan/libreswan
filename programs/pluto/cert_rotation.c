#include <nss.h>

#include "cert_rotation.h"
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

static inline void restore_cert(struct end *dst, cert_t cert)
{
	// restore old certs
	dst->cert.ty = cert.ty;
	dst->cert.u.nss_cert = cert.u.nss_cert;
}

static inline void release_cert(cert_t cert)
{
	if (cert.u.nss_cert != NULL)
		CERT_DestroyCertificate(cert.u.nss_cert);
}

// This function attempts to load a new cert if NSS DB has a new one
static bool attempt_new_cert(struct fd *whackfd, struct end *dst)
{
	const char *nickname;
	enum whack_pubkey_type pubkey_type;

	nickname = cert_nickname(&dst->cert);
	if (nickname == NULL) {
		whack_comment(whackfd, "No cert nickname found");
		return false;
	}

	pubkey_type = WHACK_PUBKEY_CERTIFICATE_NICKNAME;
	if (!load_end_cert_and_preload_secret(whackfd, dst->leftright,
					      nickname, pubkey_type, dst)) {
		whack_comment(whackfd, "New cert attempt failed for %s", nickname);
		return false;
	}

	return true;
}

static void rotate_end_cert(struct fd *whackfd, struct end *dst)
{
	cert_t old_cert;

	if (dst->cert.u.nss_cert == NULL)
		whack_comment(whackfd, "No cert exists for %s; nothing to do",
			      dst->leftright);
	else {
		old_cert = backup_cert(dst);

		if (!attempt_new_cert(whackfd, dst)) {
			whack_comment(whackfd, "Cert rotation failed for %s",
				      dst->leftright);
			restore_cert(dst, old_cert);
			return;
		}

		whack_comment(whackfd, "Cert rotation complete for %s",
			      dst->leftright);
		release_cert(old_cert);
	}
}

void rotate_cert(struct fd *whackfd, const struct whack_message *wm)
{
	struct connection *conn;
	struct end *dst;

	conn = conn_by_name(wm->name, false);
	if (conn == NULL)  {
		whack_comment(whackfd, "No connection '%s' found", wm->name);
		return;
	}

	dst = &conn->spd.this;
	rotate_end_cert(whackfd, dst);

	dst = &conn->spd.that;
	rotate_end_cert(whackfd, dst);
}
