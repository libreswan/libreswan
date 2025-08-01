/* IKEv2 EAP authentication, for libreswan
 *
 * Copyright (C) 2021 Timo Teräs <timo.teras@iki.fi>
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

/* TODO:
 * - fix EAP+PAM authentication
 * - fix EAP+PPK
 * - fix/audit sending error notifys
 * - fix EAP-TLS alert sending and receiving properly
 * - fix non-EAP code path to check EAP was not configured
 * - implement N(EAPONLY)
 * - check client certificate IDs per connection config
 * - should the refine connection code account for EAP?
 * - use helper thread to do NSS crypto?
 */

#include <ssl.h>
#include <prmem.h>

#include "defs.h"
#include "lswnss.h"
#include "state.h"
#include "log.h"
#include "ikev2.h"
#include "ikev2_message.h"
#include "ikev2_eap.h"
#include "ikev2_psk.h"
#include "ikev2_send.h"
#include "ikev2_ike_auth.h"
#include "ikev2_peer_id.h"
#include "ikev2_redirect.h"
#include "ikev2_cert.h"
#include "ikev2_child.h"
#include "pluto_stats.h"
#include "pluto_x509.h"
#include "packet.h"
#include "demux.h"
#include "keys.h"
#include "secrets.h"
#include "connections.h"
#include "crypt_prf.h"
#include "ikev2_states.h"
#include "ikev2_auth.h"
#include "ikev2_notification.h"

static ikev2_llog_success_fn llog_success_process_v2_IKE_AUTH_EAP_request;

static ikev2_state_transition_fn process_v2_IKE_AUTH_request_EAP_start;
static ikev2_state_transition_fn process_v2_IKE_AUTH_request_EAP_final;
static ikev2_state_transition_fn process_v2_IKE_AUTH_request_EAP_continue;

static v2_auth_signature_cb process_v2_IKE_AUTH_request_EAP_start_signature_continue;

struct eap_state {
	struct logger    *logger;
	uint8_t          eap_id;
	uint8_t          eap_established;

	PRFileDesc     *eaptls_desc;	/* EAP TLS */
	struct pbs_out eaptls_outbuf;
	shunk_t        eaptls_inbuf;
	chunk_t        eaptls_chunk;
	uint32_t       eaptls_pos;
};

#define llog_eap(RC_FLAGS, EAP, MSG, ...) llog(RC_FLAGS, (EAP)->logger, MSG, ##__VA_ARGS__)

static PRStatus eaptls_io_close(PRFileDesc *fd)
{
	struct eap_state *eap = (void*)fd->secret;
	llog_eap(RC_LOG, eap, "NSS: I/O close");
	return PR_SUCCESS;
}

static PRStatus eaptls_io_getpeername(PRFileDesc *fd, PRNetAddr *addr)
{
	struct eap_state *eap = (void*)fd->secret;
	llog_eap(RC_LOG, eap, "NSS: I/O getpeername");
	memset(addr, 0, sizeof(*addr));
	addr->inet.family = PR_AF_INET;
	return PR_SUCCESS;
}

static PRStatus eaptls_io_getsocketoption(PRFileDesc *fd,
					  PRSocketOptionData *data)
{
	struct eap_state *eap = (void*)fd->secret;
	switch (data->option) {
	case PR_SockOpt_Nonblocking:
		llog_eap(RC_LOG, eap, "NSS: I/O getsocketoption(Nonblocking)");
		data->value.non_blocking = PR_TRUE;
		return PR_SUCCESS;
	default:
		llog_eap(RC_LOG, eap, "NSS: I/O getsocketoption(%d)", data->option);
		return PR_FAILURE;
	}
}

static PRInt32 eaptls_io_shutdown(PRFileDesc *fd, PRInt32 how)
{
	struct eap_state *eap = (void*)fd->secret;
	llog_eap(RC_LOG, eap, "NSS: I/O shutdown(%d)", how);
	return PR_SUCCESS;
}

static PRInt32 eaptls_io_read(PRFileDesc *fd, void *buf UNUSED, PRInt32 amount)
{
	struct eap_state *eap = (void*)fd->secret;
	llog_eap(RC_LOG, eap, "NSS: I/O read(%d)", amount);
	return PR_FAILURE;
}

static PRInt32 eaptls_io_write(PRFileDesc *fd, const void *buf UNUSED, PRInt32 amount)
{
	struct eap_state *eap = (void*)fd->secret;
	llog_eap(RC_LOG, eap, "NSS: I/O write(%d)", amount);
	return PR_FAILURE;
}

static PRInt32 eaptls_io_recv(PRFileDesc *fd, void *buf, PRInt32 amount,
			      PRIntn flags UNUSED, PRIntervalTime timeout UNUSED)
{
	struct eap_state *eap = (void*)fd->secret;
	PRInt32 len = PMIN(eap->eaptls_inbuf.len, (size_t)amount);

	memcpy(buf, eap->eaptls_inbuf.ptr, len);
	eap->eaptls_inbuf.ptr += len;
	eap->eaptls_inbuf.len -= len;

	if (len == 0) {
		llog_eap(RC_LOG, eap, "NSS: I/O recv(%d): would block", amount);
		PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
		return -1;
	}

	llog_eap(RC_LOG, eap, "NSS: I/O recv(%d): return %d", amount, len);
	return len;
}

static PRInt32 eaptls_io_send(PRFileDesc *fd, const void *buf, PRInt32 amount,
			      PRIntn flags UNUSED, PRIntervalTime timeout UNUSED)
{
	struct eap_state *eap = (void*)fd->secret;
	if (!pbs_out_raw(&eap->eaptls_outbuf, buf, amount, "EAP data")) {
		/* already logged */
		return PR_FAILURE;
	}
	llog_eap(RC_LOG, eap, "NSS: I/O send(%d): ok", amount);
	return amount;
}

static const PRIOMethods eaptls_io = {
	.file_type = PR_DESC_LAYERED,
	.close = eaptls_io_close,
	.getpeername = eaptls_io_getpeername,
	.getsocketoption = eaptls_io_getsocketoption,
	.shutdown = eaptls_io_shutdown,
	.read = eaptls_io_read,
	.write = eaptls_io_write,
	.recv = eaptls_io_recv,
	.send = eaptls_io_send,
};

static PRDescIdentity get_layer_name(void)
{
	static PRDescIdentity layer_id = PR_INVALID_IO_LAYER;
	if (layer_id == PR_INVALID_IO_LAYER) {
		SSL_ConfigServerSessionIDCache(0, 0, 0, NULL);
		layer_id = PR_GetUniqueIdentity("libreswan ike eap-tls");
	}
	return layer_id;
}

static SECStatus eaptls_bad_cert_cb(void *client_data, PRFileDesc *fd)
{
	struct eap_state *eap = client_data;
	CERTCertificate *cert;
	char *subject, *issuer;

	llog_nss_error(RC_LOG, eap->logger, "Bad Server Certificate");

	cert = SSL_PeerCertificate(fd);
	subject = CERT_NameToAscii(&cert->subject);
	issuer = CERT_NameToAscii(&cert->issuer);

	llog_eap(RC_LOG, eap, "NSS: Peer certificate subject='%s' issuer='%s'", subject, issuer);
	CERT_DestroyCertificate(cert);
	PR_Free(subject);
	PR_Free(issuer);
	return SECFailure; //SECSuccess if ignore cert
}

static void eaptls_handshake_cb(PRFileDesc *fd UNUSED, void *client_data)
{
	struct eap_state *eap = client_data;
	llog_eap(RC_LOG, eap, "NSS: Handshake completed");
	eap->eap_established = 1;
}

static struct eap_state *alloc_eap_state(struct logger *logger)
{
	struct eap_state *eap = alloc_thing(struct eap_state, "EAP state");
	eap->logger = logger;
	return eap;
}

void free_eap_state(struct eap_state **_eap)
{
	struct eap_state *eap = *_eap;
	if (eap == NULL)
		return;

	if (eap->eaptls_desc) PR_Close(eap->eaptls_desc);
	free_chunk_content(&eap->eaptls_chunk);

	pfree(eap);
	*_eap = NULL;
}


static bool start_eap(struct ike_sa *ike, struct pbs_out *pbs)
{
	struct logger *logger = ike->sa.logger;
	struct eap_state *eap;
	struct pbs_out pb_eap;

	eap = alloc_eap_state(logger);
	ike->sa.st_eap = eap;

	struct ikev2_generic ie = {
		.isag_critical = build_ikev2_critical(false, ike->sa.logger),
	};
	struct eap_tls eap_payload = {
		.eap_code = EAP_CODE_REQUEST,
		.eap_identifier = eap->eap_id++,
		.eap_type = EAP_TYPE_TLS,
		.eaptls_flags = EAPTLS_FLAGS_START,
	};

	const struct connection *c = ike->sa.st_connection;
	const struct cert *mycert = c->local->host.config->cert.nss_cert != NULL ? &c->local->host.config->cert : NULL;

	if (!mycert)
		return false;

	const struct secret_pubkey_stuff *pks = get_local_private_key(c, &pubkey_type_rsa,
								      ike->sa.logger);
	if (pks == NULL) {
		llog_sa(RC_LOG, ike, "private key for connection not found");
		return false;
	}

	if (!pbs_out_struct(pbs, ie, &ikev2_eap_desc, &pb_eap) ||
	    !pbs_out_struct(&pb_eap, eap_payload, &eap_tls_desc, NULL))
		return false;

	close_pbs_out(&pb_eap);
	llog_sa(RC_LOG, ike, "added EAP payload to packet");

	PRFileDesc *pr = PR_CreateIOLayerStub(get_layer_name(), &eaptls_io);
	if (!pr) {
		llog_nss_error(RC_LOG, logger, "Failed to create TLS IO layer");
		return false;
	}
	eap->eaptls_desc = pr;
	pr->secret = (void*) eap;

	if (!SSL_ImportFD(NULL, pr) ||
	    SSL_OptionSet(pr, SSL_SECURITY, PR_TRUE) != SECSuccess ||
	    SSL_OptionSet(pr, SSL_REQUEST_CERTIFICATE, PR_TRUE) != SECSuccess ||
	    SSL_OptionSet(pr, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_ALWAYS) != SECSuccess ||
	    SSL_OptionSet(pr, SSL_ENABLE_SERVER_DHE, PR_TRUE) != SECSuccess ||
	    SSL_OptionSet(pr, SSL_ENABLE_SSL2, PR_FALSE) != SECSuccess ||
	    SSL_OptionSet(pr, SSL_ENABLE_SSL3, PR_FALSE) != SECSuccess ||
	    SSL_BadCertHook(pr, eaptls_bad_cert_cb, eap) != SECSuccess ||
	    SSL_HandshakeCallback(pr, eaptls_handshake_cb, eap) != SECSuccess ||
	    SSL_ConfigServerCert(pr, mycert->nss_cert, pks->private_key, 0, 0) != SECSuccess) {
		llog_nss_error(RC_LOG, logger, "Failed to start configure TLS options");
		return false;
	}

	SSL_ResetHandshake(pr, PR_TRUE);
	return true;
}

static stf_status send_eap_termination_response(struct ike_sa *ike, struct msg_digest *md, uint8_t eap_code)
{
	llog_sa(RC_LOG, ike, "responding with EAP termination code %d", eap_code);

	struct eap_state *eap = ike->sa.st_eap;

	struct v2_message response;
	if (!open_v2_message("EAP termination response",
			     ike, ike->sa.logger, md/*response*/,
			     ISAKMP_v2_IKE_AUTH,
			     reply_buffer, sizeof(reply_buffer),
			     &response, ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	struct ikev2_generic ie = {
		.isag_critical = build_ikev2_critical(false, ike->sa.logger),
	};
	struct eap_termination eap_msg = {
		.eap_code = eap_code,
		.eap_identifier = eap->eap_id++,
	};

	struct pbs_out eap_payload;
	if (!pbs_out_struct(response.pbs, ie, &ikev2_eap_desc, &eap_payload)) {
		return STF_INTERNAL_ERROR;
	}

	if (!pbs_out_struct(&eap_payload, eap_msg, &eap_termination_desc, NULL)) {
		return STF_INTERNAL_ERROR;
	}

	ldbg(ike->sa.logger, "closing EAP termination payload");
	close_pbs_out(&eap_payload);

	ldbg(ike->sa.logger, "closing/recording EAP termination response");
	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;
}

static stf_status send_eap_fragment_response(struct ike_sa *ike, struct msg_digest *md,
					     uint8_t eap_code, uint32_t max_frag)
{
	struct eap_state *eap = ike->sa.st_eap;

	/* make sure HDR is at start of a clean buffer */

	struct v2_message response;
	if (!open_v2_message("EAP fragment response",
			     ike, ike->sa.logger, md/*response*/,
			     ISAKMP_v2_IKE_AUTH, reply_buffer, sizeof(reply_buffer),
			     &response, ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	struct ikev2_generic ie = {
		.isag_critical = build_ikev2_critical(false, ike->sa.logger),
	};
	struct eap_tls eaptls = {
		.eap_code = eap_code,
		.eap_identifier = eap->eap_id++,
		.eap_type = EAP_TYPE_TLS,
	};
	if (max_frag) {
		max_frag -= sizeof(struct eap_tls);
		if (eap->eaptls_pos == 0) {
			eaptls.eaptls_flags |= EAPTLS_FLAGS_LENGTH;
			max_frag -= 4;
		}
		max_frag = PMIN(max_frag, eap->eaptls_chunk.len - eap->eaptls_pos);

		if (eap->eaptls_pos + max_frag != eap->eaptls_chunk.len)
			eaptls.eaptls_flags |= EAPTLS_FLAGS_MORE;
	}

	struct pbs_out eap_payload;
	if (!pbs_out_struct(response.pbs, ie, &ikev2_eap_desc, &eap_payload)) {
		return STF_INTERNAL_ERROR;
	}

	struct pbs_out eap_data;
	if (!pbs_out_struct(&eap_payload, eaptls, &eap_tls_desc, &eap_data)) {
		return STF_INTERNAL_ERROR;
	}

	if (eaptls.eaptls_flags & EAPTLS_FLAGS_LENGTH) {
		uint32_t msglen = htonl(eap->eaptls_chunk.len);
		if (!pbs_out_thing(&eap_data, msglen, "TLS Message length")) {
			/* already logged */
			goto err;
		}
	}


	llog_sa(RC_LOG, ike, "responding with %d bytes of %zd EAP data",
		max_frag, eap->eaptls_chunk.len);

	if (max_frag) {
		if (!pbs_out_raw(&eap_data, eap->eaptls_chunk.ptr + eap->eaptls_pos, max_frag, "EAP-TLS data")) {
			/* already logged */
			goto err;
		}
		eap->eaptls_pos += max_frag;

		if (!(eaptls.eaptls_flags & EAPTLS_FLAGS_MORE)) {
			free_chunk_content(&eap->eaptls_chunk);
			eap->eaptls_pos = 0;
		}
	}

	ldbg(ike->sa.logger, "closing EAP data / payload");
	close_pbs_out(&eap_data);
 	close_pbs_out(&eap_payload);

	ldbg(ike->sa.logger, "closing/recording EAP response");
	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;

err:
	return STF_FATAL;
}

stf_status process_v2_IKE_AUTH_request_EAP_start(struct ike_sa *ike,
						 struct child_sa *unused_child UNUSED,
						 struct msg_digest *md)
{
	/* for testing only */
	if (impair.send_no_ikev2_auth) {
		llog(RC_LOG, ike->sa.logger,
		     "IMPAIR: SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

	/*
	 * This log line establishes that the packet's been decrypted
	 * and now it is being processed for real.
	 *
	 * XXX: move this into ikev2.c?
	 */
	llog_msg_digest(RC_LOG, ike->sa.logger, "processing decrypted", md);

	/*
	 * XXX: hack so that incoming certs are ignored; should update
	 * CERT code?
	 */
	ike->sa.st_remote_certs.processed = true;
	ike->sa.st_remote_certs.harmless = true;

	const struct connection *c = ike->sa.st_connection;
	if (c->remote->host.config->auth != AUTH_EAPONLY) {
		llog_sa(RC_LOG, ike,
			  "Peer attempted EAP authentication, but IKE_AUTH is required");
		goto auth_fail;
	}
	if (c->local->host.config->eap != IKE_EAP_TLS ||
	    c->remote->host.config->eap != IKE_EAP_TLS) {
		llog_sa(RC_LOG, ike,
			  "Peer attempted EAP authentication, but EAP is not allowed");
		goto auth_fail;
	}

	stf_status status = process_v2_IKE_AUTH_request_standard_payloads(ike, md);
	if (status != STF_OK)
		return status;

	/*
	 * Construct the IDr payload and store it in state so that it
	 * can be emitted later.  Then use that to construct the
	 * "MACedIDFor[R]".
	 *
	 * Code assumes that struct ikev2_id's "IDType|RESERVED" is
	 * laid out the same as the packet.
	 */
	v2_IKE_AUTH_responder_id_payload(ike);

	return submit_v2AUTH_generate_responder_signature(ike, md, process_v2_IKE_AUTH_request_EAP_start_signature_continue);

auth_fail:
	pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
	record_v2N_response(ike->sa.logger, ike, md,
			    v2N_AUTHENTICATION_FAILED, empty_shunk/*no-data*/,
			    ENCRYPTED_PAYLOAD);
	return STF_FATAL;
}

static stf_status process_v2_IKE_AUTH_request_EAP_start_signature_continue(struct ike_sa *ike,
									   struct msg_digest *md,
									   const struct hash_signature *auth_sig)
{
	struct connection *c = ike->sa.st_connection;

	/* HDR out */

	struct v2_message response;
	if (!open_v2_message("start EAP response",
			     ike, ike->sa.logger, md/*response*/,
			     ISAKMP_v2_IKE_AUTH,
			     reply_buffer, sizeof(reply_buffer),
			     &response, ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	/* decide to send CERT payload before we generate IDr */
	bool send_cert = ikev2_send_cert_decision(ike);

	/* send any NOTIFY payloads */
	if (ike->sa.st_v2_mobike.enabled) {
		if (!emit_v2N(v2N_MOBIKE_SUPPORTED, response.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	if (ike->sa.st_ppk_ike_auth_used) {
		if (!emit_v2N(v2N_PPK_IDENTITY, response.pbs))
			return STF_INTERNAL_ERROR;
	}

	/* send out the IDr payload */
	{
		struct pbs_out r_id_pbs;
		if (!pbs_out_struct(response.pbs, ike->sa.st_v2_id_payload.header,
				    &ikev2_id_r_desc, &r_id_pbs) ||
		    !pbs_out_hunk(&r_id_pbs, ike->sa.st_v2_id_payload.data, "my identity"))
			return STF_INTERNAL_ERROR;
		close_pbs_out(&r_id_pbs);
		ldbg(ike->sa.logger, "added IDr payload to packet");
	}

	/*
	 * send CERT payload RFC 4306 3.6, 1.2:([CERT,] )
	 * upon which our received I2 CERTREQ is ignored,
	 * but ultimately should go into the CERT decision
	 */
	if (send_cert) {
		stf_status certstat = emit_v2CERT(ike->sa.st_connection, response.pbs);
		if (certstat != STF_OK)
			return certstat;
	}

	/*
	 * Now send AUTH payload.
	 *
	 * With EAP, the first IKE_AUTH request never contains an AUTH
	 * payload.  However, the first IKE_AUTH can omit AUTH (when
	 * it does it is called EAP-only).  If the AUTH is included in
	 * the first IKE_AUTH response it is computed similar to a
	 * non-EAP exchange.
	 *
	 * Regardless, the final IKE_AUTH exchange after the EAP
	 * exchanges, always includes AUTH and always has the EAP
	 * magic fed into it.
	 */
	if (c->local->host.config->auth == AUTH_EAPONLY) {
		ldbg_sa(ike, "EAP: skipping AUTH payload as our proof-of-identity is eap-only");
	} else {
		/*
		 * Emit the optional AUTH payload as part of the first
		 * IKE_AUTH request's response - at this point there
		 * is no accumulated EAP hash to feed into the
		 * calculation.
		 *
		 * AUTH_SIG was generated by
		 * generate_v2_responder_auth() in
		 * process_v2_IKE_AUTH_request_EAP_start(); and that
		 * knows how to generate a PSK signature.
		 */
		if (!emit_local_v2AUTH(ike, auth_sig, response.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	if (!start_eap(ike, response.pbs)) {
		goto auth_fail;
	}

	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	/* remember the original message with child sa etc. parameters */
	ike->sa.st_eap_sa_md = md_addref(md);

	return STF_OK;

auth_fail:
	pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
	record_v2N_response(ike->sa.logger, ike, md,
			    v2N_AUTHENTICATION_FAILED, empty_shunk/*no-data*/,
			    ENCRYPTED_PAYLOAD);
	return STF_FATAL;
}

stf_status process_v2_IKE_AUTH_request_EAP_continue(struct ike_sa *ike,
						    struct child_sa *unused_child UNUSED,
						    struct msg_digest *md)
{
	struct eap_state *eap = ike->sa.st_eap;
	struct logger *logger = ike->sa.logger;
	diag_t d;

	pexpect(eap != NULL);

	struct pbs_in pbs = md->chain[ISAKMP_NEXT_v2EAP]->pbs;
	struct pbs_in data;
	struct eap_tls eaptls;

	d = pbs_in_struct(&pbs, &eap_tls_desc, &eaptls, sizeof(eaptls), &data);
	if (d != NULL) goto err_diag;

	if (eaptls.eap_code != EAP_CODE_RESPONSE) {
		llog_sa(RC_LOG, ike, "EAP Code %x unexpected", eaptls.eap_code);
		return STF_FATAL;
	}

	if (eaptls.eap_type != EAP_TYPE_TLS) {
		llog_sa(RC_LOG, ike, "EAP Type %x unexpected", eaptls.eap_type);
		return STF_FATAL;
	}

	if (eaptls.eap_length == sizeof(struct eap_tls)) {
		if (eap->eap_established && eap->eaptls_chunk.len == 0) {
			llog_sa(RC_LOG, ike, "EAP Final ACK");
			return send_eap_termination_response(ike, md, EAP_CODE_SUCCESS);
		}
		llog_sa(RC_LOG, ike, "EAP Fragment acknowledgement");
		return send_eap_fragment_response(ike, md, EAP_CODE_REQUEST, 1024);
	}

	if (eaptls.eaptls_flags & EAPTLS_FLAGS_LENGTH) {
		uint32_t msglen = 0xdead;
		d = pbs_in_thing(&data, msglen, "TLS Message length");
		if (d != NULL) goto err_diag;

		msglen = ntohl(msglen);
		llog_sa(RC_LOG, ike, "EAP TLS Msglen %u", msglen);
	}

	eap->eaptls_inbuf = pbs_in_left(&data);
	eap->eaptls_outbuf = open_pbs_out("reply EAP message",
		reply_buffer, sizeof(reply_buffer), ike->sa.logger);

	llog_sa(RC_LOG, ike, "EAP with %zd bytes, flags %x",
		eap->eaptls_inbuf.len, eaptls.eaptls_flags);

	if (SSL_ForceHandshake(eap->eaptls_desc) != SECSuccess) {
		PRErrorCode err = PR_GetError();
		if (err != PR_WOULD_BLOCK_ERROR) {
			llog_nss_error(RC_LOG, logger, "Handshake failed");
			/* likely we wrote failure alert, so send that out */
		}
	}

	close_pbs_out(&eap->eaptls_outbuf);
	replace_chunk(&eap->eaptls_chunk, pbs_out_all(&eap->eaptls_outbuf), "EAP response");
	eap->eaptls_pos = 0;

	if (eaptls.eaptls_flags & EAPTLS_FLAGS_MORE) {
		llog_sa(RC_LOG, ike, "EAP TLS Fragmentation sending ACK");
		return send_eap_fragment_response(ike, md, EAP_CODE_REQUEST, 0);
	}

	return send_eap_fragment_response(ike, md, EAP_CODE_REQUEST, 1024);

err_diag:
	llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
	pfree_diag(&d);
	return STF_FATAL;
}

stf_status process_v2_IKE_AUTH_request_EAP_final(struct ike_sa *ike,
					         struct child_sa *unused_child UNUSED,
					         struct msg_digest *md)
{
	static const char key_pad_str[] = "client EAP encryption"; /* EAP-TLS RFC 5216 */
	struct eap_state *eap = ike->sa.st_eap;
	struct msg_digest *sa_md = ike->sa.st_eap_sa_md;
	struct logger *logger = ike->sa.logger;

	pexpect(eap != NULL);
	pexpect(sa_md != NULL);

	if (!eap->eap_established)
		return STF_FATAL;

	ldbg(ike->sa.logger, "responder verifying AUTH payload");

	/*
	 * IKEv2: 2.16.  Extensible Authentication Protocol Methods
	 *
	 * ... The shared key from EAP is the field from the EAP
	 * specification named MSK.
	 *
	 * In EAP-TLS, MSK is defined as:
	 *
	 * MSK          = Key_Material(0,63)
	 */
	struct hash_signature msk = { .len = 64/* from RFC? */, };
	passert(msk.len <= sizeof(msk.ptr/*array*/));
	if (SSL_ExportKeyingMaterial(eap->eaptls_desc,
				     key_pad_str, sizeof(key_pad_str) - 1,
				     PR_FALSE, NULL, 0,
				     msk.ptr, msk.len) != SECSuccess) {
		free_eap_state(&ike->sa.st_eap);
		llog_nss_error(RC_LOG, logger, "Keying material export failed");
		return STF_FATAL;
	}

	/* calculate hash of IDi for AUTH below */
	struct crypt_mac idhash_in = v2_remote_id_hash(ike, "IDi verify hash", md);

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log_hunk(logger, "EAP: msk:", msk);
		LDBG_log_hunk(logger, "EAP: idhash_in:", idhash_in);
	}

	diag_t d = verify_v2AUTH_and_log_using_psk(AUTH_EAPONLY, ike, &idhash_in,
						   &md->chain[ISAKMP_NEXT_v2AUTH]->pbs,
						   &msk);
	free_eap_state(&ike->sa.st_eap);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		ldbg(ike->sa.logger, "EAP AUTH failed");
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, empty_shunk/*no data*/,
				    ENCRYPTED_PAYLOAD);
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		return STF_FATAL;
	}

	/* construct final response */

	struct connection *c = ike->sa.st_connection;
	bool send_redirect = false;
	if (!v2_ike_sa_auth_responder_establish(ike, &send_redirect)) {
		return STF_FATAL;
	}

	/* make sure HDR is at start of a clean buffer */

	struct v2_message response;
	if (!open_v2_message("EAP final response",
			     ike, ike->sa.logger, md/*response*/,
			     ISAKMP_v2_IKE_AUTH,
			     reply_buffer, sizeof(reply_buffer),
			     &response, ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * A redirect does not tear down the IKE SA; instead that is
	 * left to the initiator:
	 *
	 * https://datatracker.ietf.org/doc/html/rfc5685#section-6
	 * 6.  Redirect during IKE_AUTH Exchange
	 *
	 * When the client receives the IKE_AUTH response with the
	 * REDIRECT payload, it SHOULD delete the IKEv2 security
	 * association with the gateway by sending an INFORMATIONAL
	 * message with a DELETE payload.
	 */
	if (send_redirect) {
		if (!emit_v2N_REDIRECT(c->config->redirect.to, response.pbs)) {
			return STF_INTERNAL_ERROR;
		}
		ike->sa.st_sent_redirect = true;	/* mark that we have sent REDIRECT in IKE_AUTH */
	}

	/*
	 * EAP only does PSK!
	 */

	enum keyword_auth local_authby = ike->sa.st_eap_sa_md ? AUTH_PSK : local_v2_auth(ike);
	enum ikev2_auth_method local_auth_method = local_v2AUTH_method(ike, local_authby);
	if (!PEXPECT(ike->sa.logger, (local_auth_method == IKEv2_AUTH_SHARED_KEY_MAC ||
				      local_auth_method == IKEv2_AUTH_NULL))) {
		return STF_INTERNAL_ERROR;
	}

	struct crypt_mac signed_octets = empty_mac;
	d = ikev2_calculate_psk_sighash(LOCAL_PERSPECTIVE,
					/*accumulated EAP hash*/&msk,
					ike, local_authby,
					&ike->sa.st_v2_id_payload.mac,
					ike->sa.st_firstpacket_me,
					&signed_octets);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, empty_shunk/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log_hunk(logger, "PSK auth octets:", signed_octets);
	}

	struct hash_signature signed_signature = {
		.len = signed_octets.len,
	};
	PASSERT(ike->sa.logger, sizeof(signed_signature.ptr) >= sizeof(signed_octets.ptr));
	memcpy_hunk(signed_signature.ptr, signed_octets, signed_octets.len);

	if (!emit_local_v2AUTH(ike, &signed_signature, response.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (ike->sa.st_v2_ike_intermediate.enabled) {
		ldbg_sa(ike, "disabling IKE_INTERMEDIATE, but why?");
		ike->sa.st_v2_ike_intermediate.enabled = false;
	}

	/*
	 * Try to build a child.
	 *
	 * The result can be fatal, or just doesn't create the child.
	 */

	if (send_redirect) {
		ldbg(ike->sa.logger, "skipping child; redirect response");
	} else if (!process_any_v2_IKE_AUTH_request_child_payloads(ike, md, response.pbs)) {
		/* already logged; already recorded */
		return STF_FATAL;
	}

	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	md_delref(&ike->sa.st_eap_sa_md);
	return STF_OK;
}

void llog_success_process_v2_IKE_AUTH_EAP_request(struct ike_sa *ike,
						  const struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, v2_msg_role(md) == MESSAGE_REQUEST);
 	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
		jam_string(buf, ike->sa.st_state->story);
	}
}

/*
 * EAP responder transitions, there is no initiator code.
 */

static const struct v2_transition v2_IKE_AUTH_EAP_responder_transition[] = {

	{ .story      = "process initial IKE_AUTH(EAP) request",
	  .to = &state_v2_IKE_AUTH_EAP_R,
	  .exchange   = ISAKMP_v2_IKE_AUTH,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(IDi),
	  .encrypted_payloads.optional = v2P(CERTREQ) | v2P(IDr) | v2P(CP) | v2P(SA) | v2P(TSi) | v2P(TSr),
	  .processor  = process_v2_IKE_AUTH_request_EAP_start,
	  .llog_success = llog_success_process_v2_IKE_AUTH_EAP_request,
	  .timeout_event = EVENT_v2_DISCARD, },

	{ .story      = "process continuing IKE_AUTH(EAP) request",
	  .to = &state_v2_IKE_AUTH_EAP_R,
	  .exchange   = ISAKMP_v2_IKE_AUTH,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(EAP),
	  .processor  = process_v2_IKE_AUTH_request_EAP_continue,
	  .llog_success = llog_success_process_v2_IKE_AUTH_EAP_request,
	  .timeout_event = EVENT_v2_DISCARD, },

	{ .story      = "process final IKE_AUTH(EAP) request",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .flags = { .release_whack = true, },
	  .exchange   = ISAKMP_v2_IKE_AUTH,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(AUTH),
	  .processor  = process_v2_IKE_AUTH_request_EAP_final,
	  .llog_success = llog_success_process_v2_IKE_AUTH_EAP_request,
	  .timeout_event = EVENT_v2_REPLACE, },

};

static const struct v2_transitions v2_IKE_AUTH_EAP_responder_transitions = {
	ARRAY_REF(v2_IKE_AUTH_EAP_responder_transition),
};

V2_STATE(IKE_AUTH_EAP_R,
	 "sent IKE_AUTH(EAP) response, waiting for IKE_AUTH(EAP) request",
	 CAT_OPEN_IKE_SA, /*secured*/true,
	 &v2_IKE_AUTH_EAP_exchange);

const struct v2_exchange v2_IKE_AUTH_EAP_exchange = {
	.type = ISAKMP_v2_IKE_AUTH,
	.subplot = "EAP",
	.secured = true,
	.responder = &v2_IKE_AUTH_EAP_responder_transitions,
};
