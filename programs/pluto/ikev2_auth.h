/* IKEv2 authentication, for libreswan
 *
 * Copyright (C) 2019  Andrew Cagney
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

#ifndef IKEV2_SIGHASH_H
#define IKEV2_SIGHASH_H

#include <stdbool.h>

#include "chunk.h"

struct state;
struct connection;
struct ike_sa;
struct hash_signature;
struct msg_digest;
struct hash_desc;
struct logger;
struct secret_stuff;
enum perspective;
struct pubkey_signer;
struct pbs_out;
struct pbs_in;

struct crypt_mac v2_sha1_hash(const struct crypt_mac *hash);
struct crypt_mac v2_calculate_sighash(const struct ike_sa *ike,
				      const struct crypt_mac *idhash,
				      const struct hash_desc *hasher,
				      enum perspective from_the_perspective_of);

const struct hash_desc *v2_auth_negotiated_signature_hash(struct ike_sa *ike);

shunk_t authby_asn1_hash_blob(const struct hash_desc *hash_algo,
			      enum keyword_auth authby);

/*
 * The local end's proof-of-identity sent to the remote peer.
 */
enum keyword_auth local_v2_auth(struct ike_sa *ike);
enum ikev2_auth_method local_v2AUTH_method(struct ike_sa *ike, enum keyword_auth auth);
bool emit_local_v2AUTH(struct ike_sa *ike,
		       const struct hash_signature *auth_sig,
		       struct pbs_out *outpbs);

typedef stf_status (v2_auth_signature_cb)(struct ike_sa *ike,
					  struct msg_digest *md,
					  const struct hash_signature *sighash_sig);

bool submit_v2_auth_signature(struct ike_sa *ike,
			      struct msg_digest *md,
			      const struct crypt_mac *sighash,
			      const struct hash_desc *hash_algo,
			      const struct pubkey_signer *signer,
			      v2_auth_signature_cb *cb,
			      where_t where);

diag_t verify_v2AUTH_and_log(enum ikev2_auth_method recv_auth,
			     struct ike_sa *ike,
			     const struct crypt_mac *idhash_in,
			     struct pbs_in *signature_pbs,
			     const enum keyword_auth that_authby);

stf_status submit_v2AUTH_generate_responder_signature(struct ike_sa *ike, struct msg_digest *md,
						      v2_auth_signature_cb auth_cb);

stf_status submit_v2AUTH_generate_initiator_signature(struct ike_sa *ike, struct msg_digest *md,
						      v2_auth_signature_cb *cb);

void v2_IKE_AUTH_responder_id_payload(struct ike_sa *ike);
void v2_IKE_AUTH_initiator_id_payload(struct ike_sa *ike);

struct crypt_mac v2_remote_id_hash(const struct ike_sa *ike, const char *why,
				   const struct msg_digest *md);

#endif
