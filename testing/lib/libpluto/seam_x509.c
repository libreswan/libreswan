void release_cert(cert_t cert)
{
}
void add_pgp_public_key(pgpcert_t *cert, time_t until,
			enum dns_auth_level dns_auth_level)
{
}
pgpcert_t *pluto_add_pgpcert(pgpcert_t *cert)
{
	return NULL;
}
void add_x509_public_key(struct id *keyid, x509cert_t *cert, time_t until,
			 enum dns_auth_level dns_auth_level)
{
}
x509cert_t *add_x509cert(x509cert_t *cert)
{
	return NULL;
}

/* fetch.c SEAM */
void list_crl_fetch_requests(bool utc)
{
}

/* ac.c SEAM */
void decode_groups(char *groups, ietfAttrList_t **listp)
{
}
void load_acerts(void)
{
}
void list_acerts(bool utc)
{
}
void list_groups(bool utc)
{
}
void free_ietfAttrList(ietfAttrList_t *list)
{
}

/* x509.c SEAM */
void load_crls(void)
{
}
void list_certs(bool utc)
{
}
void list_authcerts(const char *caption, u_char auth_flags, bool utc)
{
}
void list_crls(bool utc, bool strict)
{
}

void decode_cert(struct msg_digest *md)
{
}

void decode_cr(struct msg_digest *md, generalName_t **requested_ca)
{
}

void ikev2_decode_cert(struct msg_digest *md)
{
}

/* Decode the IKEv2 CR payload of Phase 1. */
void ikev2_decode_cr(struct msg_digest *md, generalName_t **requested_ca)
{
}

bool ikev2_build_and_ship_CR(enum ike_cert_type type, chunk_t ca, pb_stream *outs,
			     enum next_payload_types_ikev2 np)
{
	return FALSE;
}

generalName_t *collect_rw_ca_candidates(struct msg_digest *md)
{
	return NULL;
}

bool build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs, u_int8_t np)
{
	return FALSE;
}
