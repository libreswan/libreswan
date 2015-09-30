
/* keys.c SEAM */
void load_preshared_secrets()
{
}
chunk_t mysecret = { .ptr = "abcd", .len = 4 };
const chunk_t *get_preshared_secret(const struct connection *c)
{
	return &mysecret;
}

struct RSA_private_key f1;
const struct RSA_private_key *get_RSA_private_key(const struct connection *c)
{
	return &f1;
}
void list_public_keys(bool utc)
{
}
void list_psks(void)
{
}

void gw_addref(struct gw_info *gw)
{
}
void gw_delref(struct gw_info **gwp)
{
}

bool in_pending_use(const struct connection *c)
{
	return FALSE;
}

err_t add_public_key(const struct id *id,
		     enum dns_auth_level dns_auth_level,
		     enum pubkey_alg alg,
		     const chunk_t *key,
		     struct pubkey_list **head)
{
	return NULL;                                             /* no error */
}

void transfer_to_public_keys(struct gw_info *gateways_from_dns,
			     struct pubkey_list **keys)
{
}

struct pubkey_list *pluto_pubkeys = NULL;       /* keys from ipsec.conf */
