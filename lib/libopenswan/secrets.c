/*
 * mechanisms for preshared keys (public, private, and preshared secrets)
 * this is the library for reading (and later, writing!) the ipsec.secrets
 * files.
 *
 * Copyright (C) 1998-2004  D. Hugh Redelmeier.
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 *
 * RCSID $Id: keys.c,v 1.104 2005/08/19 04:03:02 mcr Exp $
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */

#include <glob.h>
#ifndef GLOB_ABORTED
# define GLOB_ABORTED    GLOB_ABEND	/* fix for old versions */
#endif

#include <gmp.h>
#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "oswlog.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswtime.h"
#include "id.h"
#include "x509.h"
#include "secrets.h"
#include "certs.h"
#include "smartcard.h"
#include "lex.h"
#include "mpzfuncs.h"

/* Maximum length of filename and passphrase buffer */
#define BUF_LEN		256

/* this does not belong here, but leave it here for now */
const struct id empty_id;	/* ID_NONE */

struct fld {
    const char *name;
    size_t offset;
};

static const struct fld RSA_private_field[] =
{
    { "Modulus", offsetof(struct RSA_private_key, pub.n) },
    { "PublicExponent", offsetof(struct RSA_private_key, pub.e) },

    { "PrivateExponent", offsetof(struct RSA_private_key, d) },
    { "Prime1", offsetof(struct RSA_private_key, p) },
    { "Prime2", offsetof(struct RSA_private_key, q) },
    { "Exponent1", offsetof(struct RSA_private_key, dP) },
    { "Exponent2", offsetof(struct RSA_private_key, dQ) },
    { "Coefficient", offsetof(struct RSA_private_key, qInv) },
};

static err_t osw_process_psk_secret(const struct secret *secrets
				    , chunk_t *psk);
static err_t osw_process_rsa_secret(const struct secret *secrets
				    , struct RSA_private_key *rsak);
static err_t osw_process_rsa_keyfile(struct secret **psecrets
				     , int verbose
				     , struct RSA_private_key *rsak
				     , prompt_pass_t *pass);

#ifdef DEBUG
static void
RSA_show_key_fields(struct RSA_private_key *k, int fieldcnt)
{
    const struct fld *p;

    DBG_log(" keyid: *%s", k->pub.keyid);

    for (p = RSA_private_field; p < &RSA_private_field[fieldcnt]; p++)
    {
	MP_INT *n = (MP_INT *) ((char *)k + p->offset);
	size_t sz = mpz_sizeinbase(n, 16);
	char buf[RSA_MAX_OCTETS * 2 + 2];	/* ought to be big enough */

	passert(sz <= sizeof(buf));
	mpz_get_str(buf, 16, n);

	DBG_log(" %s: %s", p->name, buf);
    }
}

/* debugging info that compromises security! */
static void
RSA_show_private_key(struct RSA_private_key *k)
{
    RSA_show_key_fields(k, elemsof(RSA_private_field));
}

static void
RSA_show_public_key(struct RSA_public_key *k)
{
    /* Kludge: pretend that it is a private key, but only display the
     * first two fields (which are the public key).
     */
    passert(offsetof(struct RSA_private_key, pub) == 0);
    RSA_show_key_fields((struct RSA_private_key *)k, 2);
}
#endif

static const char *
RSA_private_key_sanity(struct RSA_private_key *k)
{
    /* note that the *last* error found is reported */
    err_t ugh = NULL;
    mpz_t t, u, q1;

#ifdef DEBUG	/* debugging info that compromises security */
    DBG(DBG_PRIVATE, RSA_show_private_key(k));
#endif

    /* PKCS#1 1.5 section 6 requires modulus to have at least 12 octets.
     * We actually require more (for security).
     */
    if (k->pub.k < RSA_MIN_OCTETS)
	return RSA_MIN_OCTETS_UGH;

    /* we picked a max modulus size to simplify buffer allocation */
    if (k->pub.k > RSA_MAX_OCTETS)
	return RSA_MAX_OCTETS_UGH;

    mpz_init(t);
    mpz_init(u);
    mpz_init(q1);

    /* check that n == p * q */
    mpz_mul(u, &k->p, &k->q);
    if (mpz_cmp(u, &k->pub.n) != 0)
	ugh = "n != p * q";

    /* check that e divides neither p-1 nor q-1 */
    mpz_sub_ui(t, &k->p, 1);
    mpz_mod(t, t, &k->pub.e);
    if (mpz_cmp_ui(t, 0) == 0)
	ugh = "e divides p-1";

    mpz_sub_ui(t, &k->q, 1);
    mpz_mod(t, t, &k->pub.e);
    if (mpz_cmp_ui(t, 0) == 0)
	ugh = "e divides q-1";

    /* check that d is e^-1 (mod lcm(p-1, q-1)) */
    /* see PKCS#1v2, aka RFC 2437, for the "lcm" */
    mpz_sub_ui(q1, &k->q, 1);
    mpz_sub_ui(u, &k->p, 1);
    mpz_gcd(t, u, q1);		/* t := gcd(p-1, q-1) */
    mpz_mul(u, u, q1);		/* u := (p-1) * (q-1) */
    mpz_divexact(u, u, t);	/* u := lcm(p-1, q-1) */

    mpz_mul(t, &k->d, &k->pub.e);
    mpz_mod(t, t, u);
    if (mpz_cmp_ui(t, 1) != 0)
	ugh = "(d * e) mod (lcm(p-1, q-1)) != 1";

    /* check that dP is d mod (p-1) */
    mpz_sub_ui(u, &k->p, 1);
    mpz_mod(t, &k->d, u);
    if (mpz_cmp(t, &k->dP) != 0)
	ugh = "dP is not congruent to d mod (p-1)";

    /* check that dQ is d mod (q-1) */
    mpz_sub_ui(u, &k->q, 1);
    mpz_mod(t, &k->d, u);
    if (mpz_cmp(t, &k->dQ) != 0)
	ugh = "dQ is not congruent to d mod (q-1)";

    /* check that qInv is (q^-1) mod p */
    mpz_mul(t, &k->qInv, &k->q);
    mpz_mod(t, t, &k->p);
    if (mpz_cmp_ui(t, 1) != 0)
	ugh = "qInv is not conguent ot (q^-1) mod p";

    mpz_clear(t);
    mpz_clear(u);
    mpz_clear(q1);
    return ugh;
}

struct secret {
    struct secret  *next;
    struct id_list *ids;
    int             secretlineno;
    struct private_key_stuff pks;
};

struct private_key_stuff *osw_get_pks(struct secret *s)
{
    return &s->pks;
}

int osw_get_secretlineno(const struct secret *s)
{
    return s->secretlineno;
}

struct id_list *osw_get_idlist(const struct secret *s)
{
    return s->ids;
}

struct secret *osw_get_defaultsecret(struct secret *secrets)
{
    struct secret *s,*s2;

    /* get last element of array */
    s=s2=secrets;
    while(s2 != NULL) {
	s=s2;
	s2=s2->next;
    }
    return s;
}


/*
 * forms the keyid from the public exponent e and modulus n
 */
void
form_keyid(chunk_t e, chunk_t n, char* keyid, unsigned *keysize)
{
    /* eliminate leading zero byte in modulus from ASN.1 coding */
    if (*n.ptr == 0x00)
    {
	n.ptr++;  n.len--;
    }

    /* form the FreeS/WAN keyid */
    keyid[0] = '\0';	/* in case of splitkeytoid failure */
    splitkeytoid(e.ptr, e.len, n.ptr, n.len, keyid, KEYID_BUF);

    /* return the RSA modulus size in octets */
    *keysize = n.len;
}


struct pubkey*
allocate_RSA_public_key(const cert_t cert)
{
    struct pubkey *pk = alloc_thing(struct pubkey, "pubkey");
    chunk_t e, n;

    switch (cert.type)
    {
    case CERT_PGP:
	e = cert.u.pgp->publicExponent;
	n = cert.u.pgp->modulus;
	break;
    case CERT_X509_SIGNATURE:
	e = cert.u.x509->publicExponent;
	n = cert.u.x509->modulus;
	break;
    default:
	openswan_log("RSA public key allocation error");
	return NULL;
    }

    n_to_mpz(&pk->u.rsa.e, e.ptr, e.len);
    n_to_mpz(&pk->u.rsa.n, n.ptr, n.len);

    form_keyid(e, n, pk->u.rsa.keyid, &pk->u.rsa.k);

#ifdef DEBUG
    DBG(DBG_PRIVATE, RSA_show_public_key(&pk->u.rsa));
#endif

    pk->alg = PUBKEY_ALG_RSA;
    pk->id  = empty_id;
    pk->issuer = empty_chunk;

    return pk;
}

void free_RSA_public_content(struct RSA_public_key *rsa)
{
    mpz_clear(&rsa->n);
    mpz_clear(&rsa->e);
}

/*
 * free a public key struct
 */
void
free_public_key(struct pubkey *pk)
{
    free_id_content(&pk->id);
    freeanychunk(pk->issuer);

    /* algorithm-specific freeing */
    switch (pk->alg)
    {
    case PUBKEY_ALG_RSA:
	free_RSA_public_content(&pk->u.rsa);
	break;
    default:
	bad_case(pk->alg);
    }
    pfree(pk);
}

struct secret *osw_foreach_secret(struct secret *secrets,
				  secret_eval func, void *uservoid)
{
    struct secret *s;

    for(s=secrets; s!=NULL; s=s->next) {
	struct private_key_stuff *pks = &s->pks;
	int result = (*func)(s, pks, uservoid);

	if(result == 0)  return s;
	if(result == -1) return NULL;
    }
    return NULL;
}

struct secret_byid {
    int            kind;
    struct pubkey *my_public_key;
};
    
int osw_check_secret_byid(struct secret *secret,
			  struct private_key_stuff *pks,
			  void *uservoid)
{
    struct secret_byid *sb=(struct secret_byid *)uservoid;

    DBG(DBG_CONTROL,
	DBG_log("searching for certificate %s:%s vs %s:%s"
		, enum_name(&ppk_names, pks->kind)
		, (pks->kind==PPK_RSA?pks->u.RSA_private_key.pub.keyid : "N/A")
		, enum_name(&ppk_names, sb->kind)
		, sb->my_public_key->u.rsa.keyid)
	);
    if (pks->kind == sb->kind &&
	same_RSA_public_key(&pks->u.RSA_private_key.pub
			    , &sb->my_public_key->u.rsa))
    {
	return 0;
    }

    return 1;
}
    
				  

struct secret *osw_find_secret_by_public_key(struct secret *secrets
					     , struct pubkey *my_public_key
					     , int kind)
{
    struct secret_byid sb;

    sb.kind = kind;
    sb.my_public_key = my_public_key;

    return osw_foreach_secret(secrets, osw_check_secret_byid, &sb);
}

struct secret *osw_find_secret_by_id(struct secret *secrets
				     , enum PrivateKeyKind kind
				     , const struct id *my_id
				     , const struct id *his_id
				     , bool asym)
{
    char idstr1[IDTOA_BUF], idme[IDTOA_BUF]
	, idhim[IDTOA_BUF], idhim2[IDTOA_BUF];
    enum {	/* bits */
	match_default = 01,
	match_him = 02,
	match_me = 04
    };
    unsigned int best_match = 0;
    struct secret *s, *best = NULL;

    idtoa(my_id,  idme,  IDTOA_BUF);

    if(his_id) {
	idtoa(his_id, idhim, IDTOA_BUF);
	strcpy(idhim2, idhim);
    }

    for (s = secrets; s != NULL; s = s->next)
    {
	if (s->pks.kind == kind)
	{
	    unsigned int match = 0;

	    if (s->ids == NULL)
	    {
		/* a default (signified by lack of ids):
		 * accept if no more specific match found
		 */
		match = match_default;
	    }
	    else
	    {
		/* check if both ends match ids */
		struct id_list *i;
		int idnum = 0;

		for (i = s->ids; i != NULL; i = i->next)
		{
		    idnum++;
		    idtoa(&i->id, idstr1, IDTOA_BUF);

		    if (same_id(&i->id, my_id))
			match |= match_me;

		    if (his_id!=NULL && same_id(&i->id, his_id))
			match |= match_him;

		    DBG(DBG_CONTROL,
			DBG_log("%d: compared key %s to %s / %s -> %d"
				, idnum, idstr1, idme, idhim, match));

		}

		/* If our end matched the only id in the list,
		 * default to matching any peer.
		 * A more specific match will trump this.
		 */
		if (match == match_me
		    && s->ids->next == NULL)
		    match |= match_default;
	    }

	    switch (match)
	    {
	    case match_me:
		/* if this is an asymmetric (eg. public key) system,
		 * allow this-side-only match to count, even if
		 * there are other ids in the list.
		 */
		if (!asym)
		    break;
		/* FALLTHROUGH */
	    case match_default:	/* default all */
	    case match_me | match_default:	/* default peer */
	    case match_me | match_him:	/* explicit */
		if (match == best_match)
		{
		    /* two good matches are equally good:
		     * do they agree?
		     */
		    bool same;

		    switch (kind)
		    {
		    case PPK_PSK:
			same = s->pks.u.preshared_secret.len == best->pks.u.preshared_secret.len
			    && memcmp(s->pks.u.preshared_secret.ptr
				      , best->pks.u.preshared_secret.ptr
				      , s->pks.u.preshared_secret.len) == 0;
			break;
		    case PPK_RSA:
			/* Dirty trick: since we have code to compare
			 * RSA public keys, but not private keys, we
			 * make the assumption that equal public keys
			 * mean equal private keys.  This ought to work.
			 */
			same = same_RSA_public_key(&s->pks.u.RSA_private_key.pub
						   , &best->pks.u.RSA_private_key.pub);
			break;
		    default:
			bad_case(kind);
		    }
		    if (!same)
		    {
			loglog(RC_LOG_SERIOUS, "multiple ipsec.secrets entries with distinct secrets match endpoints:"
			    " first secret used");
			best = s;	/* list is backwards: take latest in list */
		    }
		}
		else if (match > best_match)
		{
		    DBG(DBG_CONTROL,
			DBG_log("best_match %d>%d best=%p (line=%d)"
				, best_match, match
				, s, s->secretlineno));
		    
		    /* this is the best match so far */
		    best_match = match;
		    best = s;
		} else {
		    DBG(DBG_CONTROL,
			DBG_log("match(%d) was not best_match(%d)"
				, match, best_match));
		}
	    }
	}
    }
    DBG(DBG_CONTROL,
	DBG_log("concluding with best_match=%d best=%p (lineno=%d)"
		, best_match, best, best? best->secretlineno : -1));
		    
    return best;
}

/* check the existence of an RSA private key matching an RSA public
 * key contained in an X.509 or OpenPGP certificate
 */
bool osw_has_private_key(struct secret *secrets, cert_t cert)
{
    struct secret *s;
    bool has_key = FALSE;
    struct pubkey *pubkey;

    pubkey = allocate_RSA_public_key(cert);

    if(pubkey == NULL) return FALSE;

    for (s = secrets; s != NULL; s = s->next)
    {
	if (s->pks.kind == PPK_RSA &&
	    same_RSA_public_key(&s->pks.u.RSA_private_key.pub, &pubkey->u.rsa))
	{
	    has_key = TRUE;
	    break;
	}
    }
    free_public_key(pubkey);
    return has_key;
}

/* check the existence of an RSA private key matching an RSA public
 */
bool osw_has_private_rawkey(struct secret *secrets, struct pubkey *pk)
{
    struct secret *s;
    bool has_key = FALSE;

    if(pk == NULL) return FALSE;

    for (s = secrets; s != NULL; s = s->next)
    {
	if (s->pks.kind == PPK_RSA &&
	    same_RSA_public_key(&s->pks.u.RSA_private_key.pub, &pk->u.rsa))
	{
	    has_key = TRUE;
	    break;
	}
    }
    return has_key;
}

/* digest a secrets file
 *
 * The file is a sequence of records.  A record is a maximal sequence of
 * tokens such that the first, and only the first, is in the first column
 * of a line.
 *
 * Tokens are generally separated by whitespace and are key words, ids,
 * strings, or data suitable for ttodata(3).  As a nod to convention,
 * a trailing ":" on what would otherwise be a token is taken as a
 * separate token.  If preceded by whitespace, a "#" is taken as starting
 * a comment: it and the rest of the line are ignored.
 *
 * One kind of record is an include directive.  It starts with "include".
 * The filename is the only other token in the record.
 * If the filename does not start with /, it is taken to
 * be relative to the directory containing the current file.
 *
 * The other kind of record describes a key.  It starts with a
 * sequence of ids and ends with key information.  Each id
 * is an IP address, a Fully Qualified Domain Name (which will immediately
 * be resolved), or @FQDN which will be left as a name.
 *
 * The key part can be in several forms.
 *
 * The old form of the key is still supported: a simple
 * quoted strings (with no escapes) is taken as a preshred key.
 *
 * The new form starts the key part with a ":".
 *
 * For Preshared Key, use the "PSK" keyword, and follow it by a string
 * or a data token suitable for ttodata(3).
 *
 * For RSA Private Key, use the "RSA" keyword, followed by a
 * brace-enclosed list of key field keywords and data values.
 * The data values are large integers to be decoded by ttodata(3).
 * The fields are a subset of those used by BIND 8.2 and have the
 * same names.
 */

/*
 * process rsa key file protected with optional passphrase which can either be
 * read from ipsec.secrets or prompted for by using whack
 */
err_t osw_process_rsa_keyfile(struct secret **psecrets
			      , int verbose
			      , struct RSA_private_key *rsak
			      , prompt_pass_t *pass)
{
    char filename[BUF_LEN];
    err_t ugh = NULL;
    rsa_privkey_t *key = NULL;

    memset(filename,'\0', BUF_LEN);
    memset(pass->secret,'\0', sizeof(pass->secret));

    /* we expect the filename of a PKCS#1 private key file */

    if (*flp->tok == '"' || *flp->tok == '\'')  /* quoted filename */
	memcpy(filename, flp->tok+1, flp->cur - flp->tok - 2);
    else
    	memcpy(filename, flp->tok, flp->cur - flp->tok);

    if (shift())
    {
	/* we expect an appended passphrase or passphrase prompt*/
	if (tokeqword("%prompt"))
	{
	    if (pass->fd == NULL_FD)
		return "enter a passphrase using ipsec auto --rereadsecrets";
	}
	else if (*flp->tok == '"' || *flp->tok == '\'') /* quoted passphrase */
	    memcpy(pass->secret, flp->tok+1, flp->cur - flp->tok - 2);
	else
	    memcpy(pass->secret, flp->tok, flp->cur - flp->tok);

	pass->prompt=NULL;

	if (shift())
	    ugh = "RSA private key file -- unexpected token after passphrase";
    }

    key = load_rsa_private_key(filename, verbose, pass);

    if (key == NULL)
	ugh = "error loading RSA private key file";
    else
    {
	mpz_t u;
	u_int i;

	for (i = 0; ugh == NULL && i < elemsof(RSA_private_field); i++)
	{
	    MP_INT *n = (MP_INT *) ((char *)rsak + RSA_private_field[i].offset);

	    if (key->field[i].len > 0)
	    {
		/* PKCS#1 RSA private key format - complete */
		n_to_mpz(n, key->field[i].ptr, key->field[i].len);
	    }
	    else
	    {
		/* PGP RSA private key format - missing fields */
		switch (i)
		{
		case 5:		/* dP = d mod (p-1) */
		    mpz_init(u);
		    mpz_sub_ui(u, &rsak->p, 1);
		    mpz_mod(n, &rsak->d, u);
		    mpz_clear(u);
		    break;
		case 6:		/* dQ = d mod (q-1) */
		    mpz_init(u);
		    mpz_sub_ui(u, &rsak->q, 1);
		    mpz_mod(n, &rsak->d, u);
		    mpz_clear(u);
		    break;
		case 7:		/* qInv = (q^-1) mod p */
		    mpz_invert(n, &rsak->q, &rsak->p);
		    if (mpz_cmp_ui(n, 0) < 0)
			mpz_add(n, n, &rsak->p);
		    passert(mpz_cmp(n, &rsak->p) < 0);
		    break;
		default:
		    break;
		}
	    }
	}
	form_keyid(key->field[1], key->field[0], rsak->pub.keyid,
		   &rsak->pub.k);
	ugh = RSA_private_key_sanity(rsak);
	pfree(key->keyobject.ptr);
	pfree(key);
    }
    return ugh;
}

/* parse PSK from file */
static err_t osw_process_psk_secret(const struct secret *secrets, chunk_t *psk)
{
    err_t ugh = NULL;
    
    if (*flp->tok == '"' || *flp->tok == '\'')
    {
	clonetochunk(*psk, flp->tok+1, flp->cur - flp->tok  - 2, "PSK");
	(void) shift();
    }
    else
    {
	char buf[RSA_MAX_ENCODING_BYTES];	/* limit on size of binary representation of key */
	size_t sz;

	ugh = ttodatav(flp->tok, flp->cur - flp->tok, 0, buf, sizeof(buf), &sz
	    , diag_space, sizeof(diag_space), TTODATAV_SPACECOUNTS);
	if (ugh != NULL)
	{
	    /* ttodata didn't like PSK data */
	    ugh = builddiag("PSK data malformed (%s): %s", ugh, flp->tok);
	}
	else
	{
	    clonetochunk(*psk, buf, sz, "PSK");
	    (void) shift();
	}
    }

    DBG(DBG_CONTROL, DBG_log("Processing PSK at line %d: %s"
			     , flp->lino
			     , ugh == NULL ? "passed" : ugh));

    return ugh;
}

/* Parse fields of RSA private key.
 * A braced list of keyword and value pairs.
 * At the moment, each field is required, in order.
 * The fields come from BIND 8.2's representation
 */
static err_t
osw_process_rsa_secret(const struct secret *secrets
		       , struct RSA_private_key *rsak)
{
    unsigned char buf[RSA_MAX_ENCODING_BYTES];	/* limit on size of binary representation of key */
    const struct fld *p;

    /* save bytes of Modulus and PublicExponent for keyid calculation */
    unsigned char ebytes[sizeof(buf)];
    unsigned char *eb_next = ebytes;
    chunk_t pub_bytes[2];
    chunk_t *pb_next = &pub_bytes[0];

    for (p = RSA_private_field; p < &RSA_private_field[elemsof(RSA_private_field)]; p++)
    {
	size_t sz;
	err_t ugh;

	if (!shift())
	{
	    return "premature end of RSA key";
	}
	else if (!tokeqword(p->name))
	{
	    return builddiag("%s keyword not found where expected in RSA key"
		, p->name);
	}
	else if (!(shift()
	&& (!tokeq(":") || shift())))	/* ignore optional ":" */
	{
	    return "premature end of RSA key";
	}
	else if (NULL != (ugh = ttodatav(flp->tok, flp->cur - flp->tok
					 , 0, (char *)buf
					 , sizeof(buf), &sz
					 , diag_space, sizeof(diag_space)
					 , TTODATAV_SPACECOUNTS)))
	{
	    /* in RSA key, ttodata didn't like */
	    return builddiag("RSA data malformed (%s): %s", ugh, flp->tok);
	}
	else
	{
	    MP_INT *n = (MP_INT *) ((char *)rsak + p->offset);

	    n_to_mpz(n, buf, sz);
	    if (pb_next < &pub_bytes[elemsof(pub_bytes)])
	    {
		if (eb_next - ebytes + sz > sizeof(ebytes))
		    return "public key takes too many bytes";

		setchunk(*pb_next, eb_next, sz);
		memcpy(eb_next, buf, sz);
		eb_next += sz;
		pb_next++;
	    }
#if 0	/* debugging info that compromises security */
	    {
		size_t sz = mpz_sizeinbase(n, 16);
		char buf[RSA_MAX_OCTETS * 2 + 2];	/* ought to be big enough */

		passert(sz <= sizeof(buf));
		mpz_get_str(buf, 16, n);

		loglog(RC_LOG_SERIOUS, "%s: %s", p->name, buf);
	    }
#endif
	}
    }

    /* We require an (indented) '}' and the end of the record.
     * We break down the test so that the diagnostic will be
     * more helpful.  Some people don't seem to wish to indent
     * the brace!
     */
    if (!shift() || !tokeq("}"))
    {
	return "malformed end of RSA private key -- indented '}' required";
    }
    else if (shift())
    {
	return "malformed end of RSA private key -- unexpected token after '}'";
    }
    else
    {
	unsigned bits = mpz_sizeinbase(&rsak->pub.n, 2);

	rsak->pub.k = (bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
	rsak->pub.keyid[0] = '\0';	/* in case of splitkeytoid failure */
	splitkeytoid(pub_bytes[1].ptr, pub_bytes[1].len
	    , pub_bytes[0].ptr, pub_bytes[0].len
	    , rsak->pub.keyid, sizeof(rsak->pub.keyid));
	return RSA_private_key_sanity(rsak);
    }
}

/*
 * get the matching RSA private key belonging to a given X.509 certificate
 */
const struct RSA_private_key*
osw_get_x509_private_key(struct secret *secrets, x509cert_t *cert)
{
    struct secret *s;
    const struct RSA_private_key *pri = NULL;
    cert_t c;
    struct pubkey *pubkey;

    c.forced = FALSE;
    c.type   = CERT_X509_SIGNATURE;
    c.u.x509 = cert;

    pubkey = allocate_RSA_public_key(c);

    if(pubkey == NULL) return NULL;

    for (s = secrets; s != NULL; s = s->next)
    {
	if (s->pks.kind == PPK_RSA &&
	    same_RSA_public_key(&s->pks.u.RSA_private_key.pub, &pubkey->u.rsa))
	{
	    pri = &s->pks.u.RSA_private_key;
	    break;
	}
    }
    free_public_key(pubkey);
    return pri;
}

#ifdef SMARTCARD
/*
 * process pin read from ipsec.secrets or prompted for it using whack
 */
static err_t
process_pin(struct secret *s, int whackfd)
{
    smartcard_t *sc;
    const char *pin_status = "no";

    s->pks.kind = PPK_PIN;

    /* looking for the smartcard keyword */
    if (!shift() || strncmp(flp->tok, SCX_TOKEN, strlen(SCX_TOKEN)) != 0)
	 return "PIN keyword must be followed by %smartcard<reader>:<id>";

    sc = scx_add(scx_parse_reader_id(flp->tok + strlen(SCX_TOKEN)));
    s->pks.u.smartcard = sc;
    scx_share(sc);
    scx_free_pin(&sc->pin);
    sc->valid = FALSE;

    if (!shift())
	return "PIN statement must be terminated either by <pin code> or %prompt";

    if (flp->tokeqword("%prompt"))
    {
	shift();

	/* if whackfd exists, whack will be used to prompt for a pin */
	if (whackfd != NULL_FD)
	    pin_status = scx_get_pin(sc, whackfd) ? "valid" : "invalid";
    }
    else
    {
	/* we read the pin directly from ipsec.secrets */
	err_t ugh = osk_process_psk_secret(&sc->pin);
	if (ugh != NULL)
	    return ugh;

	/* verify the pin */
	pin_status = scx_verify_pin(sc) ? "valid" : "invalid";
    }
#ifdef SMARTCARD
    openswan_log("  %s PIN for reader: %d, id: %s", pin_status, sc->reader, sc->id);
#else
    openswan_log("  warning: SMARTCARD support is deactivated in pluto/Makefile!");
#endif
    return NULL;
}
#endif

static void
process_secret(struct secret **psecrets, int verbose,
	       struct secret *s, prompt_pass_t *pass)
{
    err_t ugh = NULL;
    struct secret *secrets = *psecrets;

    s->pks.kind = PPK_PSK;	/* default */
    if (*flp->tok == '"' || *flp->tok == '\'')
    {
	/* old PSK format: just a string */
	ugh = osw_process_psk_secret(secrets, &s->pks.u.preshared_secret);
    }
    else if (tokeqword("psk"))
    {
	/* preshared key: quoted string or ttodata format */
	ugh = !shift()? "unexpected end of record in PSK"
	    : osw_process_psk_secret(secrets, &s->pks.u.preshared_secret);
    }
    else if (tokeqword("rsa"))
    {
	/* RSA key: the fun begins.
	 * A braced list of keyword and value pairs.
	 */
	s->pks.kind = PPK_RSA;
	if (!shift())
	{
	    ugh = "bad RSA key syntax";
	}
	else if (tokeq("{"))
	{
	    ugh = osw_process_rsa_secret(secrets, &s->pks.u.RSA_private_key);
	}
	else
	{
	    ugh = osw_process_rsa_keyfile(psecrets, verbose,
					  &s->pks.u.RSA_private_key,pass);
	}
	if(!ugh && verbose) {
	    openswan_log("loaded private key for keyid: %s:%s",
			 enum_name(&ppk_names, s->pks.kind),
			 s->pks.u.RSA_private_key.pub.keyid);
	}
    }
    else if (tokeqword("pin"))
    {
#ifdef SMARTCARD
	ugh = process_pin(s, pass);
#else
	ugh = "Smartcard not supported";
#endif
    }
    else
    {
	ugh = builddiag("unrecognized key format: %s", flp->tok);
    }

    if (ugh != NULL)
    {
	loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s"
	    , flp->filename, flp->lino, ugh);
	pfree(s);
    }
    else if (flushline("expected record boundary in key"))
    {

	/* gauntlet has been run: install new secret */
	lock_certs_and_keys("process_secret");

	if(s->ids == NULL) {
	    /*
	     * make sure that empty lists have an implicit match everything
	     * set of IDs (ipv4 and ipv6)
	     */
	    struct id_list *idl, *idl2;
	    
	    idl = alloc_bytes(sizeof(*idl), "id list");
	    idl->next = NULL;
	    idl->id = empty_id;
	    idl->id.kind = ID_NONE;
	    (void)anyaddr(AF_INET, &idl->id.ip_addr);

	    idl2 = alloc_bytes(sizeof(*idl2), "id list");
	    idl2->next = idl;
	    idl2->id = empty_id;
	    idl2->id.kind = ID_NONE;
	    (void)anyaddr(AF_INET, &idl2->id.ip_addr);

	    s->ids=idl2;
	}
	s->next   = *psecrets;
	*psecrets = s;
	unlock_certs_and_keys("process_secrets");
    }
}

/* forward declaration */
static void osw_process_secrets_file(struct secret **psecrets
				     , int verbose
				     , const char *file_pat
				     , prompt_pass_t *pass);


static void
osw_process_secret_records(struct secret **psecrets, int verbose,
			   prompt_pass_t *pass)
{
    //const struct secret *secret = *psecrets;

    /* read records from ipsec.secrets and load them into our table */
    for (;;)
    {
	(void)flushline(NULL);	/* silently ditch leftovers, if any */
	if (flp->bdry == B_file)
	    break;

	flp->bdry = B_none;	/* eat the Record Boundary */
	(void)shift();	/* get real first token */

	if (tokeqword("include"))
	{
	    /* an include directive */
	    char fn[MAX_TOK_LEN];	/* space for filename (I hope) */
	    char *p = fn;
	    char *end_prefix = strrchr(flp->filename, '/');

	    if (!shift())
	    {
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end of include directive"
		    , flp->filename, flp->lino);
		continue;   /* abandon this record */
	    }

	    /* if path is relative and including file's pathname has
	     * a non-empty dirname, prefix this path with that dirname.
	     */
	    if (flp->tok[0] != '/' && end_prefix != NULL)
	    {
		size_t pl = end_prefix - flp->filename + 1;

		/* "clamp" length to prevent problems now;
		 * will be rediscovered and reported later.
		 */
		if (pl > sizeof(fn))
		    pl = sizeof(fn);
		memcpy(fn, flp->filename, pl);
		p += pl;
	    }
	    if (flp->cur - flp->tok >= &fn[sizeof(fn)] - p)
	    {
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: include pathname too long"
		    , flp->filename, flp->lino);
		continue;   /* abandon this record */
	    }
	    strcpy(p, flp->tok);
	    (void) shift();	/* move to Record Boundary, we hope */
	    if (flushline("ignoring malformed INCLUDE -- expected Record Boundary after filename"))
	    {
		osw_process_secrets_file(psecrets, verbose, fn, pass);
		flp->tok = NULL;	/* correct, but probably redundant */
	    }
	}
	else
	{
	    struct secret *s = NULL;

	    /* expecting a list of indices and then the key info */
	    s = alloc_thing(struct secret, "secret");
	    
	    s->ids = NULL;
	    s->pks.kind = PPK_PSK;	/* default */
	    setchunk(s->pks.u.preshared_secret, NULL, 0);
	    s->secretlineno=flp->lino;
	    s->next = NULL;

	    while(s != NULL)
	    {
		struct id id;
		err_t ugh;

		if (tokeq(":"))
		{
		    /* found key part */
		    shift();	/* discard explicit separator */
		    process_secret(psecrets, verbose, s, pass);
		    s = NULL;
		    break;
		}

		/* an id
		 * See RFC2407 IPsec Domain of Interpretation 4.6.2
		 */
		
		if (tokeq("%any"))
		{
		    id = empty_id;
		    id.kind = ID_IPV4_ADDR;
		    ugh = anyaddr(AF_INET, &id.ip_addr);
		}
		else if (tokeq("%any6"))
		{
		    id = empty_id;
		    id.kind = ID_IPV6_ADDR;
		    ugh = anyaddr(AF_INET6, &id.ip_addr);
		}
		else
		{
		    ugh = atoid(flp->tok, &id, FALSE);
		}
		
		if (ugh != NULL)
		{
		    loglog(RC_LOG_SERIOUS
			   , "ERROR \"%s\" line %d: index \"%s\" %s"
			   , flp->filename, flp->lino, flp->tok, ugh);
		}
		else
		{
		    struct id_list *i = alloc_thing(struct id_list
						    , "id_list");
		    char idb[IDTOA_BUF];
		    
		    i->id = id;
		    unshare_id_content(&i->id);
		    i->next = s->ids;
		    s->ids = i;
		    idtoa(&id, idb, IDTOA_BUF);
		    DBG(DBG_CONTROL,
			DBG_log("id type added to secret(%p) %d: %s",
				s,
				s->pks.kind,
				idb));
		}
		if (!shift())
		{
		    /* unexpected Record Boundary or EOF */
		    loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end of id list"
			   , flp->filename, flp->lino);
		    break;
		}
	    }
	}
    }
}

static int
globugh(const char *epath, int eerrno)
{
    openswan_log_errno_routine(eerrno, "problem with secrets file \"%s\"", epath);
    return 1;	/* stop glob */
}

static void
osw_process_secrets_file(struct secret **psecrets
			 , int verbose
			 , const char *file_pat
			 , prompt_pass_t *pass)
{
    struct file_lex_position pos;
    char **fnp;
    glob_t globbuf;

    memset(&globbuf, 0, sizeof(glob_t));
    pos.depth = flp == NULL? 0 : flp->depth + 1;

    if (pos.depth > 10)
    {
	loglog(RC_LOG_SERIOUS, "preshared secrets file \"%s\" nested too deeply", file_pat);
	return;
    }

    /* do globbing */
    {
	int r = glob(file_pat, GLOB_ERR, globugh, &globbuf);

	if (r != 0)
	{
	    switch (r)
	    {
	    case GLOB_NOSPACE:
		loglog(RC_LOG_SERIOUS, "out of space processing secrets filename \"%s\"", file_pat);
		break;
	    case GLOB_ABORTED:
		break;	/* already logged */
#if defined(GLOB_NOMATCH)
	    case GLOB_NOMATCH:
		loglog(RC_LOG_SERIOUS, "no secrets filename matched \"%s\"", file_pat);
		break;
#endif
	    default:
		loglog(RC_LOG_SERIOUS, "unknown glob error %d", r);
		break;
	    }
	    globfree(&globbuf);
	    return;
	}
    }

    /* for each file... */
    for (fnp = globbuf.gl_pathv; fnp!=NULL && *fnp != NULL; fnp++)
    {
	if (lexopen(&pos, *fnp, FALSE))
	{
	    if(verbose) {
		openswan_log("loading secrets from \"%s\"", *fnp);
	    }
	    (void) flushline("file starts with indentation (continuation notation)");
	    osw_process_secret_records(psecrets, verbose, pass);
	    lexclose();
	}
    }

    globfree(&globbuf);
}

void
osw_free_preshared_secrets(struct secret **psecrets)
{
    lock_certs_and_keys("free_preshared_secrets");
    
    if (*psecrets != NULL)
    {
	struct secret *s, *ns;

	openswan_log("forgetting secrets");

	for (s = *psecrets; s != NULL; s = ns)
	{
	    struct id_list *i, *ni;

	    ns = s->next;	/* grab before freeing s */
	    for (i = s->ids; i != NULL; i = ni)
	    {
		ni = i->next;	/* grab before freeing i */
		free_id_content(&i->id);
		pfree(i);
	    }
	    switch (s->pks.kind)
	    {
	    case PPK_PSK:
		pfree(s->pks.u.preshared_secret.ptr);
		break;
	    case PPK_RSA:
		free_RSA_public_content(&s->pks.u.RSA_private_key.pub);
		mpz_clear(&s->pks.u.RSA_private_key.d);
		mpz_clear(&s->pks.u.RSA_private_key.p);
		mpz_clear(&s->pks.u.RSA_private_key.q);
		mpz_clear(&s->pks.u.RSA_private_key.dP);
		mpz_clear(&s->pks.u.RSA_private_key.dQ);
		mpz_clear(&s->pks.u.RSA_private_key.qInv);
		break;
#ifdef SMARTCARD
	    case PPK_PIN:
		scx_release(s->pks.u.smartcard);
		break;
#endif
	    default:
		bad_case(s->pks.kind);
	    }
	    pfree(s);
	}
	*psecrets = NULL;
    }
    
    unlock_certs_and_keys("free_preshard_secrets");
}

void
osw_load_preshared_secrets(struct secret **psecrets
			   , int verbose
			   , const char *secrets_file
			   , prompt_pass_t *pass)
{
    osw_free_preshared_secrets(psecrets);
    (void) osw_process_secrets_file(psecrets, verbose, secrets_file, pass);
}


struct pubkey *
reference_key(struct pubkey *pk)
{
    pk->refcnt++;
    return pk;
}

void
unreference_key(struct pubkey **pkp)
{
    struct pubkey *pk = *pkp;
    char b[IDTOA_BUF];

    if (pk == NULL)
	return;

    /* print stuff */
    DBG(DBG_CONTROLMORE,
 	idtoa(&pk->id, b, sizeof(b));
 	DBG_log("unreference key: %p %s cnt %d--", pk, b, pk->refcnt)
	);

    /* cancel out the pointer */
    *pkp = NULL;

    passert(pk->refcnt != 0);
    pk->refcnt--;

    /* we are going to free the key as the refcount will hit zero */
    if (pk->refcnt == 0)
      free_public_key(pk);
}


/* Free a public key record.
 * As a convenience, this returns a pointer to next.
 */
struct pubkey_list *
free_public_keyentry(struct pubkey_list *p)
{
    struct pubkey_list *nxt = p->next;

    if (p->key != NULL)
	unreference_key(&p->key);
    pfree(p);
    return nxt;
}

void
free_public_keys(struct pubkey_list **keys)
{
    while (*keys != NULL)
	*keys = free_public_keyentry(*keys);
}

/* decode of RSA pubkey chunk
 * - format specified in RFC 2537 RSA/MD5 Keys and SIGs in the DNS
 * - exponent length in bytes (1 or 3 octets)
 *   + 1 byte if in [1, 255]
 *   + otherwise 0x00 followed by 2 bytes of length
 * - exponent
 * - modulus
 */
err_t
unpack_RSA_public_key(struct RSA_public_key *rsa, const chunk_t *pubkey)
{
    chunk_t exp;
    chunk_t mod;

    rsa->keyid[0] = '\0';	/* in case of keybolbtoid failure */

    if (pubkey->len < 3)
	return "RSA public key blob way to short";	/* not even room for length! */

    if (pubkey->ptr[0] != 0x00)
    {
	setchunk(exp, pubkey->ptr + 1, pubkey->ptr[0]);
    }
    else
    {
	setchunk(exp, pubkey->ptr + 3
	    , (pubkey->ptr[1] << BITS_PER_BYTE) + pubkey->ptr[2]);
    }

    if (pubkey->len - (exp.ptr - pubkey->ptr) < exp.len + RSA_MIN_OCTETS_RFC)
	return "RSA public key blob too short";

    mod.ptr = exp.ptr + exp.len;
    mod.len = &pubkey->ptr[pubkey->len] - mod.ptr;

    if (mod.len < RSA_MIN_OCTETS)
	return RSA_MIN_OCTETS_UGH;

    if (mod.len > RSA_MAX_OCTETS)
	return RSA_MAX_OCTETS_UGH;

    n_to_mpz(&rsa->e, exp.ptr, exp.len);
    n_to_mpz(&rsa->n, mod.ptr, mod.len);

    keyblobtoid(pubkey->ptr, pubkey->len, rsa->keyid, sizeof(rsa->keyid));

#ifdef DEBUG
    DBG(DBG_PRIVATE, RSA_show_public_key(rsa));
#endif


    rsa->k = mpz_sizeinbase(&rsa->n, 2);	/* size in bits, for a start */
    rsa->k = (rsa->k + BITS_PER_BYTE - 1) / BITS_PER_BYTE;	/* now octets */

    if (rsa->k != mod.len)
    {
	mpz_clear(&rsa->e);
	mpz_clear(&rsa->n);
	return "RSA modulus shorter than specified";
    }

    return NULL;
}

bool
same_RSA_public_key(const struct RSA_public_key *a
    , const struct RSA_public_key *b)
{
    return a == b
    || (a->k == b->k && mpz_cmp(&a->n, &b->n) == 0 && mpz_cmp(&a->e, &b->e) == 0);
}


void
install_public_key(struct pubkey *pk, struct pubkey_list **head)
{
    struct pubkey_list *p = alloc_thing(struct pubkey_list, "pubkey entry");
    
    unshare_id_content(&pk->id);

    /* copy issuer dn */
    if (pk->issuer.ptr != NULL)
	pk->issuer.ptr = clone_bytes(pk->issuer.ptr, pk->issuer.len, "issuer dn");

    /* store the time the public key was installed */
    time(&pk->installed_time);

    /* install new key at front */
    p->key = reference_key(pk);
    p->next = *head;
    *head = p;
}


void
delete_public_keys(struct pubkey_list **head
		   , const struct id *id, enum pubkey_alg alg)
{
    struct pubkey_list **pp, *p;
    struct pubkey *pk;

    for (pp = head; (p = *pp) != NULL; )
    {
	pk = p->key;
	if (same_id(id, &pk->id) && pk->alg == alg)
	    *pp = free_public_keyentry(p);
	else
	    pp = &p->next;
    }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
