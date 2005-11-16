/* Support of X.509 keys
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2004 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: x509keys.c,v 1.5 2005/06/14 22:38:06 mcr Exp $
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include <sys/queue.h>

#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
#include "oid.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "keys.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "connections.h"
#include "state.h"
#include "md2.h"
#include "md5.h"
#include "sha1.h"
#include "whack.h"
#include "fetch.h"
#include "ocsp.h"
#include "pkcs.h"
#include "x509more.h"
#include "paths.h"

/* extract id and public key from x.509 certificate and
 * insert it into a pubkeyrec
 */
void
add_x509_public_key(x509cert_t *cert , time_t until
    , enum dns_auth_level dns_auth_level)
{
    generalName_t *gn;
    struct pubkey *pk;
    cert_t c = { FALSE, CERT_X509_SIGNATURE, {cert} };

    /* we support RSA only */
    if (cert->subjectPublicKeyAlgorithm != PUBKEY_ALG_RSA) return;

    /* ID type: ID_DER_ASN1_DN  (X.509 subject field) */
    pk = allocate_RSA_public_key(c);
    passert(pk != NULL);
    pk->id.kind = ID_DER_ASN1_DN;
    pk->id.name = cert->subject;
    pk->dns_auth_level = dns_auth_level;
    pk->until_time = until;
    pk->issuer = cert->issuer;
    delete_public_keys(&pk->id, pk->alg);
    install_public_key(pk, &pubkeys);

    gn = cert->subjectAltName;

    while (gn != NULL) /* insert all subjectAltNames */
    {
	struct id id = empty_id;

	gntoid(&id, gn);
	if (id.kind != ID_NONE)
	{
	    pk = allocate_RSA_public_key(c);
	    pk->id = id;
	    pk->dns_auth_level = dns_auth_level;
	    pk->until_time = until;
	    pk->issuer = cert->issuer;
	    delete_public_keys(&pk->id, pk->alg);
	    install_public_key(pk, &pubkeys);
	}
	gn = gn->next;
    }
}


/*  when a X.509 certificate gets revoked, all instances of
 *  the corresponding public key must be removed
 */
void
remove_x509_public_key(/*const*/ x509cert_t *cert)
{
    const cert_t c = {FALSE, CERT_X509_SIGNATURE, {cert}};
    struct pubkey_list *p, **pp;
    struct pubkey *revoked_pk;

    revoked_pk = allocate_RSA_public_key(c);
    p          = pubkeys;
    pp         = &pubkeys;

    while(p != NULL)
   {
	if (same_RSA_public_key(&p->key->u.rsa, &revoked_pk->u.rsa))
	{
	    /* remove p from list and free memory */
	    *pp = free_public_keyentry(p);
	    loglog(RC_LOG_SERIOUS,
		"invalid RSA public key deleted");
	}
	else
	{
	    pp = &p->next;
	}
	p =*pp;
    }
    free_public_key(revoked_pk);
}

/*
 * Decode the CERT payload of Phase 1.
 */
void
decode_cert(struct msg_digest *md)
{
    struct payload_digest *p;

    for (p = md->chain[ISAKMP_NEXT_CERT]; p != NULL; p = p->next)
    {
	struct isakmp_cert *const cert = &p->payload.cert;
	chunk_t blob;
	time_t valid_until;
	blob.ptr = p->pbs.cur;
	blob.len = pbs_left(&p->pbs);
	if (cert->isacert_type == CERT_X509_SIGNATURE)
	{
	    x509cert_t cert = empty_x509cert;
	    if (parse_x509cert(blob, 0, &cert))
	    {
		if (verify_x509cert(&cert, strict_crl_policy, &valid_until))
		{
		    DBG(DBG_X509 | DBG_PARSING,
			DBG_log("Public key validated")
		    )
		    add_x509_public_key(&cert, valid_until, DAL_SIGNED);
		}
		else
		{
		    plog("X.509 certificate rejected");
		}
		free_generalNames(cert.subjectAltName, FALSE);
		free_generalNames(cert.crlDistributionPoints, FALSE);
	    }
	    else
		plog("Syntax error in X.509 certificate");
	}
	else if (cert->isacert_type == CERT_PKCS7_WRAPPED_X509)
	{
	    x509cert_t *cert = NULL;

	    if (parse_pkcs7_cert(blob, &cert))
		store_x509certs(&cert, strict_crl_policy);
	    else
		plog("Syntax error in PKCS#7 wrapped X.509 certificates");
	}
	else
	{
	    loglog(RC_LOG_SERIOUS, "ignoring %s certificate payload",
		   enum_show(&cert_type_names, cert->isacert_type));
	    DBG_cond_dump_chunk(DBG_PARSING, "CERT:\n", blob);
	}
    }
}

/*
 * Decode the CR payload of Phase 1.
 */
void
decode_cr(struct msg_digest *md, generalName_t **requested_ca)
{
    struct payload_digest *p;

    for (p = md->chain[ISAKMP_NEXT_CR]; p != NULL; p = p->next)
    {
	struct isakmp_cr *const cr = &p->payload.cr;
	chunk_t ca_name;
	
	ca_name.len = pbs_left(&p->pbs);
	ca_name.ptr = (ca_name.len > 0)? p->pbs.cur : NULL;

	DBG_cond_dump_chunk(DBG_PARSING, "CR", ca_name);

	if (cr->isacr_type == CERT_X509_SIGNATURE)
	{
	    char buf[IDTOA_BUF];

	    if (ca_name.len > 0)
	    {
		generalName_t *gn;
		
		if (!is_asn1(ca_name))
		    continue;

		gn = alloc_thing(generalName_t, "generalName");
		clonetochunk(ca_name, ca_name.ptr,ca_name.len, "ca name");
		gn->kind = GN_DIRECTORY_NAME;
		gn->name = ca_name;
		gn->next = *requested_ca;
		*requested_ca = gn;
	    }

	    DBG(DBG_PARSING | DBG_CONTROL,
		dntoa_or_null(buf, IDTOA_BUF, ca_name, "%any");
		DBG_log("requested CA: '%s'", buf);
	    )
	}
	else
	    loglog(RC_LOG_SERIOUS, "ignoring %s certificate request payload",
		   enum_show(&cert_type_names, cr->isacr_type));
    }
}

bool
build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs, u_int8_t np)
{
    pb_stream cr_pbs;
    struct isakmp_cr cr_hd;
    cr_hd.isacr_np = np;
    cr_hd.isacr_type = type;

    /* build CR header */
    if (!out_struct(&cr_hd, &isakmp_ipsec_cert_req_desc, outs, &cr_pbs))
	return FALSE;

    if (ca.ptr != NULL)
    {
	/* build CR body containing the distinguished name of the CA */
	if (!out_chunk(ca, &cr_pbs, "CA"))
	    return FALSE;
    }
    close_output_pbs(&cr_pbs);
    return TRUE;
}

bool
collect_rw_ca_candidates(struct msg_digest *md, generalName_t **top)
{
    struct connection *d = find_host_connection(&md->iface->ip_addr
	, pluto_port, (ip_address*)NULL, md->sender_port);

    for (; d != NULL; d = d->hp_next)
    {
	/* must be a road warrior connection */
	if (d->kind == CK_TEMPLATE && !(d->policy & POLICY_OPPO)
	&& d->spd.that.ca.ptr != NULL)
	{
	    generalName_t *gn;
	    bool new_entry = TRUE;

	    for (gn = *top; gn != NULL; gn = gn->next)
	    {
		if (same_dn(gn->name, d->spd.that.ca))
		{
		    new_entry = FALSE;
		    break;
		}
	    }
	    if (new_entry)
	    {
		gn = alloc_thing(generalName_t, "generalName");
		gn->kind = GN_DIRECTORY_NAME;
		gn->name = d->spd.that.ca;
		gn->next = *top;
		*top = gn;
	    }
	}
    }
    return *top != NULL;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
