/* Security Policy Data Base (such as it is)
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Andrew Cagney
 * Copyright (C) 2015-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sysdep.h"
#include "constants.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "keys.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */

#include "crypto.h"

#include "kernel_alg.h"
#include "ike_alg.h"
#include "ikev1_db_ops.h"

#include "nat_traversal.h"

/**************** Oakley (main mode) SA database ****************/

/**
 * the XAUTH server/client stuff is a bit confusing.
 *
 * XAUTH overloads the RSA/PSK types with four more types that
 * mean RSA or PSK, but also include whether one is negotiating
 * that the initiator will be the XAUTH client, or the responder will be
 * XAUTH client. It seems unusual that the responder would be the one
 * to undergo XAUTH, since usually it is a roadwarrior to a gateway,
 * however, the gateway may decide it needs to do a new phase 1, for
 * instance.
 *
 * So, when reading this, say "I'm an XAUTH client and I'm initiating",
 * or "I'm an XAUTH server and I'm initiating". Responses for the responder
 * (and validation of the response by the initiator) are determined by the
 * parse_sa_isakmp() part, which folds the XAUTH types into their native
 * types to figure out if it is acceptable to us.
 *
 *
 */

/*
 * A note about SHA1 usage here. The Hash algorithm is actually not
 * used for authentication. I.e. this is not a keyed MAC.
 * It is used as the Pseudo-random-function (PRF), and is therefore
 * not really impacted by recent SHA1 or MD5 breaks.
 *
 */

/* arrays of attributes for transforms, preshared key */

#ifdef USE_DH2
static struct db_attr otpsk1024aes256sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otpsk1024aes128sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
#endif

#ifdef USE_DH2
static struct db_attr otpsk1024des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};
#endif

static struct db_attr otpsk1536des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

/* arrays of attributes for transforms, preshared key, Xauth version */

#ifdef USE_DH2
static struct db_attr otpsk1024des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};
#endif

static struct db_attr otpsk1536des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

#ifdef USE_DH2
static struct db_attr otpsk1024des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};
#endif

static struct db_attr otpsk1536des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

/* arrays of attributes for transforms, RSA signatures */

#ifdef USE_DH2
static struct db_attr otrsasig1024aes256sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otrsasig1024aes128sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
#endif

#ifdef USE_DH2
static struct db_attr otrsasig1024des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};
#endif

static struct db_attr otrsasig1536des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

/* arrays of attributes for transforms, RSA signatures, with/Xauth */
/* xauth c is when Initiator will be the xauth client */

#ifdef USE_DH2
static struct db_attr otrsasig1024des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};
#endif

static struct db_attr otrsasig1536des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

/* arrays of attributes for transforms, RSA signatures, with/Xauth */
/*
 * xauth s is when the Responder will be the xauth client
 * the only time we do this is when we are initiating to a client
 * that we lost contact with. this is rare.
 */

#ifdef USE_DH2
static struct db_attr otrsasig1024des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};
#endif

static struct db_attr otrsasig1536des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

/**************** Oakley (aggressive mode) SA database ****************/
/*
 * the Aggressive mode attributes must be separate, because there
 * can be no choices --- since we must computer keying material,
 * we must actually just agree on what we are going to use.
 */

/* tables of transforms, in preference order (select based on AUTH) */
static struct db_trans IKEv1_oakley_am_trans_psk[] = {
	{ AD_TR(KEY_IKE, otpsk1536des3sha1) },
};

static struct db_trans IKEv1_oakley_am_trans_psk_xauthc[] = {
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauthc) },
};
static struct db_trans IKEv1_oakley_am_trans_psk_xauths[] = {
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauths) },
};

static struct db_trans IKEv1_oakley_am_trans_rsasig[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1) },
};

static struct db_trans IKEv1_oakley_am_trans_rsasig_xauthc[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauthc) },
};
static struct db_trans IKEv1_oakley_am_trans_rsasig_xauths[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauths) },
};

/* array of proposals to be conjoined (can only be one for Oakley) */
static struct db_prop oakley_am_pc_psk[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_psk) } };

static struct db_prop oakley_am_pc_rsasig[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_rsasig) } };

static struct db_prop oakley_am_pc_psk_xauths[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_psk_xauths) } };

static struct db_prop oakley_am_pc_rsasig_xauths[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_rsasig_xauths) } };

static struct db_prop oakley_am_pc_psk_xauthc[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_psk_xauthc) } };

static struct db_prop oakley_am_pc_rsasig_xauthc[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_rsasig_xauthc) } };

/* array of proposal conjuncts (can only be one) */
static struct db_prop_conj IKEv1_oakley_am_props_psk[] =
	{ { AD_PC(oakley_am_pc_psk) } };

static struct db_prop_conj IKEv1_oakley_am_props_rsasig[] =
	{ { AD_PC(oakley_am_pc_rsasig) } };

static struct db_prop_conj IKEv1_oakley_am_props_psk_xauthc[] =
	{ { AD_PC(oakley_am_pc_psk_xauthc) } };

static struct db_prop_conj IKEv1_oakley_am_props_rsasig_xauthc[] =
	{ { AD_PC(oakley_am_pc_rsasig_xauthc) } };

static struct db_prop_conj IKEv1_oakley_am_props_psk_xauths[] =
	{ { AD_PC(oakley_am_pc_psk_xauths) } };

static struct db_prop_conj IKEv1_oakley_am_props_rsasig_xauths[] =
	{ { AD_PC(oakley_am_pc_rsasig_xauths) } };

/* the sadb entry, subscripted by IKEv1_db_sa_index() */
static struct db_sa IKEv1_oakley_aggr_mode_db_sa_table[16] = {
	{ AD_NULL },                                    /* none */
	{ AD_SAp(IKEv1_oakley_am_props_psk) },          /* PSK */
	{ AD_SAp(IKEv1_oakley_am_props_rsasig) },       /* RSASIG */
	{ AD_NULL },                                    /* PSK+RSASIG => invalid in AM */

	{ AD_NULL },                                    /* XAUTHSERVER + none */
	{ AD_SAp(IKEv1_oakley_am_props_psk_xauths) },   /* XAUTHSERVER + PSK */
	{ AD_SAp(IKEv1_oakley_am_props_rsasig_xauths) },/* XAUTHSERVER + RSA */
	{ AD_NULL },                                    /* XAUTHSERVER + RSA+PSK => invalid */

	{ AD_NULL },                                    /* XAUTHCLIENT + none */
	{ AD_SAp(IKEv1_oakley_am_props_psk_xauthc) },   /* XAUTHCLIENT + PSK */
	{ AD_SAp(IKEv1_oakley_am_props_rsasig_xauthc) },/* XAUTHCLIENT + RSA */
	{ AD_NULL },                                    /* XAUTHCLIENT + RSA+PSK => invalid */

	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + none */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + PSK */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
};

/*
 * The oakley sadb is subscripted by a bitset computed by
 * IKEv1_db_sa_index().
 *
 * authby.psk, authby.rsasig, and xauth.{client,server} for this end
 * (idiosyncratic).
 */

struct db_sa *IKEv1_oakley_aggr_mode_db_sa(const struct connection *c)
{
	/* IKEv1 is symmetric */
	enum keyword_auth auth = c->local->host.config->auth;
	pexpect(auth == c->remote->host.config->auth);
	int index = ((auth == AUTH_PSK ? 1 :
		      auth == AUTH_RSASIG ? 2 : 0) |
		     (c->local->host.config->xauth.server ? 4 : 0) |
		     (c->local->host.config->xauth.client ? 8 : 0));
	return &IKEv1_oakley_aggr_mode_db_sa_table[index];
}

#undef AD
#undef AD_NULL

static void free_sa_trans(struct db_trans *tr)
{
	if (tr->attrs != NULL) {
		pfree(tr->attrs);
		tr->attrs = NULL;
	}
}

static void free_sa_prop(struct db_prop *dp)
{
	if (dp->trans != NULL) {
		unsigned int i;

		for (i = 0; i < dp->trans_cnt; i++)
			free_sa_trans(&dp->trans[i]);
		pfree(dp->trans);
		dp->trans = NULL;
		dp->trans_cnt = 0;
	}
	passert(dp->trans_cnt == 0);
}

static void free_sa_prop_conj(struct db_prop_conj *pc)
{
	if (pc->props != NULL) {
		unsigned int i;

		for (i = 0; i < pc->prop_cnt; i++)
			free_sa_prop(&pc->props[i]);
		pfree(pc->props);
		pc->props = NULL;
		pc->prop_cnt = 0;
	}
	passert(pc->prop_cnt == 0);
}

void free_sa(struct db_sa **sapp)
{
	dbg_free("sadb", *sapp, HERE);
	struct db_sa *f = *sapp;

	if (f != NULL) {
		unsigned int i;

		if (f->prop_conjs != NULL) {
			for (i = 0; i < f->prop_conj_cnt; i++)
				free_sa_prop_conj(&f->prop_conjs[i]);
			pfree(f->prop_conjs);
			f->prop_conjs = NULL;
			f->prop_conj_cnt = 0;
		}
		passert(f->prop_conj_cnt == 0);

		pfree(f);
		*sapp = NULL;
	}
}

/*
 * NOTE: "unshare" means turn each pointer to a shared object
 * into a pointer to a clone of that object.  Even though the old pointer
 * is overwritten, this isn't a leak since something else must have had
 * a pointer to it.
 *
 * In these particular routines, this allows cloning to proceed top-down.
 */

static void unshare_trans(struct db_trans *tr)
{
	tr->attrs = clone_bytes(tr->attrs, tr->attr_cnt * sizeof(tr->attrs[0]),
		"sa copy attrs array (unshare)");
}

static void unshare_prop(struct db_prop *p)
{
	unsigned int i;

	p->trans = clone_bytes(p->trans,  p->trans_cnt * sizeof(p->trans[0]),
		"sa copy trans array (unshare)");
	for (i = 0; i < p->trans_cnt; i++)
		unshare_trans(&p->trans[i]);
}

static void unshare_propconj(struct db_prop_conj *pc)
{
	unsigned int i;

	pc->props = clone_bytes(pc->props, pc->prop_cnt * sizeof(pc->props[0]),
		"sa copy prop array (unshare)");
	for (i = 0; i < pc->prop_cnt; i++)
		unshare_prop(&pc->props[i]);
}

struct db_sa *sa_copy_sa(const struct db_sa *sa, where_t where)
{
	struct db_sa *nsa = clone_const_thing(*sa, "sa copy prop_conj (sa_copy_sa)");
	dbg_alloc("sadb", nsa, where);
	nsa->dynamic = true;
	nsa->parentSA = sa->parentSA;

	nsa->prop_conjs = clone_bytes(nsa->prop_conjs,
		sizeof(nsa->prop_conjs[0]) * nsa->prop_conj_cnt,
		"sa copy prop conj array (sa_copy_sa)");
	for (unsigned int i = 0; i < nsa->prop_conj_cnt; i++)
		unshare_propconj(&nsa->prop_conjs[i]);

	return nsa;
}

/*
 * this routine takes two proposals and conjoins them (or)
 */
struct db_sa *sa_merge_proposals(struct db_sa *a, struct db_sa *b)
{
	if (a == NULL || a->prop_conj_cnt == 0) {
		struct db_sa *p = sa_copy_sa(b, HERE);
		return p;
	}

	if (b == NULL || b->prop_conj_cnt == 0) {
		struct db_sa *p = sa_copy_sa(a, HERE);
		return p;
	}

	struct db_sa *n = clone_thing(*a, "conjoin sa (sa_merge_proposals)");
	dbg_alloc("sadb", n, HERE);

	passert(a->prop_conj_cnt == b->prop_conj_cnt);
	passert(a->prop_conj_cnt == 1);

	n->prop_conjs =
		clone_bytes(n->prop_conjs,
			    n->prop_conj_cnt * sizeof(n->prop_conjs[0]),
			    "sa copy prop conj array");

	for (unsigned int i = 0; i < n->prop_conj_cnt; i++) {
		struct db_prop_conj *pca = &n->prop_conjs[i];
		struct db_prop_conj *pcb = &b->prop_conjs[i];

		passert(pca->prop_cnt == pcb->prop_cnt);
		passert(pca->prop_cnt == 1);

		pca->props = clone_bytes(pca->props,
					 pca->prop_cnt * sizeof(pca->props[0]),
					 "sa copy prop array (sa_merge_proposals)");

		for (unsigned int j = 0; j < pca->prop_cnt; j++) {
			struct db_prop *pa = &pca->props[j];
			struct db_prop *pb = &pcb->props[j];
			struct db_trans *t;
			int t_cnt = pa->trans_cnt + pb->trans_cnt;

			t = alloc_bytes(t_cnt * sizeof(pa->trans[0]),
					"sa copy trans array (sa_merge_proposals)");

			memcpy(t, pa->trans, pa->trans_cnt *
			       sizeof(pa->trans[0]));
			memcpy(t + pa->trans_cnt,
			       pb->trans,
			       pb->trans_cnt * sizeof(pa->trans[0]));

			pa->trans = t;
			pa->trans_cnt = t_cnt;
			for (unsigned int k = 0; k < pa->trans_cnt; k++)
				unshare_trans(&pa->trans[k]);
		}
	}

	n->parentSA = a->parentSA;
	return n;
}
