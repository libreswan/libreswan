/* Security Policy Data Base/structure output
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2012 Antony Antony <antony@phenome.org>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "secrets.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "plutoalg.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "demux.h"
#include "ikev2.h"

#include "nat_traversal.h"

/* Taken from ikev1_spdb_struct.c, as the format is similar */
/* Note: cloned from out_attr, with the same bugs */
static bool ikev2_out_attr(int type,
		    unsigned long val,
		    struct_desc *attr_desc,
		    enum_names *const *attr_val_descs,
		    pb_stream *pbs)
{
	struct ikev2_trans_attr attr;

	if (val >> 16 == 0) {
		/* short value: use TV form - reuse ISAKMP_ATTR_defines for ikev2 */
		attr.isatr_type = type | ISAKMP_ATTR_AF_TV;
		attr.isatr_lv = val;
		if (!out_struct(&attr, attr_desc, pbs, NULL))
			return FALSE;
	} else {
		/*
		 * We really only support KEY_LENGTH, which does not use this long
		 * attribute style. See comments in out_attr() in ikev1_spdb_struct.c
		 */
		pb_stream val_pbs;
		u_int32_t nval = htonl(val);

		attr.isatr_type = type | ISAKMP_ATTR_AF_TLV;
		attr.isatr_lv = sizeof(nval);
		if (!out_struct(&attr, attr_desc, pbs, &val_pbs) ||
		    !out_raw(&nval, sizeof(nval), &val_pbs,
			     "long attribute value"))
			return FALSE;

		close_output_pbs(&val_pbs);
	}
	DBG(DBG_EMITTING, {
		    enum_names *d = attr_val_descs[type];

		    if (d != NULL)
			    DBG_log("    [%lu is %s]", val, enum_show(d,
								      val));
	    });
	return TRUE;
}

bool ikev2_out_sa(pb_stream *outs,
		  enum ikev2_sec_proto_id protoid,
		  struct db_sa *sadb,
		  struct state *st,
		  bool parentSA,
		  enum next_payload_types_ikev2 np)
{
	/*
	 * See RFC 7296 Section 3.3: Security Association Payload
	 *
	 * XXX this code does not yet handle rekeying because it assumes
	 * that a PROTO_v2_ISAKMP SPI should be empty.
	 * In rekeying, the PROTO_v2_ISAKMP SPI is 8 bytes.
	 */
	struct ipsec_proto_info *proto_info = NULL;
	int ipprotoid = 0;	/* initialize to placate old GCC (4.4.7-11) */
	pb_stream sa_pbs;
	unsigned int pc_cnt;

	/* SA header out */
	{
		struct ikev2_sa sa;

		zero(&sa);	/* OK: no pointer fields */
		sa.isasa_np = np;
		sa.isasa_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_PAYLOAD_FLAG)) {
			libreswan_log(
				" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			sa.isasa_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}

		/* no ipsec_doi on IKEv2 */

		if (!out_struct(&sa, &ikev2_sa_desc, outs, &sa_pbs))
			return FALSE;
	}

	passert(parentSA == (protoid == PROTO_v2_ISAKMP));

	switch (protoid) {
	case PROTO_v2_ISAKMP:
		break;

	case PROTO_v2_AH:
		proto_info = &st->st_ah;
		ipprotoid = IPPROTO_AH;
		break;

	case PROTO_v2_ESP:
		proto_info = &st->st_esp;
		ipprotoid = IPPROTO_ESP;
		break;

	default:
		bad_case(protoid);
	}

	if (proto_info != NULL) {
		proto_info->our_spi = get_ipsec_spi(0, /* avoid this # */
						    ipprotoid,
						    &st->st_connection->spd,
						    TRUE /* tunnel */);
	}

	/* now send out all the proposals */

	for (pc_cnt = 0; pc_cnt < sadb->v2_prop_disj_cnt; pc_cnt++) {
		struct db_v2_prop *vp = &sadb->v2_prop_disj[pc_cnt];
		unsigned int pr_cnt;

		/* now send out all the transforms */
		for (pr_cnt = 0; pr_cnt < vp->prop_cnt; pr_cnt++) {
			struct db_v2_prop_conj *vpc = &vp->props[pr_cnt];
			unsigned int ts_cnt = vpc->trans_cnt;
			unsigned int ts_i;

			/* transform to skip (if it equals ts_cnt, then none) */
			unsigned skip_encr = ts_cnt;

			struct ikev2_prop p;
			pb_stream t_pbs;

			zero(&p);	/* OK: no pointer members */

			/* if we are AH we need to skip any encryption payload */
			if (protoid == IKEv2_SEC_PROTO_AH) {
				for (ts_i = 0; ts_i < ts_cnt; ts_i++) {
					if (vpc->trans[ts_i].transform_type == IKEv2_TRANS_TYPE_ENCR) {
						/* Why have we got an ENCR transform when
						 * we are doing AH?
						 * Skip it.  Should we warn?
						 */
						DBG_log("AH: suppressing ENCR %s transform",
							enum_show(&ikev2_trans_type_encr_names,
								vpc->trans[ts_i].transid));
						skip_encr = ts_i;
						if (ts_i + 1 == ts_cnt) {
							/* trim from end */
							ts_cnt--;
							/* ts_cnt == skip_encr */
						}
						break;
					}
				}
			}

			p.isap_lp = (pr_cnt + 1 < vp->prop_cnt ||
					pc_cnt + 1 < sadb->v2_prop_disj_cnt) ?
				v2_PROPOSAL_NON_LAST : v2_PROPOSAL_LAST;

			p.isap_length = 0;
			p.isap_propnum = vpc->propnum;
			p.isap_protoid = protoid;

			p.isap_spisize = parentSA ?
				0 :	/* XXX fix to handle rekeying */
				sizeof(proto_info->our_spi);

			p.isap_numtrans = (skip_encr == ts_cnt) ?
				ts_cnt : ts_cnt - 1;

			if (!out_struct(&p, &ikev2_prop_desc, &sa_pbs, &t_pbs))
				return FALSE;

			if (parentSA) {
				/* XXX fix to handle rekeying */
			} else {
				if (!out_raw(&proto_info->our_spi,
					     sizeof(proto_info->our_spi),
					     &t_pbs, "our spi"))
					return FALSE;
			}

			for (ts_i = 0; ts_i < ts_cnt; ts_i++) {
				struct db_v2_trans *tr = &vpc->trans[ts_i];
				struct ikev2_trans t;
				pb_stream at_pbs;
				unsigned int attr_cnt;

				if (ts_i == skip_encr)
					continue;

				zero(&t);	/* OK: no pointer members */

				t.isat_lt = ts_i + 1 < ts_cnt ?
					v2_TRANSFORM_NON_LAST : v2_TRANSFORM_LAST;

				t.isat_length = 0;
				t.isat_type = tr->transform_type;
				t.isat_transid = tr->transid;

				if (!out_struct(&t, &ikev2_trans_desc, &t_pbs,
						&at_pbs))
					return FALSE;

				for (attr_cnt = 0; attr_cnt < tr->attr_cnt;
				     attr_cnt++) {
					struct db_attr *attr =
						&tr->attrs[attr_cnt];

					if (!ikev2_out_attr(attr->type.v2,
						       attr->val,
						       &ikev2_trans_attr_desc,
						       ikev2_trans_attr_val_descs,
						       &at_pbs)) {
						/*
						 * ??? this message is not
						 * helpful to a user.
						 * Is it redundant?
						 * It should be improved or
						 * eliminated.
						 */
						libreswan_log("ikev2_out_attr() failed");
						return FALSE;
					}
				}

				close_output_pbs(&at_pbs);
			}
			close_output_pbs(&t_pbs);
		}
	}

	close_output_pbs(&sa_pbs);
	return TRUE;
}

struct db_trans_flat {
	u_int8_t protoid;		/* Protocol-Id */
	u_int16_t auth_method;		/* conveyed another way in ikev2 */
	u_int16_t encr_transid;		/* Transform-Id */
	u_int16_t integ_transid;	/* Transform-Id */
	u_int16_t prf_transid;		/* Transform-Id */
	u_int16_t group_transid;	/* Transform-Id */
	u_int16_t encr_keylen;		/* Key length in bits */
};

static enum ikev2_trans_type_encr v1tov2_encr(int oakley)
{
	struct ike_alg *alg = ikev1_alg_find(IKE_ALG_ENCRYPT, oakley);
	if (alg == NULL) {
		/*
		 * Outch, somehow the v1 algorithm we found earlier
		 * has disappeared!
		 */
		DBG(DBG_CONTROL, DBG_log("v1tov2_encr() unknown v1 encrypt algorithm '%d'", oakley));
		return IKEv2_ENCR_INVALID; /* this cannot go over the wire! It's 65536 */
	} else if (alg->algo_v2id == 0) {
		/*
		 * We have some encryption algorithms in IKEv2 that do
		 * not exist in IKEv1 but this code assumes that they
		 * do.  Someone will have to add another unofficial
		 * IKEv1 algorithm id to its table or just not use
		 * this function.
		 *
		 * Better, would be to just pass the ike_alg struct
		 * around.
		 */
		DBG(DBG_CONTROL, DBG_log("v1tov2_encr() v1 encrypt algorithm '%d' has no v2 counterpart", oakley));
		return IKEv2_ENCR_INVALID; /* this cannot go over the wire! It's 65536 */
	} else {
		return alg->algo_v2id;
	}
}

static enum ikev2_trans_type_integ v1tov2_integ(enum ikev2_trans_type_integ oakley)
{
	switch (oakley) {
	case OAKLEY_MD5:
		return IKEv2_AUTH_HMAC_MD5_96;

	case OAKLEY_SHA1:
		return IKEv2_AUTH_HMAC_SHA1_96;

	case OAKLEY_SHA2_256:
		return IKEv2_AUTH_HMAC_SHA2_256_128;

	case OAKLEY_SHA2_384:
		return IKEv2_AUTH_HMAC_SHA2_384_192;

	case OAKLEY_SHA2_512:
		return IKEv2_AUTH_HMAC_SHA2_512_256;

	case OAKLEY_AES_XCBC:
		return IKEv2_AUTH_AES_XCBC_96;

	default:
		return IKEv2_AUTH_INVALID;
	}
}

static enum ikev2_trans_type_integ v1phase2tov2child_integ(int ikev1_phase2_auth)
{
	switch (ikev1_phase2_auth) {
	case AUTH_ALGORITHM_HMAC_MD5:
		return IKEv2_AUTH_HMAC_MD5_96;

	case AUTH_ALGORITHM_HMAC_SHA1:
		return IKEv2_AUTH_HMAC_SHA1_96;

	case AUTH_ALGORITHM_HMAC_SHA2_256:
		return IKEv2_AUTH_HMAC_SHA2_256_128;

	case AUTH_ALGORITHM_HMAC_SHA2_384:
		return IKEv2_AUTH_HMAC_SHA2_384_192;

	case AUTH_ALGORITHM_HMAC_SHA2_512:
		return IKEv2_AUTH_HMAC_SHA2_512_256;

	case AUTH_ALGORITHM_AES_XCBC:
		return IKEv2_AUTH_AES_XCBC_96;

	default:
		return IKEv2_AUTH_INVALID;
	}
}

static enum ikev2_trans_type_prf v1tov2_prf(enum ikev2_trans_type_prf oakley)
{
	switch (oakley) {
	case OAKLEY_MD5:
		return IKEv2_PRF_HMAC_MD5;

	case OAKLEY_SHA1:
		return IKEv2_PRF_HMAC_SHA1;
	
	/* OAKLEY_TIGER not in IKEv2 */

	case OAKLEY_SHA2_256:
		return IKEv2_PRF_HMAC_SHA2_256;

	case OAKLEY_SHA2_384:
		return IKEv2_PRF_HMAC_SHA2_384;

	case OAKLEY_SHA2_512:
		return IKEv2_PRF_HMAC_SHA2_512;

	case OAKLEY_AES_XCBC:
		return IKEv2_PRF_AES128_XCBC;

	default:
		return IKEv2_PRF_INVALID;
	}
}

/*
 * Create a V2 replica of a V1 SA, in situ
 * - idempotent: if the work has been done, don't do it again
 * - as a side effect, the resulting struct db_sa will be dynamic.
 */
void sa_v2_convert(struct db_sa **sapp)
{
	struct db_sa *f = *sapp;
	unsigned int pcc, pr_cnt, pc_cnt, propnum;
	int tot_trans;
	int i;
	struct db_trans_flat *dtfset;
	struct db_trans_flat *dtflast;
	struct db_v2_prop_conj *pc;
	struct db_v2_prop *pr;

	passert(f != NULL);	/* we expect an actual SA */

	passert((f->v2_prop_disj == NULL) == (f->v2_prop_disj_cnt == 0));

	/* make sa_v2_convert idempotent */
	if (f->v2_prop_disj != NULL) {
		DBG(DBG_CONTROL, DBG_log("FIXME: sa_v2_convert() called redundantly"));
		return;
	}

	/* ensure *sapp is mutable */
	if (!f->dynamic)
		*sapp = f = sa_copy_sa(f);

	/* count transforms and allocate space for result */
	{
		unsigned int pcc;
		int tot_trans = 0;

		for (pcc = 0; pcc < f->prop_conj_cnt; pcc++) {
			struct db_prop_conj *dpc = &f->prop_conjs[pcc];
			unsigned int prc;

			for (prc = 0; prc < dpc->prop_cnt; prc++)
				tot_trans += dpc->props[prc].trans_cnt;
		}

		dtfset = alloc_bytes(sizeof(struct db_trans_flat) * tot_trans,
			     "spdb_v2_dtfset");
	}

	tot_trans = 0;
	for (pcc = 0; pcc < f->prop_conj_cnt; pcc++) {
		struct db_prop_conj *dpc = &f->prop_conjs[pcc];
		unsigned int prc;

		for (prc = 0; prc < dpc->prop_cnt; prc++) {
			struct db_prop *dp = &dpc->props[prc];
			unsigned int tcc;

			for (tcc = 0; tcc < dp->trans_cnt; tcc++) {
				struct db_trans *tr = &dp->trans[tcc];
				struct db_trans_flat *dtfone =
					&dtfset[tot_trans];
				unsigned int attr_cnt;

				dtfone->protoid = dp->protoid;

				if (!f->parentSA) {
					dtfone->encr_transid = tr->transid;
					/* IANA ikev1 / ipsec-v3 fixup */
					if (dtfone->encr_transid == IKEv2_ENCR_CAMELLIA_CBC_ikev1)
						dtfone->encr_transid = IKEv2_ENCR_CAMELLIA_CBC;
				}

				for (attr_cnt = 0; attr_cnt < tr->attr_cnt;
				     attr_cnt++) {
					struct db_attr *attr =
						&tr->attrs[attr_cnt];

					if (f->parentSA) {
						switch (attr->type.oakley) {
						case OAKLEY_AUTHENTICATION_METHOD:
							dtfone->auth_method =
								attr->val;
							break;

						case OAKLEY_ENCRYPTION_ALGORITHM:
							dtfone->encr_transid =
								v1tov2_encr(
									attr->val);
							break;

						case OAKLEY_HASH_ALGORITHM:
							dtfone->integ_transid =
								v1tov2_integ(
									attr->val);
							dtfone->prf_transid =
								v1tov2_prf(
									attr->val);
							break;

						case OAKLEY_PRF:
							dtfone->prf_transid =
								v1tov2_prf(attr->val);
							break;

						case OAKLEY_GROUP_DESCRIPTION:
							dtfone->group_transid =
								attr->val;
							break;

						case OAKLEY_KEY_LENGTH:
							dtfone->encr_keylen =
								attr->val;
							break;

						default:
							libreswan_log(
								"sa_v2_convert(): Ignored unknown IKEv2 transform attribute type: %d",
								attr->type.oakley);
							break;
						}
					} else {
						switch (attr->type.ipsec) {
						case AUTH_ALGORITHM:
							dtfone->integ_transid =
								v1phase2tov2child_integ(
									attr->val);
							break;

						case KEY_LENGTH:
							dtfone->encr_keylen =
								attr->val;
							break;

						case ENCAPSULATION_MODE:
							break;

						default:
							libreswan_log(
								"sa_v2_convert(): Ignored unknown IPsec transform attribute type: %d",
								attr->type.ipsec);
							break;
						}
					}
				}
				/* Ensure KEY_LENGTH or OAKLEY_KEY_LENGTH if encr algo requires one */
				if (dtfone->encr_keylen == 0)
					dtfone->encr_keylen = crypto_req_keysize(
						f->parentSA ? CRK_IKEv2 : CRK_ESPorAH,
						dtfone->encr_transid);

				tot_trans++;
			}
		}
	}

	pr = NULL;
	pr_cnt = 0;
	if (tot_trans >= 1)
		pr = alloc_bytes(sizeof(struct db_v2_prop), "db_v2_prop");
	dtflast = NULL;
	pc = NULL;
	pc_cnt = 0;
	propnum = 1;

	for (i = 0; i < tot_trans; i++) {
		struct db_v2_trans *tr;
		int tr_cnt;
		int tr_pos;
		struct db_trans_flat *dtfone = &dtfset[i];

		if (dtfone->protoid == PROTO_ISAKMP)
			tr_cnt = 4;
		else
			tr_cnt = 3;

		if (dtflast != NULL) {
			/*
			 * see if previous protoid is identical to this
			 * one, and if so, then this is a disjunction (OR),
			 * otherwise, it's conjunction (AND)
			 */
			if (dtflast->protoid == dtfone->protoid) {
				/* need to extend pr (list of disjunctions) by one */
				struct db_v2_prop *pr1;

				pr_cnt++;
				pr1 = alloc_bytes(sizeof(struct db_v2_prop) *
						    (pr_cnt + 1),
						    "extended db_v2_prop");
				memcpy(pr1, pr,
				       sizeof(struct db_v2_prop) * pr_cnt);
				pfree(pr);
				pr = pr1;

				/* need to zero this, so it gets allocated */
				propnum++;
				pc = NULL;
				pc_cnt = 0;
			} else {
				/* need to extend pc (list of conjunctions) by one */
				struct db_v2_prop_conj *pc1;

				pc_cnt++;

				pc1 = alloc_bytes(
					sizeof(struct db_v2_prop_conj) *
					(pc_cnt + 1), "extended db_v2_prop_conj");
				memcpy(pc1, pc,
				       sizeof(struct db_v2_prop_conj) *
				       pc_cnt);
				pfree(pc);
				pc = pc1;
				pr[pr_cnt].props = pc;
				pr[pr_cnt].prop_cnt = pc_cnt + 1;

				/* do not increment propnum! */
			}
		}
		dtflast = dtfone;

		if (pc == NULL) {
			pc = alloc_bytes(sizeof(struct db_v2_prop_conj),
					 "db_v2_prop_conj");
			pc_cnt = 0;
			pr[pr_cnt].props = pc;
			pr[pr_cnt].prop_cnt = pc_cnt + 1;
		}

		tr = alloc_bytes(sizeof(struct db_v2_trans) * (tr_cnt),
				 "db_v2_trans");
		pc[pc_cnt].trans = tr;
		pc[pc_cnt].trans_cnt = tr_cnt;

		pc[pc_cnt].propnum = propnum;
		pc[pc_cnt].protoid = dtfset->protoid;

		tr_pos = 0;
		tr[tr_pos].transform_type = IKEv2_TRANS_TYPE_ENCR;
		tr[tr_pos].transid = dtfone->encr_transid;
		if (dtfone->encr_keylen > 0) {
			struct db_attr *attrs =
				alloc_bytes(sizeof(struct db_attr),
					    "db_attrs");

			tr[tr_pos].attrs = attrs;
			tr[tr_pos].attr_cnt = 1;
			attrs->type.v2 = IKEv2_KEY_LENGTH;
			attrs->val = dtfone->encr_keylen;
		}
		tr_pos++;

		tr[tr_pos].transid = dtfone->integ_transid;
		tr[tr_pos].transform_type = IKEv2_TRANS_TYPE_INTEG;
		tr_pos++;

		if (dtfone->protoid == PROTO_ISAKMP) {
			/* XXX Let the user set the PRF.*/
			tr[tr_pos].transform_type = IKEv2_TRANS_TYPE_PRF;
			tr[tr_pos].transid = dtfone->prf_transid;
			tr_pos++;

			tr[tr_pos].transform_type = IKEv2_TRANS_TYPE_DH;
			tr[tr_pos].transid = dtfone->group_transid;
			tr_pos++;
		} else {
			tr[tr_pos].transform_type = IKEv2_TRANS_TYPE_ESN;
			tr[tr_pos].transid = IKEv2_ESN_DISABLED;
			tr_pos++;
		}
		passert(tr_cnt == tr_pos);
	}

	f->v2_prop_disj = pr;
	f->v2_prop_disj_cnt = pr_cnt + 1;

	pfree(dtfset);
}

static bool spdb_v2_match_parent(struct db_sa *sadb,
				 unsigned propnum,
				 unsigned encr_transform,
				 int encr_keylen,
				 unsigned integ_transform,
				 int integ_keylen,
				 unsigned prf_transform,
				 int prf_keylen,
				 unsigned dh_transform,
				 bool enc_requires_integ)
{
	unsigned int pd_cnt;

	for (pd_cnt = 0; pd_cnt < sadb->v2_prop_disj_cnt; pd_cnt++) {
		struct db_v2_prop *pd = &sadb->v2_prop_disj[pd_cnt];
		struct db_v2_prop_conj *pj;
		unsigned int tr_cnt;
		bool encr_matched = FALSE;
		bool integ_matched = FALSE;
		bool integ_checked = FALSE;
		bool prf_matched = FALSE;
		bool dh_matched = FALSE;
		int
			encrid = 0,
			prfid = 0,
			dhid = 0;
		unsigned int integid = 0;
				
		int
			encrwin = -2,
			integwin = -2,
			prfwin = -2;

		/* In PARENT SAs, we only support one conjunctive item */
		if (pd->prop_cnt != 1)
			continue;

		pj = &pd->props[0];

		/* ??? is any other protoid even legal? */
		if (pj->protoid != PROTO_ISAKMP)
			continue;

		for (tr_cnt = 0; tr_cnt < pj->trans_cnt; tr_cnt++) {
			struct db_v2_trans *tr = &pj->trans[tr_cnt];

			DBG(DBG_CONTROL, DBG_log(
				"considering Transform Type %s, TransID %d",
				enum_name(&ikev2_trans_type_names,
					tr->transform_type),
				tr->transid));

			int keylen = -1;
			unsigned int attr_cnt;
			for (attr_cnt = 0; attr_cnt < tr->attr_cnt; attr_cnt++) {
				struct db_attr *attr = &tr->attrs[attr_cnt];

				if (attr->type.v2 == IKEv2_KEY_LENGTH) {
					keylen = attr->val;
					DBG(DBG_CONTROL, DBG_log(
						"IKEv2_KEY_LENGTH attribute %d",
						keylen));
				}
			}

			switch (tr->transform_type) {
			case IKEv2_TRANS_TYPE_ENCR:
				encrid = tr->transid;
				DBG(DBG_CONTROL, DBG_log(
					"encrid(%d), keylen(%d), encr_keylen(%d)",
					encrid, keylen, encr_keylen));
				if (tr->transid == encr_transform &&
				    (keylen == 0 || encr_keylen == -1 || keylen == encr_keylen)) {
					encr_matched = TRUE;
					encrwin = keylen == -1 || keylen == 0 ? encr_keylen : keylen;
				}
				DBG(DBG_CONTROLMORE, {
					struct esb_buf esb;
					DBG_log("proposal %u %s encr= (policy:%s(%d) vs offered:%s(%d))",
						propnum,
						encr_matched ? "succeeded" : "failed",
						enum_showb(&ikev2_trans_type_encr_names, encrid, &esb),
						encrwin,
						enum_show(&ikev2_trans_type_encr_names, encr_transform),
						encr_keylen);
				});
				break;

			case IKEv2_TRANS_TYPE_INTEG:
				/*
				 * When AEAD, current logic
				 * (2015-01-08) still sends a single
				 * AUTH_NONE INTEG transform, handle
				 * that.
				 */
				integid = tr->transid;
				integ_checked = TRUE;
				if (enc_requires_integ) {
					if (integid != IKEv2_AUTH_NONE &&
					    integid == integ_transform &&
					    keylen == integ_keylen) {
						integ_matched = TRUE;
						integwin = keylen;
					}
				} else {
					if (integid == IKEv2_AUTH_NONE &&
					    integ_transform == IKEv2_AUTH_NONE) {
						integ_matched = TRUE;
						integwin = 0;
					}
				}
				DBG(DBG_CONTROLMORE, {
					struct esb_buf esb;
					DBG_log("            %s integ=(policy:%s(%d) vs offered:%s(%d))",
						integ_matched ? "succeeded" : "failed",
						enum_showb(&ikev2_trans_type_integ_names, integid, &esb),
						integwin,
						enum_show(&ikev2_trans_type_integ_names,
							  integ_transform),
						integ_keylen);
				});
				break;

			case IKEv2_TRANS_TYPE_PRF:
				prfid = tr->transid;
				if (tr->transid == prf_transform &&
				    keylen == prf_keylen) {
					prf_matched = TRUE;
					prfwin = keylen;
				}
				DBG(DBG_CONTROLMORE, {
					struct esb_buf esb;
					DBG_log("            %s prf=  (policy:%s(%d) vs offered:%s(%d))",
						prf_matched ? "succeeded" : "failed",
						enum_showb(&ikev2_trans_type_prf_names, prfid, &esb),
						prfwin,
						enum_show(&ikev2_trans_type_prf_names,
							  prf_transform),
						prf_keylen);
				});
				break;

			case IKEv2_TRANS_TYPE_DH:
				/* demand keylen == -1? */
				dhid = tr->transid;
				if (tr->transid == dh_transform)
					dh_matched = TRUE;
				DBG(DBG_CONTROLMORE, {
					struct esb_buf esb;
					DBG_log("            %s dh=   (policy:%s vs offered:%s)",
						dh_matched ? "succeeded" : "failed",
						enum_showb(&oakley_group_names, dhid, &esb),
						enum_show(&oakley_group_names, dh_transform));
				});
				break;

			default:
				/* ignore this unknown or uninteresting transform */
				continue;
			}

			/* TODO: esn_matched not tested! */
			if (dh_matched && prf_matched && integ_matched && encr_matched) {
				return TRUE;
			}
		}
		if (!enc_requires_integ && !integ_checked) {
			/*
			 * Catch AEAD case where integrity isn't
			 * required and we didn't send any over the
			 * wire.  If INTEG_CHECKED then it must have been
			 * rejected.
			 *
			 * Since pluto currently (2015-01-08) always
			 * sends an INTEG transform this code
			 * shouldn't be reached; but just in case ...
			 */
			if (dh_matched && prf_matched && encr_matched) {
				return TRUE;
			}
		}

		DBG(DBG_CONTROLMORE, {
			/* note: enum_show uses a static buffer so more than one call per
			   statement is dangerous */
			struct esb_buf esb;

			DBG_log("proposal %u %s encr= (policy:%s(%d) vs offered:%s(%d))",
				propnum,
				encr_matched ? "succeeded" : "failed",
				enum_showb(&ikev2_trans_type_encr_names, encrid, &esb),
				encrwin,
				enum_show(&ikev2_trans_type_encr_names,
					  encr_transform),
					encr_keylen);
			DBG_log("            %s integ=(policy:%s vs offered:%s)",
				integ_matched ? "succeeded" : "failed",
				enum_showb(&ikev2_trans_type_integ_names, integid, &esb),
				enum_show(&ikev2_trans_type_integ_names,
					  integ_transform));
			DBG_log("            %s prf=  (policy:%s vs offered:%s)",
				prf_matched ? "succeeded" : "failed",
				enum_showb(&ikev2_trans_type_prf_names, prfid, &esb),
				enum_show(&ikev2_trans_type_prf_names,
					  prf_transform));
			DBG_log("            %s dh=   (policy:%s vs offered:%s)",
				dh_matched ? "succeeded" : "failed",
				enum_showb(&oakley_group_names, dhid, &esb),
				enum_show(&oakley_group_names, dh_transform));
		});
	}
	return FALSE;
}

#define MAX_TRANS_LIST 32	/* 32 is an arbitrary limit */

struct ikev2_transform_list {
	int encr_keylens[MAX_TRANS_LIST];	/* -1 means unspecified */
	unsigned int encr_transforms[MAX_TRANS_LIST];
	unsigned int encr_trans_next;
	unsigned int encr_i;

	int integ_keylens[MAX_TRANS_LIST];	/* -1 means unspecified */
	unsigned int integ_transforms[MAX_TRANS_LIST];
	unsigned int integ_trans_next;
	unsigned int integ_i;

	int prf_keylens[MAX_TRANS_LIST];	/* -1 means unspecified */
	unsigned int prf_transforms[MAX_TRANS_LIST];
	unsigned int prf_trans_next;
	unsigned int prf_i;

	unsigned int dh_transforms[MAX_TRANS_LIST];
	unsigned int dh_trans_next;
	unsigned int dh_i;

	unsigned int esn_transforms[MAX_TRANS_LIST];
	unsigned int esn_trans_next;
	unsigned int esn_i;
};

static bool ikev2_match_transform_list_parent(struct db_sa *sadb,
					      unsigned int propnum, u_int8_t ipprotoid,
					      struct ikev2_transform_list *itl)
{
	DBG(DBG_CONTROL,DBG_log("ipprotoid is '%d'", ipprotoid));
	passert(ipprotoid == PROTO_v2_ISAKMP);

	const struct encrypt_desc *alg = (const struct encrypt_desc*)
		ikev2_alg_find(IKE_ALG_ENCRYPT, itl->encr_transforms[0]);
	bool enc_requires_integ = ike_alg_enc_requires_integ(alg);

	unsigned int i;
	for (i = 1; i < itl->encr_trans_next; i++) {
		const struct encrypt_desc *alg2 = (const struct encrypt_desc*)
			ikev2_alg_find(IKE_ALG_ENCRYPT, itl->encr_transforms[i]);
		if (ike_alg_enc_requires_integ(alg2) != enc_requires_integ) {
			libreswan_log("rejecting ISAKMP proposal %u: encryption transforms mix AEAD (GCM, CCM) and non-AEAD",
				      propnum);
			return FALSE;
		}
	}

	/*
	 * AEAD algorithms (e.x, AES_GCM) do not require separate
	 * integrity.  Only allow NONE.
	 *
	 * If there was no integrity transform on the wire a single
	 * AUTH_NONE transform will have been added by
	 * ikev2_process_transforms.
	 */
	passert(itl->integ_trans_next >= 1);
	if (enc_requires_integ) {
		if (itl->integ_trans_next == 1 &&
		    itl->integ_transforms[0] == IKEv2_AUTH_NONE) {
			libreswan_log("rejecting ISAKMP proposal %u: encryption transform requires an integrity transform",
				      propnum);
			return FALSE;
		}
	} else {
		if (itl->integ_trans_next > 1 ||
		    (itl->integ_trans_next == 1 && itl->integ_transforms[0] != IKEv2_AUTH_NONE)) {
			libreswan_log("rejecting ISAKMP proposal %u: AEAD (i.e., CCM, GCM) encryption transform forbids an integrity transform",
				      propnum);
			return FALSE;
		}
	}

	if (itl->prf_trans_next == 0) {
		libreswan_log("ignored ISAKMP proposal %u with no PRF transform",
			      propnum);
		return FALSE;
	}
	if (itl->dh_trans_next == 0) {
		libreswan_log(
			"ignored ISAKMP proposal %u with no Diffie-Hellman transform",
			propnum);
		return FALSE;
	}

	/*
	 * now that we have a list of all the possibilities, see if any
	 * of them match.
	 */

	for (itl->encr_i = 0; itl->encr_i < itl->encr_trans_next;
	     itl->encr_i++) {
		for (itl->integ_i = 0; itl->integ_i < itl->integ_trans_next;
		     itl->integ_i++) {
			for (itl->prf_i = 0; itl->prf_i < itl->prf_trans_next;
			     itl->prf_i++) {
				for (itl->dh_i = 0;
				     itl->dh_i < itl->dh_trans_next;
				     itl->dh_i++) {
					if (spdb_v2_match_parent(sadb, propnum,
								 itl->encr_transforms[itl->encr_i],
								 itl->encr_keylens[itl->encr_i],
								 itl->integ_transforms[itl->integ_i],
								 itl->integ_keylens[itl->integ_i],
								 itl->prf_transforms[itl->prf_i],
								 itl->prf_keylens[itl->prf_i],
								 itl->dh_transforms[itl->dh_i],
								 enc_requires_integ))
						return TRUE;
				}
			}
		}
	}
	return FALSE;
}

static stf_status ikev2_process_transforms(struct ikev2_prop *prop,
					   pb_stream *prop_pbs,
					   struct ikev2_transform_list *itl)
{
	zero(itl);	/* OK: no pointer members */

	while (prop->isap_numtrans-- > 0) {
		pb_stream trans_pbs;
		pb_stream attr_pbs;
		/* u_char *attr_start; */
		/* size_t attr_len; */
		struct ikev2_trans trans;
		struct ikev2_trans_attr attr;
		int keylen = -1;
		/* err_t ugh = NULL; */	/* set to diagnostic when problem detected */

		if (!in_struct(&trans, &ikev2_trans_desc,
			       prop_pbs, &trans_pbs))
			return STF_FAIL + v2N_INVALID_SYNTAX;

		while (pbs_left(&trans_pbs) != 0) {
			if (!in_struct(&attr, &ikev2_trans_attr_desc,
				       &trans_pbs,
				       &attr_pbs))
				return STF_FAIL + v2N_INVALID_SYNTAX;

			switch (attr.isatr_type) {
			case IKEv2_KEY_LENGTH | ISAKMP_ATTR_AF_TV:
				keylen = attr.isatr_lv;
				break;
			default:
				libreswan_log(
					"ikev2_process_transforms(): Ignored unknown IKEv2 Transform Attribute: %d",
					attr.isatr_type);
				break;
			}
		}

		/* we read the attributes if we need to see details. */
		switch (trans.isat_type) {
		case IKEv2_TRANS_TYPE_ENCR:
			if (itl->encr_trans_next < MAX_TRANS_LIST) {
				itl->encr_keylens[itl->encr_trans_next] =
					keylen;
				itl->encr_transforms[itl->encr_trans_next++] =
					trans.isat_transid;
			} /* show failure with else */
			break;

		case IKEv2_TRANS_TYPE_INTEG:
			if (itl->integ_trans_next < MAX_TRANS_LIST) {
				itl->integ_keylens[itl->integ_trans_next] =
					keylen;
				itl->integ_transforms[itl->integ_trans_next++]
					= trans.isat_transid;
			}
			break;

		case IKEv2_TRANS_TYPE_PRF:
			if (itl->prf_trans_next < MAX_TRANS_LIST) {
				itl->prf_keylens[itl->prf_trans_next] = keylen;
				itl->prf_transforms[itl->prf_trans_next++] =
					trans.isat_transid;
			}
			break;

		case IKEv2_TRANS_TYPE_DH:
			if (itl->dh_trans_next < MAX_TRANS_LIST)
				itl->dh_transforms[itl->dh_trans_next++] =
					trans.isat_transid;
			break;

		case IKEv2_TRANS_TYPE_ESN:
			if (itl->esn_trans_next < MAX_TRANS_LIST)
				itl->esn_transforms[itl->esn_trans_next++] =
					trans.isat_transid;
			break;
		}
	}

	if (itl->integ_trans_next == 0) {
		/*
		 * If there's no integrity (hash) transform, such as
		 * for AEAD (e.x., AES_GCM) then fake up an AUTH_NONE
		 * transform.  A single AUTH_NONE transform (fake or
		 * real) should be ignored, and for-loops further in
		 * assume at least one is present.
		 */
		itl->integ_transforms[0] = IKEv2_AUTH_NONE;
		itl->integ_keylens[0] = 0;
		itl->integ_trans_next = 1;
	} else if (itl->integ_trans_next > 1) {
		/*
		 * If the integrity (hash) transform set contains more
		 * than one algorithm than AUTH_NONE cannot be a
		 * member.  But, as a single proposal it is ok and,
		 * like the above hack, should be ignored.
		 */
		unsigned int i;

		for (i=0; i < itl->integ_trans_next; i++) {
			if (itl->integ_transforms[i] == IKEv2_AUTH_NONE) {
				libreswan_log("IKEv2_AUTH_NONE integ transform cannot be part of a set - rejecting proposal");
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}
		}
	}
	return STF_OK;
}

static stf_status ikev2_emit_winning_sa(struct state *st,
					       pb_stream *r_sa_pbs,
					       struct trans_attrs ta,
					       bool parentSA,
					       struct ikev2_prop winning_prop)
{
	struct ipsec_proto_info *proto_info = NULL;
	struct ikev2_prop r_proposal = winning_prop;
	pb_stream r_proposal_pbs;
	struct ikev2_trans r_trans;
	pb_stream r_trans_pbs;

	/* ??? everything to do with is_ah is a kludge */
	bool is_ah = FALSE;

	zero(&r_trans);	/* OK: no pointer members */

	if (parentSA) {
		/* Proposal - XXX */
		r_proposal.isap_spisize = 0;

		/* cipher + integrity check + PRF hash + DH group */
		r_proposal.isap_numtrans = 4;
	} else {
		int ipprotoid;

		is_ah = ta.encrypt == ESP_reserved;
		if (is_ah) {
			ipprotoid = IPPROTO_AH;
			proto_info = &st->st_ah;

			/* integrity check + ESN sequence */
			r_proposal.isap_numtrans = 2;
		} else {
			ipprotoid = IPPROTO_ESP;
			proto_info = &st->st_esp;

			/* cipher + integrity check + ESN sequence */
			r_proposal.isap_numtrans = 3;
		}
		r_proposal.isap_spisize = sizeof(proto_info->our_spi);
		proto_info->present = TRUE;
		proto_info->our_spi = get_ipsec_spi(0, /* avoid this # */
						    ipprotoid,
						    &st->st_connection->spd,
						    TRUE /* tunnel */);
	}

	r_proposal.isap_lp = v2_PROPOSAL_LAST;

	if (!out_struct(&r_proposal, &ikev2_prop_desc,
			r_sa_pbs, &r_proposal_pbs))
		impossible();

	if (!parentSA) {
		if (!out_raw(&proto_info->our_spi, sizeof(proto_info->our_spi),
			     &r_proposal_pbs, "our spi")) {
			libreswan_log("out_raw() failed");
			return STF_INTERNAL_ERROR;
		}
	}

	/* Transform - cipher */
	if (!is_ah) {
		r_trans.isat_type = IKEv2_TRANS_TYPE_ENCR;
		r_trans.isat_transid = ta.encrypt;
		r_trans.isat_lt = v2_TRANSFORM_NON_LAST;
		if (!out_struct(&r_trans, &ikev2_trans_desc,
				&r_proposal_pbs, &r_trans_pbs))
			impossible();

		if (ta.encrypter != NULL) {
			int defkeysize = crypto_req_keysize(parentSA ? CRK_IKEv2 : CRK_ESPorAH,
				ta.encrypt);

			if (ta.enckeylen == 0) {
				/* pick up from received proposal, if any */
				unsigned int stoe = st->st_oakley.enckeylen;

				if (stoe != 0) {
					if (stoe == ta.encrypter->keyminlen ||
					    stoe == ta.encrypter->keydeflen ||
					    stoe == ta.encrypter->keymaxlen) {

						ta.enckeylen = stoe;
					}
				} else {
					ta.enckeylen = defkeysize;
				}
			}
			/* check for mandatory keysize, add if needed */
			if (defkeysize != 0) {
				DBG(DBG_CONTROL,DBG_log(
					"keysize is required - sending key length attribute"));
				if(!ikev2_out_attr(IKEv2_KEY_LENGTH,
						ta.enckeylen,
						&ikev2_trans_attr_desc,
						ikev2_trans_attr_val_descs,
						&r_trans_pbs)) {

						libreswan_log("ikev2_out_attr() failed");
						return STF_INTERNAL_ERROR;
				}
			} else {
				DBG(DBG_CONTROL,DBG_log(
					"keysize is NOT required - NOT sent key length attribute"));
			}
		}

		close_output_pbs(&r_trans_pbs);
	}

	/* Transform - integrity check */
	r_trans.isat_type = IKEv2_TRANS_TYPE_INTEG;
	r_trans.isat_transid = ta.integ_hash;
	r_trans.isat_lt = v2_TRANSFORM_NON_LAST;
	if (!out_struct(&r_trans, &ikev2_trans_desc,
			&r_proposal_pbs, &r_trans_pbs))
		impossible();
	close_output_pbs(&r_trans_pbs);

	if (parentSA) {
		/* Transform - PRF hash */
		r_trans.isat_type = IKEv2_TRANS_TYPE_PRF;
		r_trans.isat_transid = ta.prf_hash;
		r_trans.isat_lt = v2_TRANSFORM_NON_LAST;
		if (!out_struct(&r_trans, &ikev2_trans_desc,
				&r_proposal_pbs, &r_trans_pbs))
			impossible();
		close_output_pbs(&r_trans_pbs);

		/* Transform - DH group */
		r_trans.isat_type = IKEv2_TRANS_TYPE_DH;
		r_trans.isat_transid = ta.groupnum;
		r_trans.isat_lt = v2_TRANSFORM_LAST;
		if (!out_struct(&r_trans, &ikev2_trans_desc,
				&r_proposal_pbs, &r_trans_pbs))
			impossible();
		close_output_pbs(&r_trans_pbs);
		st->st_oakley = ta;
	} else {
		/* Transform - ESN sequence */
		r_trans.isat_type = IKEv2_TRANS_TYPE_ESN;
		r_trans.isat_transid = IKEv2_ESN_DISABLED;
		r_trans.isat_lt = v2_TRANSFORM_LAST;
		if (!out_struct(&r_trans, &ikev2_trans_desc,
				&r_proposal_pbs, &r_trans_pbs))
			impossible();
		close_output_pbs(&r_trans_pbs);
	}

	/* close out the proposal */
	close_output_pbs(&r_proposal_pbs);
	close_output_pbs(r_sa_pbs);

	/* ??? If selection, we used to save the proposal in state.
	 * We never used it.  From proposal_pbs.start,
	 * length pbs_room(&proposal_pbs)
	 */

	return STF_OK;
}

/* ??? parts of ikev2_parse_parent_sa_body and ikev2_parse_child_sa_body are enough alike that they share bugs */

stf_status ikev2_parse_parent_sa_body(
	pb_stream *sa_pbs,	/* body of input SA Payload */
	pb_stream *r_sa_pbs,	/* if non-NULL, where to emit winning SA */
	struct state *st,	/* current state object */
	bool selection)		/* if this SA is a selection, only one
				 * tranform can appear.
				 */
{
	pb_stream proposal_pbs;
	struct ikev2_prop proposal;
	unsigned int lp = v2_PROPOSAL_NON_LAST;
	unsigned int nextpropnum = 1;
	bool gotmatch = FALSE;
	struct ikev2_prop winning_prop;
	struct trans_attrs ta;
	struct connection *c = st->st_connection;
	struct ikev2_transform_list itl0;

	/* find the policy structures: quite a dance (see ikev2parent_outI1) */
	if (st->st_sadb == NULL) {
		struct db_sa *t = IKEv2_oakley_sadb(c->policy);
		struct db_sa *u = oakley_alg_makedb(st->st_connection->alg_info_ike,
					 t, FALSE);

		/* ??? why is u often NULL? */
		st->st_sadb = u == NULL ? t : u;
	}
	sa_v2_convert(&st->st_sadb);

	zero(&ta);	/* ??? pointer fields might not be NULLed */

	/*
	 * loop for each proposal.
	 *
	 * This continues even after a winner has been selected
	 * as a way of checking that the remaining proposals are correct.
	 * If we didn't care, we could exit the loop on success.
	 */
	while (lp == v2_PROPOSAL_NON_LAST) {
		/*
		 * note: we don't support ESN,
		 * so ignore any proposal that insists on it
		 */

		if (!in_struct(&proposal, &ikev2_prop_desc, sa_pbs,
			       &proposal_pbs)) {
			loglog(RC_LOG_SERIOUS, "corrupted proposal");
			return STF_FAIL + v2N_INVALID_SYNTAX;
		}

		lp = proposal.isap_lp;

		if (selection) {
			/* must be only one proposal in a selection */
			if (lp == v2_PROPOSAL_NON_LAST) {
				libreswan_log("Error: more than one proposal received from responder.");
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}
		} else {
			/* if not a selection, proposals must be ordinally numbered */
			if (proposal.isap_propnum != nextpropnum) {
				loglog(RC_LOG_SERIOUS,
					"proposal number was %u but %u expected",
					proposal.isap_propnum,
					nextpropnum);
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}
			nextpropnum = proposal.isap_propnum + 1;
		}

		if (proposal.isap_protoid != PROTO_ISAKMP) {
			loglog(RC_LOG_SERIOUS,
			       "unexpected PARENT_SA, expected child");
			return STF_FAIL + v2N_INVALID_SYNTAX;
		}

		if (proposal.isap_spisize == 0) {
			/* as it should be */
		} else if (proposal.isap_spisize <= MAX_ISAKMP_SPI_SIZE) {
			/* try to ignore crap, even though this seems stupid */
			u_char junk_spi[MAX_ISAKMP_SPI_SIZE];

			if (!in_raw(junk_spi, proposal.isap_spisize,
				    &proposal_pbs,
				    "PARENT SA SPI"))
				return STF_FAIL + v2N_INVALID_SYNTAX;
			loglog(RC_LOG,
			       "ignoring unexpected SPI (size %u) in PARENT_SA Proposal",
			       (unsigned)proposal.isap_spisize);
		} else {
			loglog(RC_LOG_SERIOUS,
			       "invalid SPI size (%u) in PARENT_SA Proposal",
			       (unsigned)proposal.isap_spisize);
			return STF_FAIL + v2N_INVALID_SPI;
		}

		{
			stf_status ret = ikev2_process_transforms(&proposal,
								  &proposal_pbs,
								  &itl0);

			if (ret != STF_OK) {
				DBG(DBG_CONTROLMORE, DBG_log("ikev2_process_transforms() failed"));
				return ret;
			}
		}

		/* Note: only try to match if we haven't had one */
		if (!gotmatch &&
		    ikev2_match_transform_list_parent(st->st_sadb,
						      proposal.isap_propnum,
						      proposal.isap_protoid,
						      &itl0)) {
			winning_prop = proposal;
			gotmatch = TRUE;

			/*
			 * record details of the winning transform now
			 * because itl0 will change with later matches
			 */
			ta.encrypt = itl0.encr_transforms[itl0.encr_i];
			ta.enckeylen = itl0.encr_keylens[itl0.encr_i] > 0 ?
				       itl0.encr_keylens[itl0.encr_i] : 0;
			ta.integ_hash = itl0.integ_transforms[itl0.integ_i];
			ta.prf_hash = itl0.prf_transforms[itl0.prf_i];
			ta.groupnum = itl0.dh_transforms[itl0.dh_i];
		}
	}

	if (!gotmatch) {
		libreswan_log("No PARENT proposal selected");
		return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
	}

	/*
	 * since we found something that matched, we might need to emit the
	 * winning value.
	 */
	ta.encrypter = (struct encrypt_desc *)ikev2_alg_find(
		IKE_ALG_ENCRYPT,
		ta.encrypt);
	passert(ta.encrypter != NULL);
	if (ta.enckeylen <= 0)
		ta.enckeylen = ta.encrypter->keydeflen;

	ta.integ_hasher = (struct hash_desc *)ikev2_alg_find(IKE_ALG_INTEG,
								 ta.integ_hash);

	ta.prf_hasher = (struct hash_desc *)ikev2_alg_find(IKE_ALG_HASH,
								ta.prf_hash);
	passert(ta.prf_hasher != NULL);

	ta.group = lookup_group(ta.groupnum);

	st->st_oakley = ta;

	if (r_sa_pbs != NULL) {
		return ikev2_emit_winning_sa(st, r_sa_pbs,
					     ta,
					     /*parentSA*/ TRUE,
					     winning_prop);
	}
	return STF_OK;
}

static bool spdb_v2_match_child(struct db_sa *sadb,
				unsigned propnum,
				unsigned encr_transform,
				int encr_keylen,
				unsigned integ_transform,
				int integ_keylen,
				unsigned esn_transform,
				bool gcm_without_integ)
{
	unsigned int pd_cnt;

	for (pd_cnt = 0; pd_cnt < sadb->v2_prop_disj_cnt; pd_cnt++) {
		struct db_v2_prop_conj  *pj;
		unsigned int tr_cnt;

		int encrid = 0;
		int integid = 0;
		int esnid = 0;

		bool integ_matched = gcm_without_integ;
		bool encr_matched = FALSE;	/* or AH so not needed */
		bool esn_matched = FALSE;

		int observed_encr_keylen = 0;
		int observed_integ_keylen = 0;

		{
			struct db_v2_prop *pd = &sadb->v2_prop_disj[pd_cnt];

			/* XXX need to fix this */
			if (pd->prop_cnt != 1)
				continue;

			pj = &pd->props[0];
		}

		if (pj->protoid == PROTO_v2_ISAKMP)
			continue;

		if (pj->protoid == PROTO_v2_AH)
			encr_matched = TRUE; /* no encryption used for AH */

		for (tr_cnt = 0; tr_cnt < pj->trans_cnt; tr_cnt++) {
			struct db_v2_trans *tr = &pj->trans[tr_cnt];
			int keylen = -1;
			unsigned int attr_cnt;

			for (attr_cnt = 0; attr_cnt < tr->attr_cnt;
			     attr_cnt++) {
				struct db_attr *attr = &tr->attrs[attr_cnt];

				if (attr->type.v2 == IKEv2_KEY_LENGTH)
					keylen = attr->val;
			}

			DBG(DBG_CONTROLMORE,DBG_log("Starting at transform type %s",
				enum_show(&ikev2_trans_type_names, tr->transform_type)));
			switch (tr->transform_type) {
			case IKEv2_TRANS_TYPE_ENCR:
				if (pj->protoid == PROTO_v2_ESP) {
					encrid = tr->transid;
					observed_encr_keylen = keylen;
					if (tr->transid == encr_transform &&
					(keylen == -1 || encr_keylen == -1 || keylen == encr_keylen))
						encr_matched = TRUE;
				}
				break;

			case IKEv2_TRANS_TYPE_INTEG:
				integid = tr->transid;
				observed_integ_keylen = keylen;
				if (tr->transid == integ_transform && keylen == integ_keylen)
					integ_matched = TRUE;
				break;

#if 0	/* eventually, for PFS in CREATE_CHILD_SA */
			case IKEv2_TRANS_TYPE_DH:
				if (tr->transid == dh_transform)
					dh_matched = TRUE;
				break;
#endif

			case IKEv2_TRANS_TYPE_ESN:
				esnid = tr->transid;
				if (tr->transid == esn_transform)
					esn_matched = TRUE;
				break;

			default:
				DBG(DBG_CONTROLMORE,DBG_log("Not comparing %s transform type",
					enum_show(&ikev2_trans_type_names, tr->transform_type)));
				continue;
			}


			DBG(DBG_CONTROLMORE, {
				DBG_log("%s proposal %u",
					(esn_matched && integ_matched && encr_matched) ?
						"matched" : "failed",
					propnum);
				if (pj->protoid == PROTO_v2_ESP) {
					DBG_log("            %s encr= (policy:%s(%d) vs offered:%s(%d))",
						encr_matched ? "succeeded" : "failed",
						enum_name(&ikev2_trans_type_encr_names, encrid),
						observed_encr_keylen,
						enum_name(&ikev2_trans_type_encr_names,
							  encr_transform),
						encr_keylen);
				}
				DBG_log("            %s integ=(policy:%s(%d) vs offered:%s(%d))",
					integ_matched ? "succeeded" : "failed",
					enum_name(&ikev2_trans_type_integ_names, integid), observed_integ_keylen,
					enum_name(&ikev2_trans_type_integ_names,
						  integ_transform), integ_keylen);
				DBG_log("            %s esn=  (policy:%s vs offered:%s)",
					esn_matched ? "succeeded" : "failed",
					enum_name(&ikev2_trans_type_esn_names, esnid),
					enum_name(&ikev2_trans_type_esn_names,
						  esn_transform));
			});

			if (esn_matched && integ_matched && encr_matched) {
				return TRUE;
			}
		}
		DBG(DBG_CONTROLMORE, {
			DBG_log("not matched proposal %u", propnum);
			if (pj->protoid == PROTO_v2_ESP) {
			   DBG_log("            %s encr= (policy:%s(%d) vs offered:%s(%d))",
				encr_matched ? "succeeded" : "failed",
				enum_name(&ikev2_trans_type_encr_names, encrid), observed_encr_keylen,
				enum_name(&ikev2_trans_type_encr_names,
					  encr_transform), encr_keylen);
			}
			DBG_log("            %s integ=(policy:%s(%d) vs offered:%s(%d))",
				integ_matched ? "succeeded" : "failed",
				enum_name(&ikev2_trans_type_integ_names, integid), observed_integ_keylen,
				enum_name(&ikev2_trans_type_integ_names,
					  integ_transform), integ_keylen);
			DBG_log("            %s esn=  (policy:%s vs offered:%s)",
				esn_matched ? "succeeded" : "failed",
				enum_name(&ikev2_trans_type_esn_names, esnid),
				enum_name(&ikev2_trans_type_esn_names,
					  esn_transform));
		});

	}
	return FALSE;
}

static bool ikev2_match_transform_list_child(struct db_sa *sadb,
					     unsigned int propnum, u_int8_t ipprotoid,
					     struct ikev2_transform_list *itl)
{
	bool gcm_without_integ = FALSE;

	if (ipprotoid == PROTO_v2_ESP && itl->encr_trans_next < 1) {
		libreswan_log("ignored ESP proposal %u with no cipher transforms",
			      propnum);
		return FALSE;
	}
	if (ipprotoid == PROTO_v2_AH && itl->encr_trans_next > 0) {
		libreswan_log("ignored AH proposal %u with cipher transform(s)",
			      propnum);
		return FALSE;
	}

	if (ipprotoid == PROTO_v2_ESP) {
		switch(itl->encr_transforms[0]) {
		case IKEv2_ENCR_AES_GCM_8:
		case IKEv2_ENCR_AES_GCM_12:
		case IKEv2_ENCR_AES_GCM_16:
		case IKEv2_ENCR_AES_CCM_8:
		case IKEv2_ENCR_AES_CCM_12:
		case IKEv2_ENCR_AES_CCM_16:
			gcm_without_integ = TRUE;
			if (itl->integ_trans_next != 1 || itl->integ_transforms[0] != IKEv2_AUTH_NONE) {
				libreswan_log(
					"ignored CCM/GCM ESP proposal %u: integrity transform must be IKEv2_AUTH_NONE or absent",
					propnum);
				return FALSE;
			}
			break;
		default:
			passert(itl->integ_trans_next > 0);
			if (itl->integ_transforms[0] == IKEv2_AUTH_NONE) {
				libreswan_log(
					"ignored ESP proposal %u with no integrity transforms (not CCM/GCM)",
					propnum);
				return FALSE;
			}
			break;
		}
	}

	if (itl->esn_trans_next == 0) {
		/* ESN can be enabled for GCM */
		itl->esn_transforms[itl->esn_trans_next++] =
			IKEv2_ESN_DISABLED;
	}

	/*
	 * now that we have a list of all the possibilities, see if any
	 * of them match.
	 */
	if (ipprotoid == PROTO_v2_ESP) {
		for (itl->encr_i = 0; itl->encr_i < itl->encr_trans_next; itl->encr_i++) {
			for (itl->integ_i = 0; itl->integ_i < itl->integ_trans_next; itl->integ_i++) {
				for (itl->esn_i = 0; itl->esn_i < itl->esn_trans_next; itl->esn_i++) {
					if (spdb_v2_match_child(sadb, propnum,
						itl->encr_transforms[itl->encr_i],
						itl->encr_keylens[itl->encr_i],
						itl->integ_transforms[itl->integ_i],
						itl->integ_keylens[itl->integ_i],
						itl->esn_transforms[itl->esn_i], gcm_without_integ))
							return TRUE;
				}
			}
		}
	} else if (ipprotoid == PROTO_v2_AH) {
			for (itl->integ_i = 0; itl->integ_i < itl->integ_trans_next; itl->integ_i++) {
				for (itl->esn_i = 0; itl->esn_i < itl->esn_trans_next; itl->esn_i++) {
					if (spdb_v2_match_child(sadb, propnum,
						itl->encr_transforms[itl->encr_i],
						itl->encr_keylens[itl->encr_i],
						itl->integ_transforms[itl->integ_i],
						itl->integ_keylens[itl->integ_i],
						itl->esn_transforms[itl->esn_i], gcm_without_integ))
							return TRUE;
				}
			}
	} else {
		libreswan_log("Ignored proposal with non-AH/non-ESP protoid '%d'", ipprotoid);
		return FALSE;
	}

	DBG(DBG_CONTROLMORE,
		DBG_log("proposal %u was not usable - but were we not our best?",
			propnum));
	return FALSE;
}

/* ??? parts of ikev2_parse_parent_sa_body and ikev2_parse_child_sa_body are enough alike that they share bugs */

stf_status ikev2_parse_child_sa_body(
	pb_stream *sa_pbs,	/* body of input SA Payload */
	pb_stream *r_sa_pbs,	/* if non-NULL, where to emit winning SA */
	struct state *st,	/* current state object */
	bool selection)		/* if this SA is a selection, only one
				 * tranform can appear.
				 */
{
	pb_stream proposal_pbs;
	struct ikev2_prop proposal;
	unsigned int lp = v2_PROPOSAL_NON_LAST;
	struct ipsec_proto_info *proto_info = NULL;
	unsigned int nextpropnum = 1;
	bool gotmatch = FALSE;
	struct ikev2_prop winning_prop;
	struct trans_attrs ta;
	struct connection *c = st->st_connection;
	struct ikev2_transform_list itl0;

	DBG(DBG_CONTROLMORE, DBG_log("entered ikev2_parse_child_sa_body()"));

	/*
	 * Find the policy structures.
	 * ??? does this only work for ESP?
	 * There is no c->alg_info_ah.
	 */
	passert(st->st_sadb == NULL);
	st->st_sadb = kernel_alg_makedb(c->policy, c->alg_info_esp, TRUE);
	sa_v2_convert(&st->st_sadb);

	zero(&ta);	/* ??? pointer fields might not be NULLed */

	/*
	 * loop for each proposal.
	 *
	 * This continues even after a winner has been selected
	 * as a way of checking that the remaining proposals are correct.
	 * If we didn't care, we could exit the loop on success.
	 */
	while (lp == v2_PROPOSAL_NON_LAST) {
		ipsec_spi_t spival;
		/*
		 * note: we don't support ESN,
		 * so ignore any proposal that insists on it
		 */

		if (!in_struct(&proposal, &ikev2_prop_desc, sa_pbs,
			       &proposal_pbs)) {
			loglog(RC_LOG_SERIOUS, "corrupted proposal");
			return STF_FAIL + v2N_INVALID_SYNTAX;
		}

		lp = proposal.isap_lp;

		if (selection) {
			/* must be only one proposal in a selection */
			if (lp == v2_PROPOSAL_NON_LAST) {
				libreswan_log("Error: more than one proposal received from responder.");
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}
		} else {
			/* if not a selection, proposals must be ordinally numbered */
			if (proposal.isap_propnum != nextpropnum) {
				loglog(RC_LOG_SERIOUS,
					"proposal number was %u but %u expected",
					proposal.isap_propnum,
					nextpropnum);
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}
			nextpropnum = proposal.isap_propnum + 1;
		}

		switch (proposal.isap_protoid) {
		case PROTO_ISAKMP:
			loglog(RC_LOG_SERIOUS,
			       "unexpected PARENT_SA, expected child");
			return STF_FAIL + v2N_INVALID_SYNTAX;

		case PROTO_IPSEC_ESP:
			proto_info = &st->st_esp;
			break;

		case PROTO_IPSEC_AH:
			proto_info = &st->st_ah;
			break;

		default:
			loglog(RC_LOG_SERIOUS,
			       "unexpected Protocol ID (%s) found in PARENT_SA Proposal",
			       enum_show(&protocol_names,
					 proposal.isap_protoid));
			return STF_FAIL + v2N_INVALID_SYNTAX;
		}

		if (proposal.isap_spisize != sizeof(proto_info->our_spi)) {
			loglog(RC_LOG_SERIOUS,
			       "invalid SPI size (%u) in CHILD_SA Proposal",
			       (unsigned)proposal.isap_spisize);
			return STF_FAIL + v2N_INVALID_SPI;
		}

		if (!in_raw(&spival, sizeof(proto_info->our_spi),
			    &proposal_pbs, "CHILD SA SPI")) {
			loglog(RC_LOG_SERIOUS,
				"Failed to read CHILD SA SPI");
			return STF_FAIL + v2N_INVALID_SYNTAX;
		}

		{
			stf_status ret = ikev2_process_transforms(&proposal,
								  &proposal_pbs,
								  &itl0);

			if (ret != STF_OK) {
				DBG(DBG_CONTROLMORE, DBG_log("ikev2_process_transforms() failed"));
				return ret;
			}
		}

		/* Note: only try to match if we haven't had one */
		if (!gotmatch &&
		    ikev2_match_transform_list_child(st->st_sadb,
						     proposal.isap_propnum,
						     proposal.isap_protoid,
						     &itl0)) {
			winning_prop = proposal;
			gotmatch = TRUE;

			/*
			 * record details of the winning transform now
			 * because itl0 will change with later matches
			 */
			ta.encrypt = itl0.encr_transforms[itl0.encr_i];
			ta.enckeylen = itl0.encr_keylens[itl0.encr_i] > 0 ?
				       itl0.encr_keylens[itl0.encr_i] : 0;
			ta.integ_hash = itl0.integ_transforms[itl0.integ_i];

			/* record peer's SPI value */
			proto_info->attrs.spi = spival;
		}
	}

	if (!gotmatch) {
		DBG(DBG_CONTROL, DBG_log("No CHILD proposal selected"));
		return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
	}

	/*
	 * since we found something that matched, we might need to emit the
	 * winning value.
	 */

	/* this is REALLY not correct, because this is not an IKE algorithm */
	/* XXX maybe we can leave this to ikev2 child key derivation */
	if (proposal.isap_protoid == PROTO_v2_ESP) {
		ta.encrypter = (struct encrypt_desc *)ikev2_alg_find(
			IKE_ALG_ENCRYPT,
			ta.encrypt);
		if (ta.encrypter != NULL) {
			err_t ugh;

			if (ta.enckeylen == 0)
				ta.enckeylen = ta.encrypter->keydeflen;
			ugh = check_kernel_encrypt_alg(ta.encrypt, ta.enckeylen);
			if (ugh != NULL) {
				libreswan_log("ESP algo %d with key_len %d is not valid (%s)", ta.encrypt, ta.enckeylen, ugh);
				return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
			}
		} else {
			/*
			 * We did not find a userspace encrypter, so we should
			 * be esp=null or a kernel-only algorithm without
			 * userland struct.
			 */
			switch(ta.encrypt) {
			case IKEv2_ENCR_NULL:
				break; /* ok */
			case IKEv2_ENCR_CAST:
				break; /* CAST is ESP only, not IKE */
			case IKEv2_ENCR_AES_CTR:
			case IKEv2_ENCR_CAMELLIA_CTR:
			case IKEv2_ENCR_CAMELLIA_CCM_A:
			case IKEv2_ENCR_CAMELLIA_CCM_B:
			case IKEv2_ENCR_CAMELLIA_CCM_C:
				/* no IKE struct encrypt_desc yet */
				/* FALL THROUGH */
			case IKEv2_ENCR_AES_CBC:
			case IKEv2_ENCR_CAMELLIA_CBC:
			case IKEv2_ENCR_CAMELLIA_CBC_ikev1: /* IANA ikev1/ipsec-v3 fixup */
				/* these all have mandatory key length attributes */
				if (ta.enckeylen == 0) {
					loglog(RC_LOG_SERIOUS, "Missing mandatory KEY_LENGTH attribute - refusing proposal");
					return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
				}
				break;
			default:
				loglog(RC_LOG_SERIOUS, "Did not find valid ESP encrypter for %d - refusing proposal", ta.encrypt);
				pexpect(ta.encrypt == IKEv2_ENCR_NULL); /* fire photon torpedo! */
				return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
			}
		}
	}

	/*
	 * this is really a mess having so many different numbers for auth
	 * algorithms.
	 */

	proto_info->attrs.transattrs = ta;
	/*
	 * here we obtain auth value for esp,
	 * but lose what is correct to be sent in the proposal
	 */
	proto_info->attrs.transattrs.integ_hash = alg_info_esp_v2tov1aa(ta.integ_hash);
	proto_info->present = TRUE;

	proto_info->attrs.encapsulation = ENCAPSULATION_MODE_TUNNEL;

	if (r_sa_pbs != NULL) {
		return ikev2_emit_winning_sa(st, r_sa_pbs,
					     ta,
					     /*parentSA*/ FALSE,
					     winning_prop);
	}

	DBG(DBG_CONTROLMORE, DBG_log("no winning proposal - parent ok but child is a problem"));
	return STF_OK;
}

stf_status ikev2_emit_ipsec_sa(struct msg_digest *md,
			       pb_stream *outpbs,
			       enum next_payload_types_ikev2 np,
			       struct connection *c,
			       lset_t policy)
{
	int proto;
	struct db_sa *p2alg;

	/* ??? this code won't support AH + ESP */
	if (c->policy & POLICY_ENCRYPT)
		proto = PROTO_v2_ESP;
	else if (c->policy & POLICY_AUTHENTICATE)
		proto = PROTO_v2_AH;
	else
		return STF_FATAL;

	p2alg = kernel_alg_makedb(policy, c->alg_info_esp, TRUE);

	sa_v2_convert(&p2alg);

	if (!ikev2_out_sa(outpbs, proto, p2alg, md->st, FALSE, np)) {
		free_sa(&p2alg);
		libreswan_log("ikev2_emit_ipsec_sa: ikev2_out_sa() failed");
		return STF_INTERNAL_ERROR;
	}
	free_sa(&p2alg);

	return STF_OK;
}
