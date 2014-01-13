/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
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
#include <libreswan/ipsec_policy.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "secrets.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "plutoalg.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"

#include "nat_traversal.h"

#ifdef HAVE_LABELED_IPSEC
#include "security_selinux.h"
#endif

#ifdef HAVE_LABELED_IPSEC
static bool parse_secctx_attr(pb_stream *pbs, struct state *st)
{
	/*supported length is 256 bytes (257 including \0)*/
	char sec_ctx_value[MAX_SECCTX_LEN];
	u_int8_t ctx_doi;
	u_int8_t ctx_alg;
	u_int16_t net_ctx_len, ctx_len;
	int i = 0;

	DBG(DBG_PARSING, DBG_log("received sec ctx"));

	/*doing sanity check*/
	if (pbs_left(pbs) <
	    (sizeof(ctx_doi) + sizeof(ctx_alg) + sizeof(ctx_len) + 1) ) {
		DBG(DBG_PARSING,
		    DBG_log("received perhaps corrupted security ctx (should not happen really)"));
		return FALSE;
	}

	/*reading ctx doi*/
	memcpy(&ctx_doi, pbs->cur, sizeof(ctx_doi));
	pbs->cur += sizeof(ctx_doi);

	/*reading ctx alg*/
	memcpy(&ctx_alg, pbs->cur, sizeof(ctx_alg));
	pbs->cur += sizeof(ctx_alg);

	/*reading ctx length*/
	memcpy(&net_ctx_len, pbs->cur, sizeof(ctx_len));
	pbs->cur += sizeof(ctx_len);
	ctx_len = ntohs(net_ctx_len);

	DBG(DBG_PARSING,
	    DBG_log("   received ctx_doi = %d, ctx_alg = %d, ctx_len = %d",
		    ctx_doi, ctx_alg, ctx_len));

	/* verifying remaining buffer length and ctx length matches or not (checking for any corruption)*/
	if (ctx_len != pbs_left(pbs) ) {
		DBG(DBG_PARSING,
		    DBG_log("received ctx length seems to be different than the length of string present in the buffer"));
		DBG(DBG_PARSING,
		    DBG_log("received ctx_len = %d, buffer left = %lu",
			    ctx_len,
			    pbs_left(pbs)));
		return FALSE;
	}

	/* do not process security labels longer than MAX_SECCTX_LEN */
	if (pbs_left(pbs) > MAX_SECCTX_LEN) {
		DBG(DBG_PARSING,
		    DBG_log("received security ctx longer than MAX_SECCTX_LEN which is not supported"));
		return FALSE;
	}

	/* reading security label*/
	memcpy(sec_ctx_value, pbs->cur, pbs_left(pbs));
	i = pbs_left(pbs);

	/*
	 * Checking if the received security label contains \0.
	 * We expect the received label to have '\0', however to be
	 * compliant with implementations that don't send \0
	 * we can add a \0 if there is space left in the buffer.
	 */

	if ( sec_ctx_value[i - 1] != '\0') {
		/*check if we have space left and then append \0*/
		if (i < MAX_SECCTX_LEN) {
			sec_ctx_value[i] = '\0';
			i = i + 1;
		} else {
			/*there is no space left*/
			DBG(DBG_PARSING,
			    DBG_log("received security label > MAX_SECCTX_LEN (should not happen really)"));
			return FALSE;
		}
	}

	/*
	   while (pbs_left(pbs) != 0){
	   sec_ctx_value[i++]= *pbs->cur++;
	    if(i == MAX_SECCTX_LEN){
	    DBG(DBG_PARSING, DBG_log("security label reached maximum length (MAX_SECCTX_LEN) allowed"));
	    break;
	    }
	   }

	   sec_ctx_value[i]='\0';
	 */
	DBG(DBG_PARSING,
	    DBG_log("   sec ctx value: %s, len=%d", sec_ctx_value, i));

	if (st->sec_ctx == NULL && st->st_state == STATE_QUICK_R0) {
		DBG_log("Receievd sec ctx in responder state");
		st->sec_ctx = alloc_thing(struct xfrm_user_sec_ctx_ike,
					  "struct xfrm_user_sec_ctx_ike");
		memcpy(st->sec_ctx->sec_ctx_value, sec_ctx_value, i);
		st->sec_ctx->ctx_len = i;
		st->sec_ctx->ctx_alg = ctx_alg;
		st->sec_ctx->ctx_doi = ctx_doi;

		/* lets verify if the received security label is within range of this connection's policy's security label*/
		if (!st->st_connection->labeled_ipsec) {
			DBG_log("This state (connection) is not labeled ipsec enabled, so can not proceed");
			return FALSE;
		} else if ( st->st_connection->policy_label != NULL &&
			    within_range(st->sec_ctx->sec_ctx_value,
					 st->st_connection->policy_label)) {
			DBG_log("security context verification succedded");
		} else {
			DBG_log("security context verification failed (perhaps policy_label is not confgured for this connection)");
			return FALSE;
		}

	} else if (st->st_state == STATE_QUICK_I1 ) {
		DBG(DBG_PARSING,
		    DBG_log("Initiator state received security context from responder state, now verifying if both are same"));
		if (streq(st->sec_ctx->sec_ctx_value, sec_ctx_value)) {
			DBG_log("security contexts are verified in the initiator state");
		} else {
			DBG_log("security context verification failed in the initiator state"
				"(shouldnt reach here unless responder (or something in between) is modifying the security context");
			return FALSE;
		}
	} else if (st->st_state == STATE_QUICK_R0) {
		DBG_log("Receievd sec ctx in responder state again, already stored it so doing nothing now");
	}
	return TRUE;
}
#endif

/** output an attribute (within an SA) */
static bool out_attr(int type,
	      unsigned long val,
	      struct_desc *attr_desc,
	      enum_names **attr_val_descs,
	      pb_stream *pbs)
{
	struct isakmp_attribute attr;

	if (val >> 16 == 0) {
		/* short value: use TV form */
		attr.isaat_af_type = type | ISAKMP_ATTR_AF_TV;
		attr.isaat_lv = val;
		if (!out_struct(&attr, attr_desc, pbs, NULL))
			return FALSE;
	} else {
		/* This is a real fudge!  Since we rarely use long attributes
		 * and since this is the only place where we can cause an
		 * ISAKMP message length to be other than a multiple of 4 octets,
		 * we force the length of the value to be a multiple of 4 octets.
		 * Furthermore, we only handle values up to 4 octets in length.
		 * Voila: a fixed format!
		 */
		pb_stream val_pbs;
		u_int32_t nval = htonl(val);

		attr.isaat_af_type = type | ISAKMP_ATTR_AF_TLV;
		if (!out_struct(&attr, attr_desc, pbs, &val_pbs) ||
		    !out_raw(&nval, sizeof(nval), &val_pbs,
			     "long attribute value"))
			return FALSE;

		close_output_pbs(&val_pbs);
	}
	DBG(DBG_EMITTING, {
		    enum_names *d = attr_val_descs[type];

		    if (d != NULL)
			    DBG_log("    [%lu is %s]",
				    val, enum_show(d, val));
	    });
	return TRUE;
}

#define return_on(var, val) do { var = val; goto return_out; } while (0);

/**
 * Output an SA, as described by a db_sa.
 * This has the side-effect of allocating SPIs for us.
 *
 */
bool out_sa(pb_stream *outs,
	    struct db_sa *sadb,
	    struct state *st,
	    bool oakley_mode,
	    bool aggressive_mode UNUSED,
	    u_int8_t np)
{
	pb_stream sa_pbs;
	unsigned int pcn;
	bool ret = FALSE;
	bool ah_spi_generated = FALSE,
	     esp_spi_generated = FALSE,
	     ipcomp_cpi_generated = FALSE;
	struct db_sa *revised_sadb;

	if (oakley_mode) {
		/* Aggr-Mode - Max transforms == 2 - Multiple transforms, 1 DH group */
		revised_sadb = oakley_alg_makedb(
			st->st_connection->alg_info_ike,
			sadb,
			aggressive_mode ? 2 : -1);
	} else {
		revised_sadb = kernel_alg_makedb(st->st_connection->policy,
						 st->st_connection->alg_info_esp,
						 TRUE);

		/* add IPcomp proposal if policy asks for it */

		if (revised_sadb && ((st->st_policy) & POLICY_COMPRESS)) {

			struct db_trans *ipcomp_trans = alloc_thing(
				struct db_trans, "ipcomp_trans");

			/* allocate space for 2 proposals */
			struct db_prop *ipcomp_prop =
				alloc_bytes( (sizeof(struct db_prop) * 2),
					     "ipcomp_prop");

			if (ipcomp_trans && ipcomp_prop) {

				passert(revised_sadb->prop_conjs->prop_cnt ==
					1);

				/* construct the IPcomp proposal  */
				ipcomp_trans->transid = IPCOMP_DEFLATE;
				ipcomp_trans->attrs = NULL;
				ipcomp_trans->attr_cnt = 0;

				/* copy the original proposal */
				ipcomp_prop[0].protoid   =
					revised_sadb->prop_conjs->props->
					protoid;
				ipcomp_prop[0].trans     =
					revised_sadb->prop_conjs->props->trans;
				ipcomp_prop[0].trans_cnt =
					revised_sadb->prop_conjs->props->
					trans_cnt;

				/* and add our IPcomp proposal */
				ipcomp_prop[1].protoid = PROTO_IPCOMP;
				ipcomp_prop[1].trans = ipcomp_trans;
				ipcomp_prop[1].trans_cnt = 1;

				/* free the old proposal, and ... */
				pfree(revised_sadb->prop_conjs->props);

				/* ... use our new one instead */
				revised_sadb->prop_conjs->props = ipcomp_prop;
				revised_sadb->prop_conjs->prop_cnt += 1;

			} else {
				/* couldn't alloc something, so skip adding the proposal */
				if (ipcomp_trans)
					pfreeany(ipcomp_trans);
				if (ipcomp_prop)
					pfreeany(ipcomp_prop);
			}
		}
	}

	/* more sanity */
	if (revised_sadb != NULL)
		sadb = revised_sadb;

	/* SA header out */
	{
		struct isakmp_sa sa;

		sa.isasa_np = np;
		st->st_doi = sa.isasa_doi = ISAKMP_DOI_IPSEC; /* all we know */
		if (!out_struct(&sa, &isakmp_sa_desc, outs, &sa_pbs))
			return_on(ret, FALSE);
	}

	/* within SA: situation out */
	st->st_situation = SIT_IDENTITY_ONLY;
	if (!out_struct(&st->st_situation, &ipsec_sit_desc, &sa_pbs, NULL))
		return_on(ret, FALSE);

	/* within SA: Proposal Payloads
	 *
	 * Multiple Proposals with the same number are simultaneous
	 * (conjuncts) and must deal with different protocols (AH or ESP).
	 * Proposals with different numbers are alternatives (disjuncts),
	 * in preference order.
	 * Proposal numbers must be monotonic.
	 * See RFC 2408 "ISAKMP" 4.2
	 */

	for (pcn = 0; pcn < sadb->prop_conj_cnt; pcn++) {
		struct db_prop_conj *pc;
		unsigned int pn;
		int valid_prop_cnt;

		pc = &sadb->prop_conjs[pcn];
		valid_prop_cnt = pc->prop_cnt;
		DBG(DBG_EMITTING,
		    DBG_log("out_sa pcn: %d has %d valid proposals",
			    pcn, valid_prop_cnt));

		for (pn = 0; pn < pc->prop_cnt; pn++) {
			struct db_prop *p;
			pb_stream proposal_pbs;
			struct isakmp_proposal proposal;
			struct_desc *trans_desc;
			struct_desc *attr_desc;
			enum_names **attr_val_descs;
			unsigned int tn;
			bool tunnel_mode;

			/*
			 * set the tunnel_mode bit on the last proposal only, and
			 * only if we are trying to negotiate tunnel mode in the first
			 * place.
			 */
			tunnel_mode = (valid_prop_cnt == 1) &&
				      (st->st_policy & POLICY_TUNNEL);

			/*
			 * pick the part of the proposal we are trying to work on
			 */
			p = &pc->props[pn];

			proposal.isap_proposal = pcn;
			proposal.isap_protoid = p->protoid;
			proposal.isap_spisize = oakley_mode ? 0 :
						p->protoid ==
						PROTO_IPCOMP ? IPCOMP_CPI_SIZE
						:
						IPSEC_DOI_SPI_SIZE;

			DBG(DBG_EMITTING,
			    DBG_log("out_sa pcn: %d pn: %d<%d valid_count: %d trans_cnt: %d",
				    pcn, pn, pc->prop_cnt, valid_prop_cnt,
				    p->trans_cnt));

			/* but, skip things if the transform count is zero */
			if (p->trans_cnt == 0)
				continue;

			/* Proposal header */
			if (--valid_prop_cnt > 0)
				proposal.isap_np = ISAKMP_NEXT_P;
			else
				proposal.isap_np = ISAKMP_NEXT_NONE;

			proposal.isap_notrans = p->trans_cnt;
			if (!out_struct(&proposal, &isakmp_proposal_desc,
					&sa_pbs, &proposal_pbs))
				return_on(ret, FALSE);

			/* Per-protocols stuff:
			 * Set trans_desc.
			 * Set attr_desc.
			 * Set attr_val_descs.
			 * If not oakley_mode, emit SPI.
			 * We allocate SPIs on demand.
			 * All ESPs in an SA will share a single SPI.
			 * All AHs in an SAwill share a single SPI.
			 * AHs' SPI will be distinct from ESPs'.
			 * This latter is needed because KLIPS doesn't
			 * use the protocol when looking up a (dest, protocol, spi).
			 * ??? If multiple ESPs are composed, how should their SPIs
			 * be allocated?
			 */
			{
				ipsec_spi_t *spi_ptr = NULL;
				int proto = 0;
				bool *spi_generated;

				spi_generated = NULL;

				switch (p->protoid) {
				case PROTO_ISAKMP:
					passert(oakley_mode);
					trans_desc =
						&isakmp_isakmp_transform_desc;
					attr_desc =
						&isakmp_oakley_attribute_desc;
					attr_val_descs = oakley_attr_val_descs;
					/* no SPI needed */
					break;

				case PROTO_IPSEC_AH:
					passert(!oakley_mode);
					trans_desc = &isakmp_ah_transform_desc;
					attr_desc =
						&isakmp_ipsec_attribute_desc;
					attr_val_descs = ipsec_attr_val_descs;
					spi_ptr = &st->st_ah.our_spi;
					spi_generated = &ah_spi_generated;
					proto = IPPROTO_AH;
					break;

				case PROTO_IPSEC_ESP:
					passert(!oakley_mode);
					trans_desc =
						&isakmp_esp_transform_desc;
					attr_desc =
						&isakmp_ipsec_attribute_desc;
					attr_val_descs = ipsec_attr_val_descs;
					spi_ptr = &st->st_esp.our_spi;
					spi_generated = &esp_spi_generated;
					proto = IPPROTO_ESP;
					break;

				case PROTO_IPCOMP:
					passert(!oakley_mode);
					trans_desc =
						&isakmp_ipcomp_transform_desc;
					attr_desc =
						&isakmp_ipsec_attribute_desc;
					attr_val_descs = ipsec_attr_val_descs;

					/* a CPI isn't quite the same as an SPI
					 * so we use specialized code to emit it.
					 */
					if (!ipcomp_cpi_generated) {
						st->st_ipcomp.our_spi =
							get_my_cpi(
								&st->st_connection->spd,
								tunnel_mode);
						if (st->st_ipcomp.our_spi == 0)
							return_on(ret, FALSE); /* problem generating CPI */

						ipcomp_cpi_generated = TRUE;
					}
					/* CPI is stored in network low order end of an
					 * ipsec_spi_t.  So we start a couple of bytes in.
					 */
					if (!out_raw((u_char *)&st->st_ipcomp.
						     our_spi +
						     IPSEC_DOI_SPI_SIZE -
						     IPCOMP_CPI_SIZE,
						     IPCOMP_CPI_SIZE,
						     &proposal_pbs, "CPI"))
						return_on(ret, FALSE);
					break;

				default:
					bad_case(p->protoid);
				}

				if (spi_ptr != NULL) {
					if (spi_generated != NULL &&
					    !*spi_generated) {
						*spi_ptr = get_ipsec_spi(0,
									 proto,
									 &st->st_connection->spd,
									 tunnel_mode);
						if (*spi_ptr == 0)
							return FALSE;

						*spi_generated = TRUE;
					}
					if (!out_raw((u_char *)spi_ptr,
						     IPSEC_DOI_SPI_SIZE,
						     &proposal_pbs, "SPI"))
						return_on(ret, FALSE);
				}
			}

			/* within proposal: Transform Payloads */
			for (tn = 0; tn != p->trans_cnt; tn++) {
				struct db_trans *t = &p->trans[tn];
				pb_stream trans_pbs;
				struct isakmp_transform trans;
				unsigned int an;

				trans.isat_np = (tn == p->trans_cnt - 1) ?
						ISAKMP_NEXT_NONE :
						ISAKMP_NEXT_T;
				trans.isat_transnum = tn;
				trans.isat_transid = t->transid;
				if (!out_struct(&trans, trans_desc,
						&proposal_pbs, &trans_pbs))
					return_on(ret, FALSE);

				/* Within tranform: Attributes. */

				/* For Phase 2 / Quick Mode, GROUP_DESCRIPTION is
				 * automatically generated because it must be the same
				 * in every transform.  Except IPCOMP.
				 */
				if (p->protoid != PROTO_IPCOMP &&
				    st->st_pfs_group != NULL) {
					passert(!oakley_mode);
					passert(st->st_pfs_group !=
						&unset_group);
					if (!out_attr(GROUP_DESCRIPTION,
						      st->st_pfs_group->group,
						      attr_desc,
						      attr_val_descs,
						      &trans_pbs))
						return_on(ret, FALSE);
				}

				/* automatically generate duration
				 * and, for Phase 2 / Quick Mode, encapsulation.
				 */
				if (oakley_mode) {
					if (!out_attr(OAKLEY_LIFE_TYPE,
						      OAKLEY_LIFE_SECONDS,
						      attr_desc,
						      attr_val_descs,
						      &trans_pbs))
						return_on(ret, FALSE);
					if (!out_attr(OAKLEY_LIFE_DURATION,
						      st->st_connection->
						      sa_ike_life_seconds,
						      attr_desc,
						      attr_val_descs,
						      &trans_pbs))
						return_on(ret, FALSE);
				} else {
					/* RFC 2407 (IPSEC DOI) 4.5 specifies that
					 * the default is "unspecified (host-dependent)".
					 * This makes little sense, so we always specify it.
					 *
					 * Unlike other IPSEC transforms, IPCOMP defaults
					 * to Transport Mode, so we can exploit the default
					 * (draft-shacham-ippcp-rfc2393bis-05.txt 4.1).
					 */
					if (p->protoid != PROTO_IPCOMP ||
					    st->st_policy & POLICY_TUNNEL) {
						if (!out_attr(
							    ENCAPSULATION_MODE,
							    NAT_T_ENCAPSULATION_MODE(
								    st,
								    st
								    ->st_policy)
							    , attr_desc,
							    attr_val_descs,
							    &trans_pbs))
							return_on(ret, FALSE);
					}
					if (!out_attr(SA_LIFE_TYPE,
						      SA_LIFE_TYPE_SECONDS,
						      attr_desc,
						      attr_val_descs,
						      &trans_pbs))
						return_on(ret, FALSE);
					if (!out_attr(SA_LIFE_DURATION,
						      st->st_connection->
						      sa_ipsec_life_seconds,
						      attr_desc,
						      attr_val_descs,
						      &trans_pbs))
						return_on(ret, FALSE);

#ifdef HAVE_LABELED_IPSEC
					if (st->sec_ctx != NULL &&
					    st->st_connection->labeled_ipsec) {
						struct isakmp_attribute attr;
						pb_stream val_pbs;
						attr.isaat_af_type =
							secctx_attr_value |
							ISAKMP_ATTR_AF_TLV;
						DBG(DBG_EMITTING,
						    DBG_log("secctx_attr_value=%d, type=%d",
							    secctx_attr_value,
							    attr.isaat_af_type));
						if (!out_struct(&attr,
								attr_desc,
								&trans_pbs,
								&val_pbs))
							return_on(ret, FALSE);
						DBG(DBG_EMITTING,
						    DBG_log("placing security context attribute in the out going structure"));
						DBG(DBG_EMITTING,
						    DBG_log("sending ctx_doi"));
						if (!out_raw(&st->sec_ctx->
							     ctx_doi,
							     sizeof(st->sec_ctx
								    ->ctx_doi),
							     &val_pbs,
							     " variable length sec ctx: ctx_doi"))
							return_on(ret, FALSE);
						DBG(DBG_EMITTING,
						    DBG_log("sending ctx_alg"));
						if (!out_raw(&st->sec_ctx->
							     ctx_alg,
							     sizeof(st->sec_ctx
								    ->ctx_alg),
							     &val_pbs,
							     " variable length sec ctx: ctx_alg"))
							return_on(ret, FALSE);
						DBG(DBG_EMITTING,
						    DBG_log("sending ctx_len after conversion to network byte order"));
						u_int16_t net_ctx_len = htons(st->sec_ctx->ctx_len);
						if (!out_raw(&net_ctx_len,
							     sizeof(st->sec_ctx
								    ->ctx_len),
							     &val_pbs,
							     " variable length sec ctx: ctx_len"))
							return_on(ret, FALSE);
						/*Sending '\0'  with sec ctx as we get it from kernel*/
						if (!out_raw(st->sec_ctx->
							     sec_ctx_value,
							     st->sec_ctx->
							     ctx_len, &val_pbs,
							     " variable length sec ctx"))
							return_on(ret, FALSE);
						DBG(DBG_EMITTING,
						    DBG_log("placed security context attribute in the out going structure"));
						close_output_pbs(&val_pbs);
						DBG(DBG_EMITTING,
						    DBG_log("end of security context attribute in the out going structure"));
					}
#endif

				}

				/* spit out attributes from table */
				for (an = 0; an != t->attr_cnt; an++) {
					struct db_attr *a = &t->attrs[an];

					if (oakley_mode) {
						if (!out_attr(a->type.oakley,
							      a->val,
							      attr_desc,
							      attr_val_descs,
							      &trans_pbs))
							return_on(ret, FALSE);
					} else {
						if (!out_attr(a->type.ipsec,
							      a->val,
							      attr_desc,
							      attr_val_descs,
							      &trans_pbs))
							return_on(ret, FALSE);

					}

				}

				close_output_pbs(&trans_pbs);
			}
			close_output_pbs(&proposal_pbs);
		}
		/* end of a conjunction of proposals */
	}
	close_output_pbs(&sa_pbs);
	ret = TRUE;

return_out:

	if (revised_sadb)
		free_sa(revised_sadb);
	return ret;
}

/** Handle long form of duration attribute.
 * The code is can only handle values that can fit in unsigned long.
 * "Clamping" is probably an acceptable way to impose this limitation.
 *
 * @param pbs PB Stream
 * @return u_int32_t duration, in seconds.
 */
static u_int32_t decode_long_duration(pb_stream *pbs)
{
	u_int32_t val = 0;

	/* ignore leading zeros */
	while (pbs_left(pbs) != 0 && *pbs->cur == '\0')
		pbs->cur++;

	if (pbs_left(pbs) > sizeof(val)) {
		/* "clamp" too large value to max representable value */
		val -= 1; /* portable way to get to maximum value */
		DBG(DBG_PARSING,
		    DBG_log("   too large duration clamped to: %lu",
			    (unsigned long)val));
	} else {
		/* decode number */
		while (pbs_left(pbs) != 0)
			val = (val << BITS_PER_BYTE) | *pbs->cur++;
		DBG(DBG_PARSING,
		    DBG_log("   long duration: %lu", (unsigned long)val));
	}
	return val;
}

/* Preparse the body of an ISAKMP SA Payload and find which policy is required
 * to match the packet. Errors are just ignored and will be detected and
 * handled later in parse_isakmp_sa_body().
 *
 * All we want for the moment is to know whether peer is using RSA or PSK.
 */
lset_t preparse_isakmp_sa_body(pb_stream *sa_pbs)
{
	pb_stream proposal_pbs;
	struct isakmp_proposal proposal;
	pb_stream trans_pbs;
	struct isakmp_transform trans;
	struct isakmp_attribute a;
	pb_stream attr_pbs;
	u_int32_t ipsecdoisit;
	unsigned trans_left;
	lset_t policy = 0;

	if (!in_struct(&ipsecdoisit, &ipsec_sit_desc, sa_pbs, NULL))
		return LEMPTY;

	if (!in_struct(&proposal, &isakmp_proposal_desc, sa_pbs,
		       &proposal_pbs))
		return LEMPTY;

	if (proposal.isap_spisize > MAX_ISAKMP_SPI_SIZE)
		return LEMPTY;

	if (proposal.isap_spisize > 0) {
		u_char junk_spi[MAX_ISAKMP_SPI_SIZE];

		if (!in_raw(junk_spi, proposal.isap_spisize, &proposal_pbs,
			    "Oakley SPI"))
			return LEMPTY;
	}

	trans_left = proposal.isap_notrans;
	while (trans_left--) {
		if (!in_struct(&trans, &isakmp_isakmp_transform_desc,
			       &proposal_pbs,
			       &trans_pbs))
			return LEMPTY;

		while (pbs_left(&trans_pbs) != 0) {
			if (!in_struct(&a, &isakmp_oakley_attribute_desc,
				       &trans_pbs,
				       &attr_pbs))
				return LEMPTY;

			switch (a.isaat_af_type) {
			case OAKLEY_AUTHENTICATION_METHOD | ISAKMP_ATTR_AF_TV:
				switch (a.isaat_lv) {
				case XAUTHInitPreShared:
					policy |= POLICY_XAUTH;
				case OAKLEY_PRESHARED_KEY:
					policy |= POLICY_PSK;
					break;
				case XAUTHInitRSA:
					policy |= POLICY_XAUTH;
				case OAKLEY_RSA_SIG:
					policy |= POLICY_RSASIG;
					break;
				}
				break;
			}
		}
	}

	if ((policy & POLICY_PSK) && (policy & POLICY_RSASIG))
		policy &= ~(POLICY_PSK | POLICY_RSASIG);

	return policy;
}

/**
 * Parse the body of an ISAKMP SA Payload (i.e. Phase 1 / Main Mode).
 * Various shortcuts are taken.  In particular, the policy, such as
 * it is, is hardwired.
 *
 * If r_sa is non-NULL, the body of an SA representing the selected
 * proposal is emitted.
 *
 * If "selection" is true, the SA is supposed to represent the
 * single tranform that the peer has accepted.
 * ??? We only check that it is acceptable, not that it is one that we offered!
 *
 * It also means that we are inR1, and this as implications when we are
 * doing XAUTH, as it changes the meaning of the XAUTHInit/XAUTHResp.
 *
 * Only IPsec DOI is accepted (what is the ISAKMP DOI?).
 * Error response is rudimentary.
 *
 * This routine is used by main_inI1_outR1() and main_inR1_outI2().
 */
notification_t parse_isakmp_sa_body(pb_stream *sa_pbs,          /* body of input SA Payload */
				    const struct isakmp_sa *sa, /* header of input SA Payload */
				    pb_stream *r_sa_pbs,        /* if non-NULL, where to emit winning SA */
				    bool selection,             /* if this SA is a selection, only one tranform
                                                                 * can appear. */
				    struct state *st)           /* current state object */
{
	u_int32_t ipsecdoisit;
	pb_stream proposal_pbs;
	struct isakmp_proposal proposal;
	unsigned no_trans_left;
	int last_transnum;
	struct connection *c = st->st_connection;
	struct spd_route *spd, *me = &c->spd;
	bool xauth_init, xauth_resp;
	const char *role;

	role = "";

	xauth_init = xauth_resp = FALSE;

	/* calculate the per-end policy which might apply */
	for (spd = me; spd; spd = spd->next) {
		if (selection) { /* this is the initiator, we have proposed, they have answered,
			          * and we must decide if they proposed what we wanted.
			          */
			role = "initiator";
			xauth_init |= spd->this.xauth_client;
			xauth_resp |= spd->this.xauth_server;
		} else { /* this is the responder, they have proposed to us, what
			  * are we willing to be?
			  */
			role = "responder";
			xauth_init = xauth_init | spd->this.xauth_server;
			xauth_resp = xauth_resp | spd->this.xauth_client;
		}
	}

	/* DOI */
	if (sa->isasa_doi != ISAKMP_DOI_IPSEC) {
		loglog(RC_LOG_SERIOUS, "Unknown/unsupported DOI %s",
		       enum_show(&doi_names, sa->isasa_doi));
		/* XXX Could send notification back */
		return DOI_NOT_SUPPORTED;
	}

	/* Situation */
	if (!in_struct(&ipsecdoisit, &ipsec_sit_desc, sa_pbs, NULL))
		return SITUATION_NOT_SUPPORTED;

	if (ipsecdoisit != SIT_IDENTITY_ONLY) {
		loglog(RC_LOG_SERIOUS, "unsupported IPsec DOI situation (%s)",
		       bitnamesof(sit_bit_names, ipsecdoisit));
		/* XXX Could send notification back */
		return SITUATION_NOT_SUPPORTED;
	}

	/* The rules for ISAKMP SAs are scattered.
	 * RFC 2409 "IKE" section 5 says that there
	 * can only be one SA, and it can have only one proposal in it.
	 * There may well be multiple transforms.
	 */
	if (!in_struct(&proposal, &isakmp_proposal_desc, sa_pbs,
		       &proposal_pbs))
		return PAYLOAD_MALFORMED;

	if (proposal.isap_np != ISAKMP_NEXT_NONE) {
		loglog(RC_LOG_SERIOUS,
		       "Proposal Payload must be alone in Oakley SA; found %s following Proposal",
		       enum_show(&payload_names_ikev1, proposal.isap_np));
		return PAYLOAD_MALFORMED;
	}

	if (proposal.isap_protoid != PROTO_ISAKMP) {
		loglog(RC_LOG_SERIOUS,
		       "unexpected Protocol ID (%s) found in Oakley Proposal",
		       enum_show(&protocol_names, proposal.isap_protoid));
		return INVALID_PROTOCOL_ID;
	}

	/* Just what should we accept for the SPI field?
	 * The RFC is sort of contradictory.  We will ignore the SPI
	 * as long as it is of the proper size.
	 *
	 * From RFC2408 2.4 Identifying Security Associations:
	 *   During phase 1 negotiations, the initiator and responder cookies
	 *   determine the ISAKMP SA. Therefore, the SPI field in the Proposal
	 *   payload is redundant and MAY be set to 0 or it MAY contain the
	 *   transmitting entity's cookie.
	 *
	 * From RFC2408 3.5 Proposal Payload:
	 *    o  SPI Size (1 octet) - Length in octets of the SPI as defined by
	 *       the Protocol-Id.  In the case of ISAKMP, the Initiator and
	 *       Responder cookie pair from the ISAKMP Header is the ISAKMP SPI,
	 *       therefore, the SPI Size is irrelevant and MAY be from zero (0) to
	 *       sixteen (16).  If the SPI Size is non-zero, the content of the
	 *       SPI field MUST be ignored.  If the SPI Size is not a multiple of
	 *       4 octets it will have some impact on the SPI field and the
	 *       alignment of all payloads in the message.  The Domain of
	 *       Interpretation (DOI) will dictate the SPI Size for other
	 *       protocols.
	 */
	if (proposal.isap_spisize == 0) {
		/* empty (0) SPI -- fine */
	} else if (proposal.isap_spisize <= MAX_ISAKMP_SPI_SIZE) {
		u_char junk_spi[MAX_ISAKMP_SPI_SIZE];

		if (!in_raw(junk_spi, proposal.isap_spisize, &proposal_pbs,
			    "Oakley SPI"))
			return PAYLOAD_MALFORMED;
	} else {
		loglog(RC_LOG_SERIOUS,
		       "invalid SPI size (%u) in Oakley Proposal",
		       (unsigned)proposal.isap_spisize);
		return INVALID_SPI;
	}

	if (selection && proposal.isap_notrans != 1) {
		loglog(RC_LOG_SERIOUS,
		       "a single Transform is required in a selecting Oakley Proposal; found %u",
		       (unsigned)proposal.isap_notrans);
		return BAD_PROPOSAL_SYNTAX;
	}

	/* for each transform payload... */

	last_transnum = -1;
	no_trans_left = proposal.isap_notrans;
	for (;; ) {
		pb_stream trans_pbs;
		u_char *attr_start;
		size_t attr_len;
		struct isakmp_transform trans;
		lset_t seen_attrs = 0,
		       seen_durations = 0;
		u_int16_t life_type;
		struct trans_attrs ta;
		err_t ugh = NULL;       /* set to diagnostic when problem detected */
		char ugh_buf[256];      /* room for building a diagnostic */
		zero(&ta);

		life_type = 0;

		/* initialize only optional field in ta */
		ta.life_seconds = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT; /* When this SA expires (seconds) */

		if (no_trans_left == 0) {
			loglog(RC_LOG_SERIOUS,
			       "number of Transform Payloads disagrees with Oakley Proposal Payload");
			return BAD_PROPOSAL_SYNTAX;
		}

		if (!in_struct(&trans, &isakmp_isakmp_transform_desc,
			       &proposal_pbs, &trans_pbs))
			return BAD_PROPOSAL_SYNTAX;

		if (trans.isat_transnum <= last_transnum) {
			/* picky, picky, picky */
			loglog(RC_LOG_SERIOUS, "Transform Numbers are not monotonically increasing"
			       " in Oakley Proposal");
			return BAD_PROPOSAL_SYNTAX;
		}
		last_transnum = trans.isat_transnum;

		if (trans.isat_transid != KEY_IKE) {
			loglog(RC_LOG_SERIOUS,
			       "expected KEY_IKE but found %s in Oakley Transform",
			       enum_show(&isakmp_transformid_names,
					 trans.isat_transid));
			return INVALID_TRANSFORM_ID;
		}

		attr_start = trans_pbs.cur;
		attr_len = pbs_left(&trans_pbs);

		/* process all the attributes that make up the transform */

		while (pbs_left(&trans_pbs) != 0) {
			struct isakmp_attribute a;
			pb_stream attr_pbs;
			u_int32_t val; /* room for larger values */

			if (!in_struct(&a, &isakmp_oakley_attribute_desc,
				       &trans_pbs, &attr_pbs))
				return BAD_PROPOSAL_SYNTAX;

			passert((a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK) <
				LELEM_ROOF);

			if (LHAS(seen_attrs, a.isaat_af_type &
				 ISAKMP_ATTR_RTYPE_MASK)) {
				loglog(RC_LOG_SERIOUS,
				       "repeated %s attribute in Oakley Transform %u",
				       enum_show(&oakley_attr_names,
						 a.isaat_af_type),
				       trans.isat_transnum);
				return BAD_PROPOSAL_SYNTAX;
			}

			seen_attrs |= LELEM(
				a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);

			val = a.isaat_lv;

			DBG(DBG_PARSING,
			    {
				    enum_names *vdesc = oakley_attr_val_descs
							[a.isaat_af_type &
							 ISAKMP_ATTR_RTYPE_MASK];

				    if (vdesc != NULL) {
					    const char *nm =
						    enum_name(vdesc,
							      val);

					    if (nm != NULL) {
						    DBG_log("   [%u is %s]",
							    (unsigned)val,
							    nm);
					    }
				    }
			    });

			switch (a.isaat_af_type) {
			case OAKLEY_ENCRYPTION_ALGORITHM | ISAKMP_ATTR_AF_TV:
				if (ike_alg_enc_ok(val, 0, c->alg_info_ike,
						   &ugh, ugh_buf,
						   sizeof(ugh_buf))) {
					/* if (ike_alg_enc_present(val)) { */
					ta.encrypt = val;
					ta.encrypter =
						crypto_get_encrypter(val);
					ta.enckeylen = ta.encrypter->keydeflen;
				} else
				switch (val) {
				case OAKLEY_3DES_CBC:
					ta.encrypt = val;
					ta.encrypter =
						crypto_get_encrypter(val);
					break;

				case OAKLEY_DES_CBC:
					libreswan_log("1DES is not encryption");
				/* FALL THROUGH */
				default:
					ugh = builddiag("%s is not supported",
							enum_show(&oakley_enc_names,
								  val));
				}
				break;

			case OAKLEY_HASH_ALGORITHM | ISAKMP_ATTR_AF_TV:
				if (ike_alg_hash_present(val)) {
					ta.prf_hash = val;
					ta.prf_hasher = crypto_get_hasher(val);
				} else
/* #else */
				switch (val) {
				case OAKLEY_MD5:
				case OAKLEY_SHA1:
					ta.prf_hash = val;
					ta.prf_hasher = crypto_get_hasher(val);
					break;
				default:
					ugh = builddiag("%s is not supported",
							enum_show(&oakley_hash_names,
								  val));
				}
/* #endif */
				break;

			case OAKLEY_AUTHENTICATION_METHOD | ISAKMP_ATTR_AF_TV:
			{
				lset_t iap = st->st_policy &
					     POLICY_ID_AUTH_MASK;

				/* check that authentication method is acceptable */
				switch (val) {
				case XAUTHInitPreShared:
					if (!xauth_init) {
						ugh = builddiag(
							"policy does not allow Extended Authentication (XAUTH) of initiator (we are %s)",
							role);
						break;
					}
					ta.doing_xauth = TRUE;
					goto psk_common;

				case XAUTHRespPreShared:
					if (!xauth_resp) {
						ugh = builddiag(
							"policy does not allow Extended Authentication (XAUTH) of responder (we are %s)",
							role);
						break;
					}
					ta.doing_xauth = TRUE;
					goto psk_common;

				case OAKLEY_PRESHARED_KEY:
					if (xauth_init) {
						ugh = builddiag(
							"policy mandates Extended Authentication (XAUTH) with PSK of initiator (we are %s)",
							role);
						break;
					}
					if (xauth_resp) {
						ugh = builddiag(
							"policy mandates Extended Authentication (XAUTH) with PSK of responder (we are %s)",
							role);
						break;
					}
psk_common:

					if ((iap & POLICY_PSK) == LEMPTY) {
						ugh = "policy does not allow OAKLEY_PRESHARED_KEY authentication";
					} else {
						/* check that we can find a preshared secret */
						struct connection *con =
							st->st_connection;

						if (get_preshared_secret(con)
						    == NULL)
						{
							char mid[IDTOA_BUF],
							     hid[IDTOA_BUF];

							idtoa(&con->spd.this.id, mid,
							      sizeof(mid));
							if (his_id_was_instantiated(
									con))
							{
								strcpy(hid,
								       "%any");
							} else {
								idtoa(&con->spd.that.id, hid,
								      sizeof(hid));
							}

							ugh = builddiag(
								"Can't authenticate: no preshared key found for `%s' and `%s'",
								mid, hid);
						}
						ta.auth = OAKLEY_PRESHARED_KEY;
					}
					break;

				case XAUTHInitRSA:
					if (!xauth_init) {
						ugh = builddiag(
							"policy does not allow Extended Authentication (XAUTH) with RSA of initiator (we are %s)",
							role);
						break;
					}
					ta.doing_xauth = TRUE;
					goto rsasig_common;

				case XAUTHRespRSA:
					if (!xauth_resp) {
						ugh = builddiag(
							"policy does not allow Extended Authentication (XAUTH) with RSA of responder (we are %s)",
							role);
						break;
					}
					ta.doing_xauth = TRUE;
					goto rsasig_common;

				case OAKLEY_RSA_SIG:
					if (xauth_init) {
						ugh = builddiag(
							"policy mandates Extended Authentication (XAUTH) with RSA of initiator (we are %s)",
							role);
						break;
					}
					if (xauth_resp) {
						ugh = builddiag(
							"policy mandates Extended Authentication (XAUTH) with RSA of responder (we are %s)",
							role);
						break;
					}
rsasig_common:
					/* Accept if policy specifies RSASIG or is default */
					if ((iap & POLICY_RSASIG) == LEMPTY) {
						ugh = "policy does not allow OAKLEY_RSA_SIG authentication";
					} else {
						/* We'd like to check that we can find a public
						 * key for him and a private key for us that is
						 * suitable, but we don't yet have his
						 * Id Payload, so it seems futile to try.
						 * We can assume that if he proposes it, he
						 * thinks we've got it.  If we proposed it,
						 * perhaps we know what we're doing.
						 */
						ta.auth = OAKLEY_RSA_SIG;
					}
					break;

				default:
					ugh = builddiag(
						"Pluto does not support %s authentication",
						enum_show(&oakley_auth_names,
							  val));
					break;
				}
			}
			break;

			case OAKLEY_GROUP_DESCRIPTION | ISAKMP_ATTR_AF_TV:
				ta.group = lookup_group(val);
				if (ta.group == NULL) {
					ugh = builddiag(
						"OAKLEY_GROUP %d not supported",
						val);
					break;
				}
				break;

			case OAKLEY_LIFE_TYPE | ISAKMP_ATTR_AF_TV:
				switch (val) {
				case OAKLEY_LIFE_SECONDS:
				case OAKLEY_LIFE_KILOBYTES:
					if (LHAS(seen_durations, val)) {
						loglog(RC_LOG_SERIOUS,
						       "attribute OAKLEY_LIFE_TYPE value %s repeated",
						       enum_show(&oakley_lifetime_names,
								 val));
						return BAD_PROPOSAL_SYNTAX;
					}
					seen_durations |= LELEM(val);
					life_type = val;
					break;
				default:
					ugh = builddiag("unknown value %s",
							enum_show(&oakley_lifetime_names,
								  val));
					break;
				}
				break;

			case OAKLEY_LIFE_DURATION | ISAKMP_ATTR_AF_TLV:
				val = decode_long_duration(&attr_pbs);
			/* fall through */
			case OAKLEY_LIFE_DURATION | ISAKMP_ATTR_AF_TV:
				if (!LHAS(seen_attrs, OAKLEY_LIFE_TYPE)) {
					ugh =
						"OAKLEY_LIFE_DURATION attribute not preceded by OAKLEY_LIFE_TYPE attribute";
					break;
				}
				seen_attrs &=
					~(LELEM(OAKLEY_LIFE_DURATION) |
					  LELEM(OAKLEY_LIFE_TYPE));

				switch (life_type) {
				case OAKLEY_LIFE_SECONDS:
					if (val >
					    OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM)
					{
						ugh = builddiag("peer requested %lu seconds"
								" which exceeds our limit %d seconds",
								(long) val,
								OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM);
					}
					ta.life_seconds = val;
					break;
				case OAKLEY_LIFE_KILOBYTES:
					ta.life_kilobytes = val;
					break;
				default:
					bad_case(life_type);
				}
				break;

			case OAKLEY_KEY_LENGTH | ISAKMP_ATTR_AF_TV:
				if ((seen_attrs &
				     LELEM(OAKLEY_ENCRYPTION_ALGORITHM)) ==
				    0) {
					ugh =
						"OAKLEY_KEY_LENGTH attribute not preceded by OAKLEY_ENCRYPTION_ALGORITHM attribute";
					break;
				}
				if (ta.encrypter == NULL) {
					ugh =
						"NULL encrypter with seen OAKLEY_ENCRYPTION_ALGORITHM";
					break;
				}
				/*
				 * check if this keylen is compatible with
				 * specified alg_info_ike
				 */
				if (!ike_alg_enc_ok(ta.encrypt, val,
						    c->alg_info_ike, NULL,
						    ugh_buf,
						    sizeof(ugh_buf)))
					ugh =
						"peer proposed key_len not valid for encrypt algo setup specified";


				ta.enckeylen = val;
				break;
#if 0                           /* not yet supported */
			case OAKLEY_GROUP_TYPE | ISAKMP_ATTR_AF_TV:
			case OAKLEY_PRF | ISAKMP_ATTR_AF_TV:
			case OAKLEY_FIELD_SIZE | ISAKMP_ATTR_AF_TV:

			case OAKLEY_GROUP_PRIME | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_PRIME | ISAKMP_ATTR_AF_TLV:
			case OAKLEY_GROUP_GENERATOR_ONE | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_GENERATOR_ONE | ISAKMP_ATTR_AF_TLV:
			case OAKLEY_GROUP_GENERATOR_TWO | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_GENERATOR_TWO | ISAKMP_ATTR_AF_TLV:
			case OAKLEY_GROUP_CURVE_A | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_CURVE_A | ISAKMP_ATTR_AF_TLV:
			case OAKLEY_GROUP_CURVE_B | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_CURVE_B | ISAKMP_ATTR_AF_TLV:
			case OAKLEY_GROUP_ORDER | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_ORDER | ISAKMP_ATTR_AF_TLV:
#endif
			default:
				ugh = "unsupported OAKLEY attribute";
				break;
			}

			if (ugh != NULL) {
				loglog(RC_LOG_SERIOUS, "%s.  Attribute %s",
				       ugh,
				       enum_show(&oakley_attr_names,
						 a.isaat_af_type));
				break;
			}
		}

		/*
		 * ML: at last check for allowed transforms in alg_info_ike
		 */
		if (ugh == NULL) {
			if (!ike_alg_ok_final(ta.encrypt, ta.enckeylen,
					      ta.prf_hash,
					      ta.group ? ta.group->group :
					      65535, c->alg_info_ike))
				ugh = "OAKLEY proposal refused";
		}

		if (ugh == NULL) {
			/* a little more checking is in order */
			{
				lset_t missing =
					~seen_attrs &
					(LELEM(OAKLEY_ENCRYPTION_ALGORITHM) |
					 LELEM(OAKLEY_HASH_ALGORITHM) |
					 LELEM(OAKLEY_AUTHENTICATION_METHOD) |
					 LELEM(OAKLEY_GROUP_DESCRIPTION));

				if (missing) {
					loglog(RC_LOG_SERIOUS,
					       "missing mandatory attribute(s) %s in Oakley Transform %u",
					       bitnamesof(oakley_attr_bit_names,
							  missing),
					       trans.isat_transnum);
					return BAD_PROPOSAL_SYNTAX;
				}
			}
			/* We must have liked this transform.
			 * Lets finish early and leave.
			 */

			DBG(DBG_PARSING | DBG_CRYPT,
			    DBG_log("Oakley Transform %u accepted",
				    trans.isat_transnum));

			if (r_sa_pbs != NULL) {
				struct isakmp_proposal r_proposal = proposal;
				pb_stream r_proposal_pbs;
				struct isakmp_transform r_trans = trans;
				pb_stream r_trans_pbs;

				/* Situation */
				if (!out_struct(&ipsecdoisit, &ipsec_sit_desc,
						r_sa_pbs, NULL))
					impossible();

				/* Proposal */
#ifdef EMIT_ISAKMP_SPI
				r_proposal.isap_spisize = COOKIE_SIZE;
#else
				r_proposal.isap_spisize = 0;
#endif
				r_proposal.isap_notrans = 1;
				if (!out_struct(&r_proposal,
						&isakmp_proposal_desc,
						r_sa_pbs,
						&r_proposal_pbs))
					impossible();

				/* SPI */
#ifdef EMIT_ISAKMP_SPI
				if (!out_raw(my_cookie, COOKIE_SIZE,
					     &r_proposal_pbs, "SPI"))
					impossible();
				r_proposal.isap_spisize = COOKIE_SIZE;
#else
				/* none (0) */
#endif

				/* Transform */
				r_trans.isat_np = ISAKMP_NEXT_NONE;
				if (!out_struct(&r_trans,
						&isakmp_isakmp_transform_desc,
						&r_proposal_pbs,
						&r_trans_pbs))
					impossible();

				if (!out_raw(attr_start, attr_len,
					     &r_trans_pbs, "attributes"))
					impossible();
				close_output_pbs(&r_trans_pbs);
				close_output_pbs(&r_proposal_pbs);
				close_output_pbs(r_sa_pbs);
			}

			/* ??? If selection, we used to save the proposal in state.
			 * We never used it.  From proposal_pbs.start,
			 * length pbs_room(&proposal_pbs)
			 */

			/* copy over the results */
			st->st_oakley = ta;
			return NOTHING_WRONG;
		}

		/* on to next transform */
		no_trans_left--;

		if (trans.isat_np == ISAKMP_NEXT_NONE) {
			if (no_trans_left != 0) {
				loglog(RC_LOG_SERIOUS,
				       "number of Transform Payloads disagrees with Oakley Proposal Payload");
				return BAD_PROPOSAL_SYNTAX;
			}
			break;
		}
		if (trans.isat_np != ISAKMP_NEXT_T) {
			loglog(RC_LOG_SERIOUS,
			       "unexpected %s payload in Oakley Proposal",
			       enum_show(&payload_names_ikev1, proposal.isap_np));
			return BAD_PROPOSAL_SYNTAX;
		}
	}
	loglog(RC_LOG_SERIOUS, "no acceptable Oakley Transform");
	return NO_PROPOSAL_CHOSEN;
}

/* Initialize st_oakley field of state for use when initiating in
 * aggressive mode.
 *
 * This should probably get more of its parameters, like what group to use,
 * from the connection specification, but it's not there yet.
 * This should ideally be done by passing them via whack.
 *
 */

/* XXX MCR. I suspect that actually all of this is redundent */
bool init_am_st_oakley(struct state *st, lset_t policy)
{
	struct trans_attrs ta;
	struct db_attr  *enc, *hash, *auth, *grp;
	struct db_trans *trans;
	struct db_prop  *prop;
	struct db_prop_conj *cprop;
	struct db_sa    *sa;
	struct db_sa    *revised_sadb;
	struct connection *c = st->st_connection;
	unsigned int policy_index = POLICY_ISAKMP(policy,
						  c->spd.this.xauth_server,
						  c->spd.this.xauth_client);

	zero(&ta);

	/* When this SA expires (seconds) */
	ta.life_seconds = st->st_connection->sa_ike_life_seconds;
	ta.life_kilobytes = 1000000;

	passert(policy_index < elemsof(oakley_am_sadb));
	sa = &oakley_am_sadb[policy_index];

	/* Max transforms == 2 - Multiple transforms, 1 DH group */
	revised_sadb = oakley_alg_makedb(st->st_connection->alg_info_ike,
					 sa, 2);

	if (revised_sadb == NULL)
		return FALSE;

	passert(revised_sadb->prop_conj_cnt == 1);
	cprop = &revised_sadb->prop_conjs[0];

	passert(cprop->prop_cnt == 1);
	prop = &cprop->props[0];

	trans = &prop->trans[0];

	passert(trans->attr_cnt == 4 || trans->attr_cnt == 5);
	enc  = &trans->attrs[0];
	hash = &trans->attrs[1];
	auth = &trans->attrs[2];
	grp  = &trans->attrs[3];

	DBG(DBG_CONTROL,
	    DBG_log("initiating aggressive mode with IKE=E=%d-H=%d-M=%d",
		    enc->val,
		    hash->val,
		    grp->val));

	passert(enc->type.oakley == OAKLEY_ENCRYPTION_ALGORITHM);
	ta.encrypt = enc->val;         /* OAKLEY_ENCRYPTION_ALGORITHM */
	ta.encrypter = crypto_get_encrypter(ta.encrypt);
	passert(ta.encrypter != NULL);

	if (trans->attr_cnt == 5) {
		struct db_attr *enc_keylen;
		enc_keylen = &trans->attrs[4];
		ta.enckeylen = enc_keylen->val;
	} else {
		ta.enckeylen = ta.encrypter->keydeflen;
	}

	passert(hash->type.oakley == OAKLEY_HASH_ALGORITHM);
	ta.prf_hash = hash->val;           /* OAKLEY_HASH_ALGORITHM */
	ta.prf_hasher = crypto_get_hasher(ta.prf_hash);
	passert(ta.prf_hasher != NULL);

	passert(auth->type.oakley == OAKLEY_AUTHENTICATION_METHOD);
	ta.auth   = auth->val;         /* OAKLEY_AUTHENTICATION_METHOD */

	passert(grp->type.oakley == OAKLEY_GROUP_DESCRIPTION);
	ta.group = lookup_group(grp->val); /* OAKLEY_GROUP_DESCRIPTION */
	passert(ta.group != NULL);

	st->st_oakley = ta;

	return TRUE;
}

/**
 * Parse the body of an IPsec SA Payload (i.e. Phase 2 / Quick Mode).
 *
 * The main routine is parse_ipsec_sa_body; other functions defined
 * between here and there are just helpers.
 *
 * Various shortcuts are taken.  In particular, the policy, such as
 * it is, is hardwired.
 *
 * If r_sa is non-NULL, the body of an SA representing the selected
 * proposal is emitted into it.
 *
 * If "selection" is true, the SA is supposed to represent the
 * single tranform that the peer has accepted.
 * ??? We only check that it is acceptable, not that it is one that we offered!
 *
 * Only IPsec DOI is accepted (what is the ISAKMP DOI?).
 * Error response is rudimentary.
 *
 * Since all ISAKMP groups in all SA Payloads must match, st->st_pfs_group
 * holds this across multiple payloads.
 * &unset_group signifies not yet "set"; NULL signifies NONE.
 *
 * This routine is used by quick_inI1_outR1() and quick_inR1_outI2().
 */

static const struct ipsec_trans_attrs null_ipsec_trans_attrs = {
	.spi = 0,                                               /* spi */
	.life_seconds = SA_LIFE_DURATION_DEFAULT,               /* life_seconds */
	.life_kilobytes = SA_LIFE_DURATION_K_DEFAULT,           /* life_kilobytes */
	.encapsulation = ENCAPSULATION_MODE_UNSPECIFIED,        /* encapsulation */
};

static bool parse_ipsec_transform(struct isakmp_transform *trans,
				  struct ipsec_trans_attrs *attrs,
				  pb_stream *prop_pbs,
				  pb_stream *trans_pbs,
				  struct_desc *trans_desc,
				  int previous_transnum, /* or -1 if none */
				  bool selection,
				  bool is_last,
				  bool is_ipcomp,
				  struct state *st) /* current state object */
{
	lset_t seen_attrs = 0,
	       seen_durations = 0;
	u_int16_t life_type;
	const struct oakley_group_desc *pfs_group = NULL;

	life_type = 0;

	if (!in_struct(trans, trans_desc, prop_pbs, trans_pbs))
		return FALSE;

	if (trans->isat_transnum <= previous_transnum) {
		loglog(RC_LOG_SERIOUS,
		       "Transform Numbers in Proposal are not monotonically increasing");
		return FALSE;
	}

	switch (trans->isat_np) {
	case ISAKMP_NEXT_T:
		if (is_last) {
			loglog(RC_LOG_SERIOUS,
			       "Proposal Payload has more Transforms than specified");
			return FALSE;
		}
		break;
	case ISAKMP_NEXT_NONE:
		if (!is_last) {
			loglog(RC_LOG_SERIOUS,
			       "Proposal Payload has fewer Transforms than specified");
			return FALSE;
		}
		break;
	default:
		loglog(RC_LOG_SERIOUS,
		       "expecting Transform Payload, but found %s in Proposal",
		       enum_show(&payload_names_ikev1, trans->isat_np));
		return FALSE;
	}

	*attrs = null_ipsec_trans_attrs;
	attrs->transattrs.encrypt = trans->isat_transid;

	while (pbs_left(trans_pbs) != 0) {
		struct isakmp_attribute a;
		pb_stream attr_pbs;
		enum_names *vdesc;
		u_int32_t val;                          /* room for larger value */
		bool ipcomp_inappropriate = is_ipcomp;  /* will get reset if OK */

		if (!in_struct(&a, &isakmp_ipsec_attribute_desc, trans_pbs,
			       &attr_pbs))
			return FALSE;

#ifndef HAVE_LABELED_IPSEC
		/*This check is no longer valid when using security labels as SECCTX attribute is in private range and has value of 32001*/
		passert((a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK) < LELEM_ROOF);
#endif

		if (LHAS(seen_attrs, a.isaat_af_type &
			 ISAKMP_ATTR_RTYPE_MASK)) {
			loglog(RC_LOG_SERIOUS,
			       "repeated %s attribute in IPsec Transform %u",
			       enum_show(&ipsec_attr_names, a.isaat_af_type),
			       trans->isat_transnum);
			return FALSE;
		}

		seen_attrs |= LELEM(a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);

		val = a.isaat_lv;

		vdesc = ipsec_attr_val_descs[a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK
#ifdef HAVE_LABELED_IPSEC
		/* The original code (without labeled ipsec) assumes a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK) < LELEM_ROOF, */
		/* so for retaining the same behavior when this is < LELEM_ROOF and if more than >= LELEM_ROOF setting it to 0, */
		/* which is NULL in ipsec_attr_val_desc*/
					     >= LELEM_ROOF ? 0 : a.isaat_af_type &
					     ISAKMP_ATTR_RTYPE_MASK
#endif
			];
		if (vdesc != NULL) {
			if (enum_name(vdesc, val) == NULL) {
				loglog(RC_LOG_SERIOUS,
				       "invalid value %u for attribute %s in IPsec Transform",
				       (unsigned)val,
				       enum_show(&ipsec_attr_names,
						 a.isaat_af_type));
				return FALSE;
			}
			DBG(DBG_PARSING, {
				    if ((a.isaat_af_type &
					 ISAKMP_ATTR_AF_MASK) ==
					ISAKMP_ATTR_AF_TV) {
					    DBG_log("   [%u is %s]",
						    (unsigned)val,
						    enum_show(vdesc, val));
				    }
			    });
		}

		switch (a.isaat_af_type) {
#ifdef HAVE_LABELED_IPSEC
		case SECCTX | ISAKMP_ATTR_AF_TLV:
		{
			pb_stream *   pbs = &attr_pbs;
			if (!parse_secctx_attr(pbs, st))
				return FALSE;
		}
		break;
#endif
		case SA_LIFE_TYPE | ISAKMP_ATTR_AF_TV:
			ipcomp_inappropriate = FALSE;
			if (LHAS(seen_durations, val)) {
				loglog(RC_LOG_SERIOUS,
				       "attribute SA_LIFE_TYPE value %s repeated in message",
				       enum_show(&sa_lifetime_names, val));
				return FALSE;
			}
			seen_durations |= LELEM(val);
			life_type = val;
			break;
		case SA_LIFE_DURATION | ISAKMP_ATTR_AF_TLV:
			val = decode_long_duration(&attr_pbs);
		/* fall through */
		case SA_LIFE_DURATION | ISAKMP_ATTR_AF_TV:
			ipcomp_inappropriate = FALSE;
			if (!LHAS(seen_attrs, SA_LIFE_DURATION)) {
				loglog(RC_LOG_SERIOUS,
				       "SA_LIFE_DURATION IPsec attribute not preceded by SA_LIFE_TYPE attribute");
				return FALSE;
			}
			seen_attrs &=
				~(LELEM(SA_LIFE_DURATION) |
				  LELEM(SA_LIFE_TYPE));

			switch (life_type) {
			case SA_LIFE_TYPE_SECONDS:
				/* silently limit duration to our maximum */
				attrs->life_seconds = val <=
						      SA_LIFE_DURATION_MAXIMUM
						      ?
						      (val <
						       st->st_connection->
						       sa_ipsec_life_seconds ?
						       val :
						       st->st_connection->
						       sa_ipsec_life_seconds) :
						      SA_LIFE_DURATION_MAXIMUM;
				break;
			case SA_LIFE_TYPE_KBYTES:
				attrs->life_kilobytes = val;
				break;
			default:
				bad_case(life_type);
			}
			break;
		case GROUP_DESCRIPTION | ISAKMP_ATTR_AF_TV:
			if (is_ipcomp) {
				/* Accept reluctantly.  Should not happen, according to
				 * draft-shacham-ippcp-rfc2393bis-05.txt 4.1.
				 */
				ipcomp_inappropriate = FALSE;
				loglog(RC_COMMENT,
				       "IPCA (IPcomp SA) contains GROUP_DESCRIPTION."
				       "  Ignoring inapproprate attribute.");
			}
			pfs_group = lookup_group(val);
			if (pfs_group == NULL) {
				loglog(RC_LOG_SERIOUS,
				       "OAKLEY_GROUP %d not supported for PFS",
				       val);
				return FALSE;
			}
			break;

		case ENCAPSULATION_MODE | ISAKMP_ATTR_AF_TV:
			ipcomp_inappropriate = FALSE;
			switch (val) {
			case ENCAPSULATION_MODE_TUNNEL:
			case ENCAPSULATION_MODE_TRANSPORT:
				DBG(DBG_NATT,
				    DBG_log("NAT-T non-encap: Installing IPsec SA without ENCAP, st->hidden_variables.st_nat_traversal is '%d'",
					    st->hidden_variables.
					    st_nat_traversal));
				if (st->hidden_variables.st_nat_traversal &
				    NAT_T_DETECTED) {
					loglog(RC_LOG_SERIOUS,
					       "%s must only be used if "
					       "NAT-Traversal is not detected",
					       enum_name(&enc_mode_names,
							 val));
					/*
					 * Accept it anyway because SSH-Sentinel does not
					 * use UDP_TUNNEL or UDP_TRANSPORT for the diagnostic.
					 *
					 * remove when SSH-Sentinel is fixed
					 */
#ifdef I_DONT_CARE_OF_SSH_SENTINEL
					return FALSE;

#endif
				}
				attrs->encapsulation = val;
				break;

			case ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS:
			case ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS:
				DBG(DBG_NATT,
				    DBG_log("NAT-T draft: Installing IPsec SA with ENCAP, st->hidden_variables.st_nat_traversal is '%d'",
					    st->hidden_variables.
					    st_nat_traversal));
				if (st->hidden_variables.st_nat_traversal &
				    NAT_T_WITH_ENCAPSULATION_RFC_VALUES) {
					loglog(RC_LOG_SERIOUS,
					       "%s must only be used with old IETF drafts",
					       enum_name(&enc_mode_names,
							 val));
					if (st->st_connection->remotepeertype
					    ==
					    CISCO) {
						DBG_log("Allowing, as this may be due to remote_peer Cisco rekey");
						attrs->encapsulation = val -
								       ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS
								       +
								       ENCAPSULATION_MODE_TUNNEL;
					} else {
						return FALSE;
					}
				} else if (st->hidden_variables.
					   st_nat_traversal & NAT_T_DETECTED) {
					attrs->encapsulation = val -
							       ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS
							       +
							       ENCAPSULATION_MODE_TUNNEL;
				} else {
					loglog(RC_LOG_SERIOUS,
					       "%s must only be used if "
					       "NAT-Traversal is detected",
					       enum_name(&enc_mode_names,
							 val));
					return FALSE;
				}
				break;

			case ENCAPSULATION_MODE_UDP_TRANSPORT_RFC:
			case ENCAPSULATION_MODE_UDP_TUNNEL_RFC:
				DBG(DBG_NATT,
				    DBG_log("NAT-T RFC: Installing IPsec SA with ENCAP, st->hidden_variables.st_nat_traversal is '%d'",
					    st->hidden_variables.
					    st_nat_traversal));
				if ((st->hidden_variables.st_nat_traversal &
				     NAT_T_DETECTED) &&
				    (st->hidden_variables.st_nat_traversal &
				     NAT_T_WITH_ENCAPSULATION_RFC_VALUES)) {
					attrs->encapsulation = val -
							       ENCAPSULATION_MODE_UDP_TUNNEL_RFC
							       +
							       ENCAPSULATION_MODE_TUNNEL;
				} else if (st->hidden_variables.
					   st_nat_traversal & NAT_T_DETECTED) {
					loglog(RC_LOG_SERIOUS,
					       "%s must only be used with NAT-T RFC",
					       enum_name(&enc_mode_names,
							 val));
					return FALSE;
				} else {
					loglog(RC_LOG_SERIOUS,
					       "%s must only be used if "
					       "NAT-Traversal is detected",
					       enum_name(&enc_mode_names,
							 val));
					return FALSE;
				}
				break;
			default:
				loglog(RC_LOG_SERIOUS,
				       "unknown ENCAPSULATION_MODE %d in IPSec SA",
				       val);
				return FALSE;

				break;
			}
			break;
		case AUTH_ALGORITHM | ISAKMP_ATTR_AF_TV:
			attrs->transattrs.integ_hash = val;
			break;
		case KEY_LENGTH | ISAKMP_ATTR_AF_TV:
			attrs->transattrs.enckeylen = val;
			break;
#if 0
		case KEY_ROUNDS | ISAKMP_ATTR_AF_TV:
			attrs->key_rounds = val;
			break;
#endif
#if 0                   /* not yet implemented */
		case COMPRESS_DICT_SIZE | ISAKMP_ATTR_AF_TV:
			break;
		case COMPRESS_PRIVATE_ALG | ISAKMP_ATTR_AF_TV:
			break;

		case SA_LIFE_DURATION | ISAKMP_ATTR_AF_TLV:
			break;
		case COMPRESS_PRIVATE_ALG | ISAKMP_ATTR_AF_TLV:
			break;
#endif
		default:
#ifdef HAVE_LABELED_IPSEC
			if (a.isaat_af_type ==
			    (secctx_attr_value | ISAKMP_ATTR_AF_TLV) ) {
				pb_stream *   pbs = &attr_pbs;
				if (!parse_secctx_attr(pbs, st))
					return FALSE;
			} else {
#endif
			loglog(RC_LOG_SERIOUS,
			       "unsupported IPsec attribute %s",
			       enum_show(&ipsec_attr_names, a.isaat_af_type));
			return FALSE;

#ifdef HAVE_LABELED_IPSEC
		}
#endif
		}

		if (ipcomp_inappropriate) {
			loglog(RC_LOG_SERIOUS,
			       "IPsec attribute %s inappropriate for IPCOMP",
			       enum_show(&ipsec_attr_names, a.isaat_af_type));
			return FALSE;
		}
	}

	/* Although an IPCOMP SA (IPCA) ought not to have a pfs_group,
	 * if it does, demand that it be consistent.
	 * See draft-shacham-ippcp-rfc2393bis-05.txt 4.1.
	 */
	if (!is_ipcomp || pfs_group != NULL) {
		if (st->st_pfs_group == &unset_group)
			st->st_pfs_group = pfs_group;

		if (st->st_pfs_group != pfs_group) {
			loglog(RC_LOG_SERIOUS,
			       "GROUP_DESCRIPTION inconsistent with that of %s in IPsec SA",
			       selection ? "the Proposal" : "a previous Transform");
			return FALSE;
		}
	}

	if (LHAS(seen_attrs, SA_LIFE_DURATION)) {
		loglog(RC_LOG_SERIOUS,
		       "SA_LIFE_TYPE IPsec attribute not followed by SA_LIFE_DURATION attribute in message");
		return FALSE;
	}

	if (!LHAS(seen_attrs, ENCAPSULATION_MODE)) {
		if (is_ipcomp) {
			/* draft-shacham-ippcp-rfc2393bis-05.txt 4.1:
			 * "If the Encapsulation Mode is unspecified,
			 * the default value of Transport Mode is assumed."
			 * This contradicts/overrides the DOI (quuoted below).
			 */
			attrs->encapsulation = ENCAPSULATION_MODE_TRANSPORT;
		} else {
			/* ??? Technically, RFC 2407 (IPSEC DOI) 4.5 specifies that
			 * the default is "unspecified (host-dependent)".
			 * This makes little sense, so we demand that it be specified.
			 */
			loglog(RC_LOG_SERIOUS,
			       "IPsec Transform must specify ENCAPSULATION_MODE");
			return FALSE;
		}
	}

	/* ??? should check for key_len and/or key_rounds if required */

	return TRUE;
}

static void echo_proposal(struct isakmp_proposal r_proposal,    /* proposal to emit */
			  struct isakmp_transform r_trans,      /* winning transformation within it */
			  u_int8_t np,                          /* Next Payload for proposal */
			  pb_stream *r_sa_pbs,                  /* SA PBS into which to emit */
			  struct ipsec_proto_info *pi,          /* info about this protocol instance */
			  struct_desc *trans_desc,              /* descriptor for this transformation */
			  pb_stream *trans_pbs,                 /* PBS for incoming transform */
			  struct spd_route *sr,                 /* host details for the association */
			  bool tunnel_mode)                     /* true for inner most tunnel SA */
{
	pb_stream r_proposal_pbs;
	pb_stream r_trans_pbs;

	/* Proposal */
	r_proposal.isap_np = np;
	r_proposal.isap_notrans = 1;
	if (!out_struct(&r_proposal, &isakmp_proposal_desc, r_sa_pbs,
			&r_proposal_pbs))
		impossible();

	/* allocate and emit our CPI/SPI */
	if (r_proposal.isap_protoid == PROTO_IPCOMP) {
		/* CPI is stored in network low order end of an
		 * ipsec_spi_t.  So we start a couple of bytes in.
		 * Note: we may fail to generate a satisfactory CPI,
		 * but we'll ignore that.
		 */
		pi->our_spi = get_my_cpi(sr, tunnel_mode);
		if (!out_raw((u_char *) &pi->our_spi +
			     IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE,
			     IPCOMP_CPI_SIZE,
			     &r_proposal_pbs, "CPI"))
			impossible();
	} else {
		pi->our_spi = get_ipsec_spi(pi->attrs.spi,
					    r_proposal.isap_protoid == PROTO_IPSEC_AH ?
					    IPPROTO_AH : IPPROTO_ESP,
					    sr,
					    tunnel_mode);
		/* XXX should check for errors */
		if (!out_raw((u_char *) &pi->our_spi, IPSEC_DOI_SPI_SIZE,
			     &r_proposal_pbs, "SPI"))
			impossible();
	}

	/* Transform */
	r_trans.isat_np = ISAKMP_NEXT_NONE;
	if (!out_struct(&r_trans, trans_desc, &r_proposal_pbs, &r_trans_pbs))
		impossible();

	/* Transform Attributes: pure echo */
	trans_pbs->cur = trans_pbs->start + sizeof(struct isakmp_transform);
	if (!out_raw(trans_pbs->cur, pbs_left(trans_pbs),
		     &r_trans_pbs, "attributes"))
		impossible();

	close_output_pbs(&r_trans_pbs);
	close_output_pbs(&r_proposal_pbs);
}

notification_t parse_ipsec_sa_body(pb_stream *sa_pbs,           /* body of input SA Payload */
				   const struct isakmp_sa *sa,  /* header of input SA Payload */
				   pb_stream *r_sa_pbs,         /* if non-NULL, where to emit body of winning SA */
				   bool selection,              /* if this SA is a selection, only one transform may appear */
				   struct state *st)            /* current state object */
{
	const struct connection *c = st->st_connection;
	u_int32_t ipsecdoisit;
	pb_stream next_proposal_pbs;

	struct isakmp_proposal next_proposal;
	ipsec_spi_t next_spi;

	bool next_full = TRUE;

	/* DOI */
	if (sa->isasa_doi != ISAKMP_DOI_IPSEC) {
		loglog(RC_LOG_SERIOUS, "Unknown or unsupported DOI %s",
		       enum_show(&doi_names, sa->isasa_doi));
		/* XXX Could send notification back */
		return DOI_NOT_SUPPORTED;
	}

	/* Situation */
	if (!in_struct(&ipsecdoisit, &ipsec_sit_desc, sa_pbs, NULL))
		return SITUATION_NOT_SUPPORTED;

	if (ipsecdoisit != SIT_IDENTITY_ONLY) {
		loglog(RC_LOG_SERIOUS, "unsupported IPsec DOI situation (%s)",
		       bitnamesof(sit_bit_names, ipsecdoisit));
		/* XXX Could send notification back */
		return SITUATION_NOT_SUPPORTED;
	}

	/* The rules for IPsec SAs are scattered.
	 * RFC 2408 "ISAKMP" section 4.2 gives some info.
	 * There may be multiple proposals.  Those with identical proposal
	 * numbers must be considered as conjuncts.  Those with different
	 * numbers are disjuncts.
	 * Each proposal may have several transforms, each considered
	 * an alternative.
	 * Each transform may have several attributes, all applying.
	 *
	 * To handle the way proposals are combined, we need to do a
	 * look-ahead.
	 */

	if (!in_struct(&next_proposal, &isakmp_proposal_desc, sa_pbs,
		       &next_proposal_pbs))
		return BAD_PROPOSAL_SYNTAX;

	/* for each conjunction of proposals... */
	while (next_full) {
		int propno = next_proposal.isap_proposal;
		pb_stream ah_prop_pbs, esp_prop_pbs, ipcomp_prop_pbs;
		struct isakmp_proposal ah_proposal, esp_proposal,
				       ipcomp_proposal;
		ipsec_spi_t ah_spi, esp_spi, ipcomp_cpi;
		bool ah_seen = FALSE, esp_seen = FALSE, ipcomp_seen = FALSE;
		int inner_proto = 0;
		bool tunnel_mode = FALSE;
		u_int16_t well_known_cpi = 0;

		pb_stream ah_trans_pbs, esp_trans_pbs, ipcomp_trans_pbs;
		struct isakmp_transform ah_trans, esp_trans, ipcomp_trans;
		struct ipsec_trans_attrs ah_attrs, esp_attrs, ipcomp_attrs;

		ipcomp_cpi = 0;
		esp_spi = 0;
		ah_spi = 0;

		zero(&ah_proposal);
		zero(&esp_proposal);
		zero(&ipcomp_proposal);

		/* for each proposal in the conjunction */
		do {

			if (next_proposal.isap_protoid == PROTO_IPCOMP) {
				/* IPCOMP CPI */
				if (next_proposal.isap_spisize ==
				    IPSEC_DOI_SPI_SIZE) {
					/* This code is to accommodate those peculiar
					 * implementations that send a CPI in the bottom of an
					 * SPI-sized field.
					 * See draft-shacham-ippcp-rfc2393bis-05.txt 4.1
					 */
					u_int8_t filler[IPSEC_DOI_SPI_SIZE -
							IPCOMP_CPI_SIZE];

					if (!in_raw(filler, sizeof(filler),
						    &next_proposal_pbs,
						    "CPI filler") ||
					    !all_zero(filler, sizeof(filler)))
						return INVALID_SPI;
				} else if (next_proposal.isap_spisize !=
					   IPCOMP_CPI_SIZE) {
					loglog(RC_LOG_SERIOUS,
					       "IPsec Proposal with improper CPI size (%u)",
					       next_proposal.isap_spisize);
					return INVALID_SPI;
				}

				/* We store CPI in the low order of a network order
				 * ipsec_spi_t.  So we start a couple of bytes in.
				 */
				zero(&next_spi);
				if (!in_raw((u_char *)&next_spi +
					    IPSEC_DOI_SPI_SIZE -
					    IPCOMP_CPI_SIZE,
					    IPCOMP_CPI_SIZE,
					    &next_proposal_pbs, "CPI"))
					return INVALID_SPI;

				/* If sanity ruled, CPIs would have to be such that
				 * the SAID (the triple (CPI, IPCOM, destination IP))
				 * would be unique, just like for SPIs.  But there is a
				 * perversion where CPIs can be well-known and consequently
				 * the triple is not unique.  We hide this fact from
				 * ourselves by fudging the top 16 bits to make
				 * the property true internally!
				 */
				switch (ntohl(next_spi)) {
				case IPCOMP_DEFLATE:
					well_known_cpi = ntohl(next_spi);
					next_spi = uniquify_his_cpi(next_spi,
								    st);
					if (next_spi == 0) {
						loglog(RC_LOG_SERIOUS,
						       "IPsec Proposal contains well-known CPI that I cannot uniquify");
						return INVALID_SPI;
					}
					break;
				default:
					if (ntohl(next_spi) <
					    IPCOMP_FIRST_NEGOTIATED ||
					    ntohl(next_spi) >
					    IPCOMP_LAST_NEGOTIATED) {
						loglog(RC_LOG_SERIOUS,
						       "IPsec Proposal contains CPI from non-negotiated range (0x%lx)",
						       (unsigned long) ntohl(next_spi));
						return INVALID_SPI;
					}
					break;
				}
			} else {
				/* AH or ESP SPI */
				if (next_proposal.isap_spisize !=
				    IPSEC_DOI_SPI_SIZE) {
					loglog(RC_LOG_SERIOUS,
					       "IPsec Proposal with improper SPI size (%u)",
					       next_proposal.isap_spisize);
					return INVALID_SPI;
				}

				if (!in_raw((u_char *)&next_spi,
					    sizeof(next_spi),
					    &next_proposal_pbs, "SPI"))
					return INVALID_SPI;

				/* SPI value 0 is invalid and values 1-255 are reserved to IANA.
				 * RFC 2402 (ESP) 2.4, RFC 2406 (AH) 2.1
				 * IPCOMP???
				 */
				if (ntohl(next_spi) < IPSEC_DOI_SPI_MIN) {
					loglog(RC_LOG_SERIOUS,
					       "IPsec Proposal contains invalid SPI (0x%lx)",
					       (unsigned long) ntohl(next_spi));
					return INVALID_SPI;
				}
			}

			if (next_proposal.isap_notrans == 0) {
				loglog(RC_LOG_SERIOUS,
				       "IPsec Proposal contains no Transforms (skipped)");
				continue;
			}

			switch (next_proposal.isap_protoid) {
			case PROTO_IPSEC_AH:
				if (ah_seen) {
					loglog(RC_LOG_SERIOUS,
					       "IPsec SA contains two simultaneous AH Proposals");
					return BAD_PROPOSAL_SYNTAX;
				}
				ah_seen = TRUE;
				ah_prop_pbs = next_proposal_pbs;
				ah_proposal = next_proposal;
				ah_spi = next_spi;
				break;

			case PROTO_IPSEC_ESP:
				if (esp_seen) {
					loglog(RC_LOG_SERIOUS,
					       "IPsec SA contains two simultaneous ESP Proposals");
					return BAD_PROPOSAL_SYNTAX;
				}
				esp_seen = TRUE;
				esp_prop_pbs = next_proposal_pbs;
				esp_proposal = next_proposal;
				esp_spi = next_spi;
				break;

			case PROTO_IPCOMP:
				if (ipcomp_seen) {
					loglog(RC_LOG_SERIOUS,
					       "IPsec SA contains two simultaneous IPCOMP Proposals");
					return BAD_PROPOSAL_SYNTAX;
				}
				ipcomp_seen = TRUE;
				ipcomp_prop_pbs = next_proposal_pbs;
				ipcomp_proposal = next_proposal;
				ipcomp_cpi = next_spi;
				break;

			default:
				loglog(RC_LOG_SERIOUS,
				       "unexpected Protocol ID (%s) in IPsec Proposal",
				       enum_show(&protocol_names,
						 next_proposal.isap_protoid));
				return INVALID_PROTOCOL_ID;
			}

			/* refill next_proposal */
			if (next_proposal.isap_np == ISAKMP_NEXT_NONE) {
				next_full = FALSE;
				break;
			} else if (next_proposal.isap_np != ISAKMP_NEXT_P) {
				loglog(RC_LOG_SERIOUS,
				       "unexpected in Proposal: %s",
				       enum_show(&payload_names_ikev1,
						 next_proposal.isap_np));
				return BAD_PROPOSAL_SYNTAX;
			}

			if (!in_struct(&next_proposal, &isakmp_proposal_desc,
				       sa_pbs, &next_proposal_pbs))
				return BAD_PROPOSAL_SYNTAX;
		} while (next_proposal.isap_proposal == propno);

		/* Now that we have all conjuncts, we should try
		 * the Cartesian product of eachs tranforms!
		 * At the moment, we take short-cuts on account of
		 * our rudimentary hard-wired policy.
		 * For now, we find an acceptable AH (if any)
		 * and then an acceptable ESP.  The only interaction
		 * is that the ESP acceptance can know whether there
		 * was an acceptable AH and hence not require an AUTH.
		 */

		if (ah_seen) {
			int previous_transnum = -1;
			int tn;

			for (tn = 0; tn != ah_proposal.isap_notrans; tn++) {
				int ok_transid = 0;
				bool ok_auth = FALSE;

				if (!parse_ipsec_transform(&ah_trans,
							   &ah_attrs,
							   &ah_prop_pbs,
							   &ah_trans_pbs,
							   &isakmp_ah_transform_desc,
							   previous_transnum,
							   selection,
							   tn == ah_proposal.isap_notrans - 1,
							   FALSE,
							   st))
					return BAD_PROPOSAL_SYNTAX;

				previous_transnum = ah_trans.isat_transnum;

				/* we must understand ah_attrs.transid
				 * COMBINED with ah_attrs.transattrs.integ_hash.
				 * See RFC 2407 "IPsec DOI" section 4.4.3
				 * The following combinations are legal,
				 * but we don't implement all of them:
				 * It seems as if each auth algorithm
				 * only applies to one ah transid.
				 * AH_MD5, AUTH_ALGORITHM_HMAC_MD5
				 * AH_MD5, AUTH_ALGORITHM_KPDK (unimplemented)
				 * AH_SHA, AUTH_ALGORITHM_HMAC_SHA1
				 * AH_DES, AUTH_ALGORITHM_DES_MAC (unimplemented)
				 */
				switch (ah_attrs.transattrs.integ_hash) {
				case AUTH_ALGORITHM_NONE:
					loglog(RC_LOG_SERIOUS,
					       "AUTH_ALGORITHM attribute missing in AH Transform");
					return BAD_PROPOSAL_SYNTAX;

				case AUTH_ALGORITHM_HMAC_MD5:
					ok_auth = TRUE;
				/* fall through */
				case AUTH_ALGORITHM_KPDK:
					ok_transid = AH_MD5;
					break;

				case AUTH_ALGORITHM_HMAC_SHA1:
					ok_auth = TRUE;
					ok_transid = AH_SHA;
					break;

				case AUTH_ALGORITHM_DES_MAC:
					ok_transid = AH_DES;
					break;
				}
				if (ah_attrs.transattrs.encrypt !=
				    ok_transid) {
					char esb[ENUM_SHOW_BUF_LEN];

					loglog(RC_LOG_SERIOUS,
					       "%s attribute inappropriate in %s Transform",
					       enum_showb(&auth_alg_names,
							 ah_attrs.transattrs.
							 integ_hash,
							 esb, sizeof(esb)),
					       enum_show(&ah_transformid_names,
							 ah_attrs.transattrs.
							 encrypt));
					return BAD_PROPOSAL_SYNTAX;
				}
				if (!ok_auth) {
					char esb[ENUM_SHOW_BUF_LEN];

					DBG(DBG_CONTROL | DBG_CRYPT,
					    DBG_log("%s attribute unsupported"
						    " in %s Transform from %s",
						    enum_showb(&auth_alg_names,
							      ah_attrs.
							      transattrs.
							      integ_hash,
							      esb, sizeof(esb)),
						    enum_show(&ah_transformid_names,
							      ah_attrs.
							      transattrs.
							      encrypt),
						    ip_str(&c->spd.that.
							   host_addr)));
					continue;       /* try another */
				}
				break;                  /* we seem to be happy */
			}
			if (tn == ah_proposal.isap_notrans)
				continue; /* we didn't find a nice one */
			ah_attrs.spi = ah_spi;
			inner_proto = IPPROTO_AH;
			if (ah_attrs.encapsulation ==
			    ENCAPSULATION_MODE_TUNNEL)
				tunnel_mode = TRUE;
		}

		if (esp_seen) {
			int previous_transnum = -1;
			int tn;
			err_t ugh;

			for (tn = 0; tn != esp_proposal.isap_notrans; tn++) {
				if (!parse_ipsec_transform(&esp_trans,
							   &esp_attrs,
							   &esp_prop_pbs,
							   &esp_trans_pbs,
							   &
							   isakmp_esp_transform_desc,
							   previous_transnum,
							   selection,
							   tn ==
							   esp_proposal.
							   isap_notrans - 1,
							   FALSE,
							   st))
					return BAD_PROPOSAL_SYNTAX;

				previous_transnum = esp_trans.isat_transnum;

				ugh = "no alg";

				if (c->alg_info_esp) {
					ugh = kernel_alg_esp_enc_ok(
						esp_attrs.transattrs.encrypt,
						esp_attrs.transattrs.enckeylen,
						c->alg_info_esp);
				}

				if (ugh != NULL) {
					switch (esp_attrs.transattrs.encrypt) {
					case ESP_AES:
					case ESP_3DES:
						break;
#ifdef SUPPORT_ESP_NULL                         /* should be about as secure as AH-only */
#warning "Building with ESP-Null"
					case ESP_NULL:
						if (esp_attrs.transattrs.
						    integ_hash ==
						    AUTH_ALGORITHM_NONE) {
							loglog(RC_LOG_SERIOUS,
							       "ESP_NULL requires auth algorithm");
							return
								BAD_PROPOSAL_SYNTAX;
						}

						if (st->st_policy &
						    POLICY_ENCRYPT) {
							DBG(DBG_CONTROL | DBG_CRYPT,
							    DBG_log("ESP_NULL Transform Proposal from %s"
									" does not satisfy POLICY_ENCRYPT",
								    ip_str(&c->spd.that.host_addr)));
							continue; /* try another */
						}
						break;
#endif

					case ESP_DES: /* NOT safe */
						loglog(RC_LOG_SERIOUS,
						       "1DES was proposed, it is insecure and was rejected");
						/* Fall through */
					default:
						loglog(RC_LOG_SERIOUS,
						       "kernel algorithm does not like: %s",
						       ugh);
						loglog(RC_LOG_SERIOUS,
						       "unsupported ESP Transform %s from %s",
						       enum_show(&esp_transformid_names,
								 esp_attrs.
								 transattrs.
								 encrypt),
						       ip_str(&c->spd.that.
							      host_addr));
						continue; /* try another */
					}
				}

				ugh = kernel_alg_esp_auth_ok(
					esp_attrs.transattrs.integ_hash,
					c->alg_info_esp);

				if (ugh != NULL) {
					switch (esp_attrs.transattrs.integ_hash)
					{
					case AUTH_ALGORITHM_NONE:
						if (!ah_seen) {
							DBG(DBG_CONTROL | DBG_CRYPT,
							    DBG_log("ESP from %s must either have AUTH or be combined with AH",
								    ip_str(&c->spd.that.host_addr)));
							continue; /* try another */
						}
						break;
					case AUTH_ALGORITHM_HMAC_MD5:
					case AUTH_ALGORITHM_HMAC_SHA1:
						break;
					default:
						loglog(RC_LOG_SERIOUS,
						       "unsupported ESP auth alg %s from %s",
						       enum_show(&auth_alg_names,
								 esp_attrs.
								 transattrs.
								 integ_hash),
						       ip_str(&c->spd.that.
							      host_addr));
						continue; /* try another */
					}
				}

				if (ah_seen && ah_attrs.encapsulation !=
				    esp_attrs.encapsulation) {
					/* ??? This should be an error, but is it? */
					loglog(RC_LOG_SERIOUS,
					       "AH and ESP transforms disagree about encapsulation; TUNNEL presumed");
				}

				break; /* we seem to be happy */
			}
			if (tn == esp_proposal.isap_notrans)
				continue; /* we didn't find a nice one */
			/*
			 * ML: at last check for allowed transforms in alg_info_esp
			 *
			 */
			if (c->alg_info_esp != NULL &&
			    !kernel_alg_esp_ok_final(esp_attrs.transattrs.
						     encrypt,
						     esp_attrs.transattrs.
						     enckeylen,
						     esp_attrs.transattrs.
						     integ_hash,
						     c->alg_info_esp))
				continue;
			esp_attrs.spi = esp_spi;
			inner_proto = IPPROTO_ESP;
			if (esp_attrs.encapsulation ==
			    ENCAPSULATION_MODE_TUNNEL)
				tunnel_mode = TRUE;
		} else if (st->st_policy & POLICY_ENCRYPT) {
			DBG(DBG_CONTROL | DBG_CRYPT,
			    DBG_log("policy for \"%s\" requires encryption but ESP not in Proposal from %s",
				    c->name, ip_str(&c->spd.that.host_addr)));
			continue; /* we needed encryption, but didn't find ESP */
		} else if ((st->st_policy & POLICY_AUTHENTICATE) && !ah_seen) {
			DBG(DBG_CONTROL | DBG_CRYPT,
			    DBG_log("policy for \"%s\" requires authentication"
				    " but none in Proposal from %s",
				    c->name, ip_str(&c->spd.that.host_addr)));
			continue; /* we need authentication, but we found neither ESP nor AH */
		}

		if (ipcomp_seen) {
			int previous_transnum = -1;
			int tn;

			if (!(st->st_policy & POLICY_COMPRESS)) {
				libreswan_log(
					"compression proposed by %s, but policy for \"%s\" forbids it",
					ip_str(&c->spd.that.host_addr),
					c->name);
				return BAD_PROPOSAL_SYNTAX;
			}

			if (!can_do_IPcomp) {
				libreswan_log(
					"compression proposed by %s, but kernel has no IPCOMP support",
					ip_str(&c->spd.that.host_addr));
				return BAD_PROPOSAL_SYNTAX;
			}

			if (well_known_cpi != 0 && !ah_seen && !esp_seen) {
				libreswan_log(
					"illegal proposal: bare IPCOMP used with well-known CPI");
				return BAD_PROPOSAL_SYNTAX;
			}

			for (tn = 0; tn != ipcomp_proposal.isap_notrans;
			     tn++) {
				if (!parse_ipsec_transform(&ipcomp_trans,
							   &ipcomp_attrs,
							   &ipcomp_prop_pbs,
							   &ipcomp_trans_pbs,
							   &
							   isakmp_ipcomp_transform_desc,
							   previous_transnum,
							   selection,
							   tn ==
							   ipcomp_proposal.
							   isap_notrans - 1,
							   TRUE,
							   st))
					return BAD_PROPOSAL_SYNTAX;

				previous_transnum = ipcomp_trans.isat_transnum;

				if (well_known_cpi != 0 &&
				    ipcomp_attrs.transattrs.encrypt !=
				    well_known_cpi) {
					libreswan_log(
						"illegal proposal: IPCOMP well-known CPI disagrees with transform");
					return BAD_PROPOSAL_SYNTAX;
				}

				switch (ipcomp_attrs.transattrs.encrypt) {
				case IPCOMP_DEFLATE: /* all we can handle! */
					break;

				default:
					DBG(DBG_CONTROL | DBG_CRYPT,
					    DBG_log("unsupported IPCOMP Transform %s from %s",
						    enum_show(&ipcomp_transformid_names,
							      ipcomp_attrs.
							      transattrs.
							      encrypt),
						    ip_str(&c->spd.that.
							   host_addr)));
					continue; /* try another */
				}

				if (ah_seen && ah_attrs.encapsulation !=
				    ipcomp_attrs.encapsulation) {
					/* ??? This should be an error, but is it? */
					DBG(DBG_CONTROL | DBG_CRYPT,
					    DBG_log("AH and IPCOMP transforms disagree about encapsulation; TUNNEL presumed"));
				} else if (esp_seen &&
					   esp_attrs.encapsulation !=
					   ipcomp_attrs.encapsulation) {
					/* ??? This should be an error, but is it? */
					DBG(DBG_CONTROL | DBG_CRYPT,
					    DBG_log("ESP and IPCOMP transforms disagree about encapsulation; TUNNEL presumed"));
				}

				break; /* we seem to be happy */
			}
			if (tn == ipcomp_proposal.isap_notrans)
				continue; /* we didn't find a nice one */
			ipcomp_attrs.spi = ipcomp_cpi;
			inner_proto = IPPROTO_COMP;
			if (ipcomp_attrs.encapsulation ==
			    ENCAPSULATION_MODE_TUNNEL)
				tunnel_mode = TRUE;
		}

		/* Eureka: we liked what we saw -- accept it. */

		if (r_sa_pbs != NULL) {
			/* emit what we've accepted */

			/* Situation */
			if (!out_struct(&ipsecdoisit, &ipsec_sit_desc,
					r_sa_pbs, NULL))
				impossible();

			/* AH proposal */
			if (ah_seen) {
				echo_proposal(ah_proposal,
					      ah_trans,
					      esp_seen || ipcomp_seen ? ISAKMP_NEXT_P : ISAKMP_NEXT_NONE,
					      r_sa_pbs,
					      &st->st_ah,
					      &isakmp_ah_transform_desc,
					      &ah_trans_pbs,
					      &st->st_connection->spd,
					      tunnel_mode && inner_proto ==
					      IPPROTO_AH);
			}

			/* ESP proposal */
			if (esp_seen) {
				echo_proposal(esp_proposal,
					      esp_trans,
					      ipcomp_seen ? ISAKMP_NEXT_P : ISAKMP_NEXT_NONE,
					      r_sa_pbs,
					      &st->st_esp,
					      &isakmp_esp_transform_desc,
					      &esp_trans_pbs,
					      &st->st_connection->spd,
					      tunnel_mode && inner_proto ==
					      IPPROTO_ESP);
			}

			/* IPCOMP proposal */
			if (ipcomp_seen) {
				echo_proposal(ipcomp_proposal,
					      ipcomp_trans,
					      ISAKMP_NEXT_NONE,
					      r_sa_pbs,
					      &st->st_ipcomp,
					      &isakmp_ipcomp_transform_desc,
					      &ipcomp_trans_pbs,
					      &st->st_connection->spd,
					      tunnel_mode && inner_proto ==
					      IPPROTO_COMP);
			}

			close_output_pbs(r_sa_pbs);
		}

		/* save decoded version of winning SA in state */

		st->st_ah.present = ah_seen;
		if (ah_seen)
			st->st_ah.attrs = ah_attrs;

		st->st_esp.present = esp_seen;
		if (esp_seen) {
			st->st_esp.attrs = esp_attrs;
		}
		st->st_ipcomp.present = ipcomp_seen;
		if (ipcomp_seen)
			st->st_ipcomp.attrs = ipcomp_attrs;

		return NOTHING_WRONG;
	}

	loglog(RC_LOG_SERIOUS, "no acceptable Proposal in IPsec SA");
	return NO_PROPOSAL_CHOSEN;
}
