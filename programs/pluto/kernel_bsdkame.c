/* pfkey interface to the NetBSD/FreeBSD/OSX IPsec mechanism
 *
 * based upon kernel_klips.c.
 *
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/queue.h>		/* for TAILQ_xx macros */

#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <netipsec/ipsec.h>
#include "libbsdpfkey/libpfkey.h"

#include "sysdep.h"
#include "constants.h"

#include "defs.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel.h"
#include "timer.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "packet.h"     /* for pb_stream in nat_traversal.h */
#include "nat_traversal.h"
#include "kernel_alg.h"
#include "iface.h"
#include "ip_sockaddr.h"
#include "rnd.h"

static void bsdkame_algregister(int satype, int supp_exttype,
				struct sadb_alg *alg);

/*
 * Multiplier for converting .sadb_msg_len (in 64-bit words) to
 * size_t.
 */
#define KERNEL_SADB_WORD_SIZE (64/8)

int pfkeyfd = NULL_FD;
unsigned int pfkey_seq = 1;
bool nat_traversal_support_port_floating;


typedef struct pfkey_item {
	TAILQ_ENTRY(pfkey_item) list;
	struct sadb_msg        *msg;
} pfkey_item;

TAILQ_HEAD(, pfkey_item) pfkey_iq;

/* used by kernel_netlink.c and kernel_bsdkame.c */
static void kernel_add_sadb_alg(int satype, int exttype, const struct sadb_alg *sadb_alg)
{
	uint8_t alg_id = sadb_alg->sadb_alg_id;

	const struct encrypt_desc *encrypt = NULL;
	const struct integ_desc *integ = NULL;
	bool combo_ok = false;
	switch (exttype) {
	case SADB_EXT_SUPPORTED_ENCRYPT:
		switch (satype) {
		case SADB_SATYPE_ESP:
			encrypt = encrypt_desc_by_sadb_ealg_id(alg_id);
			combo_ok = true;
			break;
		}
		break;
	case SADB_EXT_SUPPORTED_AUTH:
		switch (satype) {
		case SADB_SATYPE_ESP:
		case SADB_SATYPE_AH:
			integ = integ_desc_by_sadb_aalg_id(alg_id);
			combo_ok = true;
			break;
		}
		break;
	}

	if (DBGP(DBG_BASE)) {
		JAMBUF(buf) {
			jam_string(buf, __func__);
			jam_string(buf, ":");
			jam(buf, " satype=%d(%s)", satype,
			    satype == SADB_SATYPE_ESP ? "SADB_SATYPE_ESP"
			    : satype == SADB_SATYPE_AH ? "SADB_SATYPE_AH"
			    : "SADB_SATYPE_???");
			jam(buf, " exttype=%d(%s)", exttype,
			    exttype == SADB_EXT_SUPPORTED_AUTH ? "SADB_EXT_SUPPORTED_AUTH"
			    : exttype == SADB_EXT_SUPPORTED_ENCRYPT ? "SADB_EXT_SUPPORTED_ENCRYPT"
			    : "SADB_EXT_SUPPORTED_???");
			DBG_log(" alg_id=%d(%s)", alg_id,
				integ != NULL ? integ->common.fqn
				: encrypt != NULL ? encrypt->common.fqn
				: "???");
			jam(buf, " alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d",
			    sadb_alg->sadb_alg_ivlen,
			    sadb_alg->sadb_alg_minbits,
			    sadb_alg->sadb_alg_maxbits);
			if (integ == NULL && encrypt == NULL) {
				jam_string(buf, ", not supported");
			}
			if (!combo_ok) {
				jam_string(buf, ", invalid combo");
			}
			jambuf_to_logger(buf, &global_logger, DEBUG_STREAM);
		}
	}

	if (encrypt != NULL) {
		kernel_encrypt_add(encrypt);
	}
	if (integ != NULL) {
		kernel_integ_add(integ);
	}
}

static void bsdkame_init_pfkey(struct logger *logger)
{
	/* open PF_KEY socket */

	TAILQ_INIT(&pfkey_iq);

	pfkeyfd = pfkey_open();
	if (pfkeyfd < 0) {
		fatal_errno(PLUTO_EXIT_KERNEL_FAIL, logger, errno,
			    "socket() in init_pfkeyfd()");
	}

	dbg("listening for PF_KEY_V2 on file descriptor %d", pfkeyfd);

	/* probe to see if it is alive */
	if (pfkey_send_register(pfkeyfd, SADB_SATYPE_UNSPEC) < 0 ||
	    pfkey_recv_register(pfkeyfd) < 0) {
		fatal_errno(PLUTO_EXIT_KERNEL_FAIL, logger, errno,
			    "pfkey probe failed");
	}

	DBG_log("pfkey_register AH");
	pfkey_send_register(pfkeyfd, SADB_SATYPE_AH);
	pfkey_recv_register(pfkeyfd);

	DBG_log("pfkey_register ESP");
	pfkey_send_register(pfkeyfd, SADB_SATYPE_ESP);
	pfkey_recv_register(pfkeyfd);

	pfkey_send_register(pfkeyfd, SADB_X_SATYPE_IPCOMP);
	pfkey_recv_register(pfkeyfd);

	foreach_supported_alg(bsdkame_algregister);
}

static void bsdkame_algregister(int satype, int supp_exttype,
				struct sadb_alg *alg)
{
	switch (satype) {

	case SADB_SATYPE_AH:
		kernel_add_sadb_alg(satype, supp_exttype, alg);
		dbg("algregister_ah(%p) exttype=%d alg_id=%d, alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d",
		    alg, supp_exttype,
		    alg->sadb_alg_id,
		    alg->sadb_alg_ivlen,
		    alg->sadb_alg_minbits,
		    alg->sadb_alg_maxbits);
		break;

	case SADB_SATYPE_ESP:
		kernel_add_sadb_alg(satype, supp_exttype, alg);
		dbg("algregister(%p) alg_id=%d, alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d",
		    alg,
		    alg->sadb_alg_id,
		    alg->sadb_alg_ivlen,
		    alg->sadb_alg_minbits,
		    alg->sadb_alg_maxbits);
		break;

	case SADB_X_SATYPE_IPCOMP:
		dbg("ipcomp algregister(%p) alg_id=%d, alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d",
		    alg,
		    alg->sadb_alg_id,
		    alg->sadb_alg_ivlen,
		    alg->sadb_alg_minbits,
		    alg->sadb_alg_maxbits);
		break;

	default:
		break;
	}
}

static void bsdkame_pfkey_register_response(struct sadb_msg *msg)
{
	pfkey_set_supported(msg, msg->sadb_msg_len);
}

static void bsdkame_pfkey_acquire(struct sadb_msg *msg UNUSED)
{
	DBG_log("received acquire --- discarded");
}

/* process a pfkey message */
static void bsdkame_pfkey_async(struct sadb_msg *reply)
{
	switch (reply->sadb_msg_type) {
	case SADB_REGISTER:
		bsdkame_pfkey_register_response(reply);
		break;

	case SADB_ACQUIRE:
		bsdkame_pfkey_acquire(reply);
		break;

	/* case SADB_NAT_T UPDATE STUFF */

	default:
		break;
	}

}

/* asynchronous messages from our queue */
static void bsdkame_dequeue(void)
{
	struct pfkey_item *pi, *pinext;

	for (pi = pfkey_iq.tqh_first; pi; pi = pinext) {
		pinext = pi->list.tqe_next;
		TAILQ_REMOVE(&pfkey_iq, pi, list);

		bsdkame_pfkey_async(pi->msg);
		free(pi->msg);	/* was malloced by pfkey_recv() */
		pfree(pi);
	}
}

/* asynchronous messages directly from PF_KEY socket */
static void bsdkame_process_msg(int i UNUSED, struct logger *unused_logger UNUSED)
{
	struct sadb_msg *reply = pfkey_recv(pfkeyfd);

	bsdkame_pfkey_async(reply);
	free(reply);	/* was malloced by pfkey_recv() */
}

static void bsdkame_consume_pfkey(int pfkeyfd, unsigned int pfkey_seq, struct logger *logger)
{
	struct sadb_msg *reply = pfkey_recv(pfkeyfd);

	while (reply != NULL && reply->sadb_msg_seq != pfkey_seq) {
		struct pfkey_item *pi;
		pi = alloc_thing(struct pfkey_item, "pfkey item");

		pi->msg = reply;
		TAILQ_INSERT_TAIL(&pfkey_iq, pi, list);

		reply = pfkey_recv(pfkeyfd);
	}

	if (reply != NULL && reply->sadb_msg_errno != 0) {
		llog_errno(DEBUG_STREAM, logger, reply->sadb_msg_errno,
			   "pfkey result");
	}
}

/*
 * We are were to install a set of policy, when there is in fact an SA
 * that is already setup.
 */
static bool bsdkame_raw_policy(enum kernel_policy_op sadb_op,
			       enum expect_kernel_policy what_about_inbound UNUSED,
			       const ip_selector *src_client,
			       const ip_selector *dst_client,
			       enum shunt_policy shunt_policy,
			       const struct kernel_policy *encap,
			       deltatime_t use_lifetime UNUSED,
			       uint32_t sa_priority UNUSED,
			       const struct sa_marks *sa_marks UNUSED,
			       const struct pluto_xfrmi *xfrmi UNUSED,
			       const shunk_t policy_label UNUSED,
			       struct logger *logger)
{
	pexpect(src_client->ipproto == dst_client->ipproto);
	unsigned int transport_proto = src_client->ipproto;

	ip_sockaddr saddr = sockaddr_from_address(selector_prefix(*src_client));
	ip_sockaddr daddr = sockaddr_from_address(selector_prefix(*dst_client));
	char pbuf[512];
	struct sadb_x_policy *policy_struct = (struct sadb_x_policy *)pbuf;
	struct sadb_x_ipsecrequest *ir;
	int policylen;
	int ret;

	int policy;

	/* shunt route */
	switch (shunt_policy) {
	case SHUNT_PASS:
		dbg("netlink_raw_policy: SHUNT_PASS");
		policy = IPSEC_POLICY_NONE;
		break;
	case SHUNT_HOLD:
		/*
		 * We don't know how to implement %hold, but it is
		 * okay.  When we need a hold, the kernel XFRM acquire
		 * state will do the job (by dropping or holding the
		 * packet) until this entry expires.
		 *
		 * XXX: except this is BSD ...; same should hold true
		 * with a different option?
		 */
		dbg("netlink_raw_policy: SHUNT_HOLD implemented as no-op");
		return true; /* yes really */
	case SHUNT_DROP:
	case SHUNT_REJECT:
	case SHUNT_NONE:
		policy = IPSEC_POLICY_DISCARD;
		break;
	case SHUNT_TRAP:
		if (sadb_op == KP_ADD_INBOUND ||
		    sadb_op == KP_DELETE_INBOUND)
			return true;
		policy = IPSEC_POLICY_IPSEC;
		break;
	case SHUNT_UNSET:
		policy = IPSEC_POLICY_IPSEC;
		break;
	default:
		bad_case(shunt_policy);
	}

	const int dir = ((sadb_op == KP_ADD_INBOUND || sadb_op == KP_DELETE_INBOUND) ?
			 IPSEC_DIR_INBOUND : IPSEC_DIR_OUTBOUND);

	/*
	 * XXX: Hack: don't install an inbound spdb entry when
	 * transport mode?
	 */
	if (dir == IPSEC_DIR_INBOUND &&
	    encap != NULL &&
	    encap->mode == ENCAP_MODE_TRANSPORT) {
		dbg("%s() ignoring inbound non-tunnel policy entry",
		    __func__);
		return true;
	}

	zero(&pbuf);	/* OK: no pointer fields */

	passert(policy != -1);

	policy_struct->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy_struct->sadb_x_policy_type = policy;
	policy_struct->sadb_x_policy_dir  = dir;
	policy_struct->sadb_x_policy_id   = 0; /* needs to be set, and recorded */

	policylen = sizeof(*policy_struct);

	if (policy == IPSEC_POLICY_IPSEC && encap != NULL) {
		ip_sockaddr local_sa = sockaddr_from_address(encap->src.host);
		ip_sockaddr remote_sa = sockaddr_from_address(encap->dst.host);

		ir = (struct sadb_x_ipsecrequest *)&policy_struct[1];

		ir->sadb_x_ipsecrequest_len = (sizeof(struct sadb_x_ipsecrequest) +
					       local_sa.len + remote_sa.len);
		/*pexpect(encap != NULL)?*/
		ir->sadb_x_ipsecrequest_mode = (encap->mode == ENCAP_MODE_TUNNEL ? IPSEC_MODE_TUNNEL :
						encap->mode == ENCAP_MODE_TRANSPORT ? IPSEC_MODE_TRANSPORT :
						0);
		ir->sadb_x_ipsecrequest_proto = encap->rule[1].proto;
		dbg("%s() sadb mode %d proto %d",
		    __func__, ir->sadb_x_ipsecrequest_mode, ir->sadb_x_ipsecrequest_proto);
		ir->sadb_x_ipsecrequest_level = IPSEC_LEVEL_REQUIRE;
		ir->sadb_x_ipsecrequest_reqid = 0; /* not used for now */

		uint8_t *addrmem = (uint8_t*)&ir[1];
		memcpy(addrmem, &local_sa.sa,  local_sa.len);
		addrmem += local_sa.len;
		memcpy(addrmem, &remote_sa.sa, remote_sa.len);
		addrmem += remote_sa.len;

		policylen += ir->sadb_x_ipsecrequest_len;

		dbg("request_len=%u policylen=%u",
		    ir->sadb_x_ipsecrequest_len, policylen);
	} else {
		dbg("setting policy=%d", policy);
	}

	policy_struct->sadb_x_policy_len = PFKEY_UNIT64(policylen);

	pfkey_seq++;

	dbg("calling pfkey_send_spdadd() from %s", __func__);
	ret = pfkey_send_spdadd(pfkeyfd,
				&saddr.sa.sa, src_client->maskbits,
				&daddr.sa.sa, dst_client->maskbits,
				transport_proto ? transport_proto : 255 /* proto */,
				(caddr_t)policy_struct, policylen,
				pfkey_seq);

	dbg("consuming pfkey from %s", __func__);
	bsdkame_consume_pfkey(pfkeyfd, pfkey_seq, logger);

	if (ret < 0) {
		selector_buf s, d;
		llog(RC_LOG, logger,
		     "ret = %d from send_spdadd: %s addr=%s/%s seq=%u opname=eroute", ret,
		     ipsec_strerror(),
		     str_selector_subnet_port(src_client, &s),
		     str_selector_subnet_port(dst_client, &d),
		     pfkey_seq);
		return false;
	}
	return true;
}

static bool bsdkame_add_sa(const struct kernel_sa *sa, bool replace,
			   struct logger *logger)
{
	ip_sockaddr saddr = sockaddr_from_address(*sa->src.address);
	ip_sockaddr daddr = sockaddr_from_address(*sa->dst.address);
	char keymat[256];
	int ret;

	/* only the inner-most SA gets the tunnel flag */
	int mode = (sa->tunnel && sa->level == 0 ? IPSEC_MODE_TUNNEL : IPSEC_MODE_TRANSPORT);

	int satype;
	switch (sa->esatype) {
	case ET_AH:
		satype = SADB_SATYPE_AH;
		break;
	case ET_ESP:
		satype = SADB_SATYPE_ESP;
		break;
	case ET_IPCOMP:
		satype = SADB_X_SATYPE_IPCOMP;
		break;
	case ET_IPIP:
		llog(RC_LOG, logger, "in %s() ignoring nonsensical ET_IPIP", __func__);
		return true;

	default:
	case ET_INT:
	case ET_UNSPEC:
		bad_case(sa->esatype);
	}

	if ((sa->enckeylen + sa->authkeylen) > sizeof(keymat)) {
		llog(RC_LOG, logger,
			    "Key material is too big for kernel interface: %d>%zu",
			    (sa->enckeylen + sa->authkeylen),
			    sizeof(keymat));
		return false;
	}

	pfkey_seq++;

	memcpy(keymat, sa->enckey, sa->enckeylen);
	memcpy(keymat + sa->enckeylen, sa->authkey, sa->authkeylen);

	DBG_dump("keymat", keymat, sa->enckeylen + sa->authkeylen);
	dbg("calling pfkey_send_add2() for pfkeyseq=%d encalg=%s/%d authalg=%s/%d spi=%08x, reqid=%u, satype=%d",
	    pfkey_seq,
	    sa->encrypt->common.fqn, sa->enckeylen,
	    sa->integ->common.fqn, sa->authkeylen,
	    sa->spi, sa->reqid, satype);

	ret =  (replace ? pfkey_send_update : pfkey_send_add)(pfkeyfd,
			    satype, mode,
			    &saddr.sa.sa, &daddr.sa.sa,
			    sa->spi,
			    sa->reqid,  /* reqid */
			    64,         /* wsize, replay window size */
			    keymat,
							      sa->encrypt->encrypt_sadb_ealg_id,
			    sa->enckeylen,
							      sa->integ->integ_sadb_aalg_id,
			    sa->authkeylen,
			    0,                  /*flags */
			    0,                  /* l_alloc */
			    0,                  /* l_bytes */
			    deltasecs(sa->sa_lifetime),    /* l_addtime */
			    0,                  /* l_usetime, */
			    pfkey_seq);
#if 0
	struct pfkey_send_sa_args add_args = {
		.so = pfkeyfd,
		.type = (replace ? SADB_UPDATE : SADB_ADD),
		.satype = satype,
		.mode = mode,
		.src = &saddr.sa.sa,
		.dst = &daddr.sa.sa,
		.spi = sa->spi,
		.reqid = sa->reqid,  /* reqid */
		.wsize = 64,         /* wsize, replay window size */
		.keymat = keymat,
		.e_type = sa->encrypt->encrypt_sadb_ealg_id,
		.e_keylen = sa->enckeylen,
		.a_type = sa->integ->integ_sadb_aalg_id,
		.a_keylen = sa->authkeylen,
		.flags = 0,                  /*flags */
		.l_alloc = 0,                  /* l_alloc */
		.l_bytes = 0,                  /* l_bytes */
		.l_addtime = deltasecs(sa->sa_lifetime),    /* l_addtime */
		.l_usetime = 0,                  /* l_usetime, */
		.seq = pfkey_seq,
	};
	ret = pfkey_send_add2(&add_args);
#endif

	bsdkame_consume_pfkey(pfkeyfd, pfkey_seq, logger);

	if (ret < 0) {
		llog(RC_LOG, logger,
			    "ret = %d from add_sa: %s seq=%d", ret,
			    ipsec_strerror(), pfkey_seq);
		return false;
	}

	return true;
}

static ipsec_spi_t bsdkame_get_ipsec_spi(ipsec_spi_t avoid,
					 const ip_address *src UNUSED,
					 const ip_address *dst UNUSED,
					 const struct ip_protocol *proto UNUSED,
					 bool tunnel_mode UNUSED,
					 reqid_t reqid UNUSED,
					 uintmax_t min UNUSED, uintmax_t max UNUSED,
					 const char *story UNUSED,
					 struct logger *logger UNUSED)
{
	if (proto == &ip_protocol_ipcomp) {

		static cpi_t first_busy_cpi = 0;
		static cpi_t latest_cpi = 0;

		while (!(IPCOMP_FIRST_NEGOTIATED <= first_busy_cpi &&
			 first_busy_cpi < IPCOMP_LAST_NEGOTIATED)) {
			get_rnd_bytes((uint8_t *)&first_busy_cpi,
				      sizeof(first_busy_cpi));
			latest_cpi = first_busy_cpi;
		}

		latest_cpi++;

		if (latest_cpi == first_busy_cpi)
			find_my_cpi_gap(&latest_cpi, &first_busy_cpi);

		if (latest_cpi > IPCOMP_LAST_NEGOTIATED)
			latest_cpi = IPCOMP_FIRST_NEGOTIATED;

		return htonl((ipsec_spi_t)latest_cpi);

	} else {
		ipsec_spi_t network_spi;
		static ipsec_spi_t host_spi; /* host order, so not returned directly! */
		do {
			get_rnd_bytes(&host_spi, sizeof(host_spi));
			network_spi = htonl(host_spi);
		} while (host_spi < IPSEC_DOI_SPI_OUR_MIN || network_spi == avoid);
		return network_spi;
	}
}

static bool bsdkame_del_ipsec_spi(ipsec_spi_t spi UNUSED,
				  const struct ip_protocol *proto UNUSED,
				  const ip_address *src_address UNUSED,
				  const ip_address *dst_address UNUSED,
				  const char *story UNUSED,
				  struct logger *logger UNUSED)
{
	return true;
}

static bool bsdkame_except_socket(int socketfd, int family, struct logger *logger)
{
	struct sadb_x_policy policy;
	int level, optname;

	switch (family) {
	case AF_INET:
		level = IPPROTO_IP;
		optname = IP_IPSEC_POLICY;
		break;
#ifdef INET6
	case AF_INET6:
		level = IPPROTO_IPV6;
		optname = IPV6_IPSEC_POLICY;
		break;
#endif
	default:
		llog(RC_LOG, logger, "unsupported address family (%d)", family);
		return false;
	}

	zero(&policy);	/* OK: no pointer fields */
	policy.sadb_x_policy_len = PFKEY_UNIT64(sizeof(policy));
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	if (setsockopt(socketfd, level, optname, &policy,
		       sizeof(policy)) == -1) {
		log_errno(logger, errno, "bsdkame except socket setsockopt");
		return false;
	}
	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
	if (setsockopt(socketfd, level, optname, &policy,
		       sizeof(policy)) == -1) {
		log_errno(logger, errno, "bsdkame except socket setsockopt");
		return false;
	}
	return true;
}

static const char *bsdkame_protostack_names[] = { "bsdkame", "bsd", "kame", NULL, };

const struct kernel_ops bsdkame_kernel_ops = {
	.protostack_names = bsdkame_protostack_names,
	.interface_name = "BSD Kame",
	.updown_name = "bsd",
	.async_fdp = &pfkeyfd,
	.replay_window = 64,
	.esn_supported = false,
	.process_queue = bsdkame_dequeue,
	.process_msg = bsdkame_process_msg,
	.raw_policy = bsdkame_raw_policy,
	.add_sa = bsdkame_add_sa,
	.grp_sa = NULL,
	.del_ipsec_spi = bsdkame_del_ipsec_spi,
	.get_ipsec_spi = bsdkame_get_ipsec_spi,
	.init = bsdkame_init_pfkey,
	.shutdown = NULL,
	.exceptsocket = bsdkame_except_socket,
	.overlap_supported = false,
	.sha2_truncbug_support = false,
	.v6holes = NULL,
};
