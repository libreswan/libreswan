/* Interface to the PF_KEY v2 IPsec mechanism, for Libreswan
 *
 * Copyright (C)  2022  Andrew Cagney
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
#include <unistd.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "ip_info.h"
#include "chunk.h"
#include "hunk.h"

#include "kernel.h"
#include "kernel_alg.h"
#include "kernel_sadb.h"
#include "log.h"
#include "rnd.h"
#include "initiate.h"

static pid_t pfkeyv2_pid;
static uint32_t pfkeyv2_seq;
static int pfkeyv2_fd;

#define SIZEOF_SADB_ADDRESS (sizeof(struct sadb_address) + sizeof(ip_sockaddr))
#define SIZEOF_SADB_BASE sizeof(struct sadb_msg)
#define SIZEOF_SADB_IDENT sizeof(struct sadb_ident)
#define SIZEOF_SADB_KEY (sizeof(struct sadb_key) +  1024 / 8 /*key*/)
#define SIZEOF_SADB_LIFETIME sizeof(struct sadb_lifetime)
#define SIZEOF_SADB_SA sizeof(struct sadb_sa)
#define SIZEOF_SADB_SENS sizeof(struct sadb_sens)
#define SIZEOF_SADB_SPIRANGE sizeof(struct sadb_spirange)
#define SIZEOF_SADB_X_POLICY (sizeof(struct sadb_x_policy) + SIZEOF_SADB_X_IPSECREQUEST * 2)
#define SIZEOF_SADB_X_SA2 sizeof(struct sadb_x_sa2)
#define SIZEOF_SADB_X_IPSECREQUEST (sizeof(struct sadb_x_ipsecrequest) + SIZEOF_SADB_ADDRESS * 2)

struct outbuf {
	const char *what;
	chunk_t buf;
	void *ptr;
	size_t len;
	unsigned seq;
	struct logger *logger;
};

static void ldbg_outbuf(struct logger *logger, struct outbuf *msg)
{
	ldbg(logger, "msg: %p + %zu = %p + %zu = %p",
	     msg->buf.ptr, (msg->ptr - (void*)msg->buf.ptr),
	     msg->ptr, msg->len,
	     (msg->ptr + msg->len));
	passert((msg->ptr + msg->len) == (msg->buf.ptr + msg->buf.len));
}

static size_t msg_len(const void *start, struct outbuf *msg)
{
	return (msg->ptr - start) / sizeof (uint64_t);
}

/*
 * Build and emit structures.
 *
 * - the *_INIT macros exist because remembering to correctly
 *   initializing .TYPE##_len is a pain
 *
 * - the *_INIT expand to the structures contents, and not the the
 *   brace wrapped structure because it ends up expanding MACRO({ a,
 *   b, c}) and that confuses the compiler, sigh.
 *
 * - it's assumed that, at all times, the chunk has correct memory
 *   alignment; that holds for pfkeyV2
 */

#define SADB_INIT(TYPE, ...)						\
	.TYPE##_len = sizeof(struct TYPE) / sizeof(uint64_t),		\
		##__VA_ARGS__						\

#define SADB_EXT_INIT(TYPE, EXTTYPE, ...)				\
	SADB_INIT(TYPE, .TYPE##_exttype = EXTTYPE, ##__VA_ARGS__)

#define put_sadb_struct(MSG, TYPE, ...)					\
	({								\
		struct TYPE ps_thing_ = { __VA_ARGS__ };		\
		struct outbuf *ps_req_ = MSG;				\
		struct TYPE *ps_ptr_ = hunk_put_thing(ps_req_, ps_thing_); \
		ldbg_##TYPE(ps_req_->logger, ps_ptr_, "put ");		\
		ps_ptr_;						\
	})

#define put_sadb(MSG, TYPE, ...)					\
	put_sadb_struct(MSG, TYPE, SADB_INIT(TYPE, __VA_ARGS__))

#define padup_sadb(MSG, NAME)						\
	({								\
		struct outbuf *req_ = MSG; /* eval once */		\
		/* ASSUME TYPE and VARIABLE have same name! */		\
		struct sadb_##NAME *ext_ = NAME; /* eval once */	\
		/* pad to 64-bit boundary */				\
		unsigned pad_ = req_->len % sizeof(uint64_t);		\
		req_->ptr += pad_;					\
		req_->len -= pad_;					\
		/* XXX: pexpect ..._len == sizeof(TYPE) */		\
		ext_->sadb_##NAME##_len = msg_len(ext_, req_);		\
		ldbg_sadb_##NAME(req_->logger, NAME, " padup ");		\
	})

#define put_sadb_ext(REQ, TYPE, EXTTYPE, ...)				\
	put_sadb_struct(REQ, TYPE, SADB_EXT_INIT(TYPE, EXTTYPE, __VA_ARGS__))

struct pending {
	chunk_t msg;
	struct list_entry entry;
};

static void jam_pending(struct jambuf *buf, const struct pending *pending)
{
	jam(buf, "%p", pending);
}

LIST_INFO(pending, entry, pending_info, jam_pending);

static struct list_head pending_queue = INIT_LIST_HEAD(&pending_queue, &pending_info);

struct inbuf {
	const char *what;
	chunk_t buf;
	shunk_t msg;
	shunk_t msgbase;
	uint8_t buffer[65536];
};

static void queue_msg(const struct inbuf *msg)
{
	struct pending *pending = alloc_thing(struct pending, __func__);
	/* assume MSG still points at the entire buffer */
	pending->msg = clone_hunk(msg->buf, __func__);
	init_list_entry(&pending_info, pending, &pending->entry);
	insert_list_entry(&pending_queue, &pending->entry);
}

static bool recv_msg(struct inbuf *msg, const char *what, struct logger *logger)
{
	*msg = (struct inbuf) { .what = what, };
	ssize_t s = recv(pfkeyv2_fd, msg->buffer, sizeof(msg->buffer), /*flags*/0);
	if (s < 0) {
		llog_errno(RC_LOG_SERIOUS, logger, errno,
			   "receiving %s response: ", what);
		return false;
	}

	ldbg(logger, "read %zd bytes", s);
	msg->buf = chunk2(msg->buffer, s);
	ldbg_msg(logger, msg->buf.ptr, msg->buf.len, "%s:", msg->what);

	return true;
}

static bool msg_recv(struct inbuf *msg, const char *what, const struct sadb_msg *req, struct logger *logger)
{
	while (true) {
		if (!recv_msg(msg, what, logger)) {
			return false;
		}

		msg->msg = shunk2(msg->buf.ptr, msg->buf.len);
		const struct sadb_msg *base = get_sadb_msg(&msg->msg, &msg->msgbase, logger);
		if (base == NULL) {
			llog_pexpect(logger, HERE, "no base");
			return false;
		}

		if (base->sadb_msg_seq != req->sadb_msg_seq) {
			llog_pexpect(logger, HERE, "wrong base");
			/* XXX: need to trigger event */
			queue_msg(msg);
			continue;
		}

		/*
		 * XXX: update when SA expired?
		 */
		if (base->sadb_msg_errno == ENOENT) {
			llog_pexpect(logger, HERE, "ENOENT returned");
			return true;
		}

		if (base->sadb_msg_errno != 0) {
			llog_errno(RC_LOG, logger, base->sadb_msg_errno, "bad response");
			return false;
		}

		return true;
	}
}

static bool msg_sendrecv(struct outbuf *req, struct sadb_msg *msg, struct inbuf *recv)
{
	padup_sadb(req, msg);
	ldbg_msg(req->logger, req->buf.ptr, req->buf.len, "sending %s:", req->what);
	ssize_t s = send(pfkeyv2_fd, req->buf.ptr, req->ptr - (void*)req->buf.ptr, 0);
	if (s < 0) {
		fatal_errno(PLUTO_EXIT_KERNEL_FAIL, req->logger, errno,
			    "sending %s: ", req->what);
		return false;
	}

	return msg_recv(recv, req->what, msg, req->logger);
}

static struct sadb_msg *put_sadb_base(struct outbuf *msg,
				      enum sadb_type type,
				      enum sadb_satype satype,
				      unsigned seq)
{
	struct sadb_msg *base = put_sadb(msg, sadb_msg,
					 .sadb_msg_version = PF_KEY_V2,
					 .sadb_msg_type = type,
					 .sadb_msg_errno = 0,
					 .sadb_msg_satype = satype,
					 .sadb_msg_seq = seq,
					 .sadb_msg_pid = pfkeyv2_pid);
	return base;
}

static struct sadb_sa *put_sadb_sa(struct outbuf *msg,
				   ipsec_spi_t spi,
				   enum sadb_satype satype,
				   enum sadb_sastate state,
				   unsigned replay,
				   const struct integ_desc *integ,
				   const struct encrypt_desc *encrypt,
				   const struct ipcomp_desc *ipcomp)
{
	unsigned aalg = (integ != NULL ? integ->integ_sadb_aalg_id :
			 0);
	unsigned ealg = (encrypt != NULL ? encrypt->encrypt_sadb_ealg_id :
			 /* XXX: NetBSD treats IPCOMP like ENCRYPT */
			 ipcomp != NULL ? ipcomp->kernel.sadb_calg_id :
			 0);

	struct sadb_sa tmp = {
		SADB_EXT_INIT(sadb_sa, sadb_ext_sa,
			      .sadb_sa_replay = replay,
			      .sadb_sa_state = state,
			      .sadb_sa_spi = spi,
			      .sadb_sa_auth = aalg,
			      .sadb_sa_encrypt = ealg),
	};
	struct sadb_sa *sa = hunk_put_thing(msg, tmp);
	ldbg_sadb_sa(msg->logger, satype, sa, "put ");
	return sa;
}

static struct sadb_sa *put_sadb_sa__spi(struct outbuf *msg, ipsec_spi_t spi)
{
	return put_sadb_sa(msg, spi, 0, 0, 0, NULL, NULL, 0);
}

static struct ip_sockaddr *put_ip_sockaddr(struct outbuf *msg,
					   const ip_address *addr)
{
	ip_sockaddr sa = sockaddr_from_address(*addr);
	return hunk_put(msg, &sa.sa, sa.len);
}

static struct sadb_address *put_sadb_selector(struct outbuf *msg,
					      enum sadb_exttype srcdst,
					      const ip_selector *selector)
{
	const struct ip_protocol *protocol = selector_protocol(*selector);
	enum ipsec_proto proto = (protocol == &ip_protocol_all ? ipsec_proto_any/*255*/ :
				  protocol != NULL ? protocol->ipproto :
				  pexpect(0));
	ip_address prefix = selector_prefix(*selector);
	unsigned prefix_len = selector_prefix_bits(*selector);
	struct sadb_address *address =
		put_sadb_ext(msg, sadb_address, srcdst,
			     .sadb_address_proto = proto,
			     .sadb_address_prefixlen = prefix_len);
	put_ip_sockaddr(msg, &prefix);
	padup_sadb(msg, address);
	return address;
}

static struct sadb_address *put_sadb_address(struct outbuf *msg,
					     enum sadb_exttype srcdst,
					     const ip_address *addr)
{
	const struct ip_info *afi = address_type(addr);
	struct sadb_address *address =
		put_sadb_ext(msg, sadb_address, srcdst,
			     .sadb_address_proto = ipsec_proto_any/*255*/,
			     .sadb_address_prefixlen = afi->mask_cnt);
	put_ip_sockaddr(msg, addr);
	padup_sadb(msg, address);
	return address;
}

static struct sadb_key *put_sadb_key(struct outbuf *msg,
				     enum sadb_exttype key_alg,
				     shunk_t keyval)
{
	struct sadb_key *key =
		put_sadb_ext(msg, sadb_key, key_alg,
			     .sadb_key_bits = keyval.len * BITS_PER_BYTE);
	if (hunk_put_hunk(msg, keyval) == NULL) {
		llog_passert(msg->logger, HERE, "bad key(E)");
	}
	padup_sadb(msg, key);
	return key;
}

static struct sadb_spirange *put_sadb_spirange(struct outbuf *msg, uintmax_t min, uintmax_t max)
{
	struct sadb_spirange *spirange =
		put_sadb_ext(msg, sadb_spirange, sadb_ext_spirange,
			     .sadb_spirange_min = min,
			     .sadb_spirange_max = max);
	return spirange;
}

static struct sadb_x_sa2 *put_sadb_x_sa2(struct outbuf *msg,
					 enum ipsec_mode ipsec_mode,
					 reqid_t reqid)
{
	struct sadb_x_sa2 *x_sa2 =
		put_sadb_ext(msg, sadb_x_sa2, sadb_x_ext_sa2,
			     .sadb_x_sa2_mode = ipsec_mode,
			     .sadb_x_sa2_sequence = 0,/*SPD sequence?*/
			     .sadb_x_sa2_reqid = reqid);
	return x_sa2;
}

static struct sadb_msg *msg_base(struct outbuf *msg, const char *what,
				 chunk_t buf,
				 enum sadb_type type,
				 enum sadb_satype satype,
				 struct logger *logger)
{
	*msg = (struct outbuf) {
		.buf = buf,
		.ptr = buf.ptr,
		.len = buf.len,
		.what = what,
		.seq = ++pfkeyv2_seq,
		.logger = logger,
	};
	ldbg_outbuf(logger, msg);
	struct sadb_msg *base = put_sadb_base(msg, type, satype, msg->seq);
	return base;
}

static enum sadb_satype proto_satype(const struct ip_protocol *proto)
{
	return (proto == &ip_protocol_esp ? sadb_satype_esp :
		proto == &ip_protocol_ah ? sadb_satype_ah :
		proto == &ip_protocol_ipcomp ? sadb_x_satype_ipcomp :
		pexpect(0));
}

static void register_satype(const struct ip_protocol *proto, struct logger *logger)
{
	ldbg(logger, "sending %s request", proto->name);

	uint8_t reqbuf[SIZEOF_SADB_BASE];
	struct outbuf req;
	struct sadb_msg *base = msg_base(&req, __func__,
					 chunk2(reqbuf, sizeof(reqbuf)),
					 sadb_register, proto_satype(proto), logger);

	struct inbuf resp;
	if (!msg_sendrecv(&req, base, &resp)) {
		return;
	}

	while (resp.msgbase.len > 0) {

		shunk_t msgext;
		const struct sadb_ext *ext =
			get_sadb_ext(&resp.msgbase, &msgext, logger);
		if (ext == NULL) {
			llog_pexpect(logger, HERE, "bad ext");
			return;
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {
		case sadb_ext_supported_auth:
		case sadb_ext_supported_encrypt:
		{
			const struct sadb_supported *supported =
				hunk_get_thing(&msgext, const struct sadb_supported);
			if (supported == NULL) {
				llog_pexpect(logger, HERE, "bad ext");
				return;
			}
			ldbg_sadb_supported(logger, supported, "get ");

			unsigned nr_algs = ((supported->sadb_supported_len * sizeof(uint64_t) -
					     sizeof(struct sadb_supported)) / sizeof(struct sadb_alg));
			for (unsigned n = 0; n < nr_algs; n++) {

				const struct sadb_alg *alg =
					hunk_get_thing(&msgext, const struct sadb_alg);
				if (alg == NULL) {
					llog_pexpect(logger, HERE, "bad ext");
					return;
				}

				enum sadb_exttype exttype = supported->sadb_supported_exttype;
				ldbg_sadb_alg(logger, exttype, alg, "get ");

				switch (exttype) {
				case sadb_ext_supported_auth:
				{
					const struct integ_desc *integ =
						integ_desc_by_sadb_aalg_id(alg->sadb_alg_id);
					if (integ != NULL) {
						kernel_integ_add(integ);
					}
					break;
				}
				case sadb_ext_supported_encrypt:
				{
					const struct encrypt_desc *encrypt =
						encrypt_desc_by_sadb_ealg_id(alg->sadb_alg_id);
					if (encrypt != NULL) {
						kernel_encrypt_add(encrypt);
					}
					break;
				}
				default:
					llog_pexpect(logger, HERE, "unknown");
					break;
				}
			}
			break;
		}
		default:
			llog_pexpect(logger, HERE, "unknown ext");
			break;
		}
	}
}

static void pfkeyv2_init(struct logger *logger)
{
	ldbg(logger, "initializing PFKEY V2");

	pfkeyv2_pid = getpid();

	/* initialize everything */
	pfkeyv2_fd = socket(PF_KEY, SOCK_RAW|SOCK_CLOEXEC, PF_KEY_V2);
	if (pfkeyv2_fd < 0) {
		fatal_errno(PLUTO_EXIT_KERNEL_FAIL, logger, errno,
			    "opening PF_KEY_V2 socket failed");
	}
	ldbg(logger, "pfkey opened on %d with CLOEXEC", pfkeyv2_fd);

	/* register everything */

	register_satype(&ip_protocol_ah, logger);
	register_satype(&ip_protocol_esp, logger);
	register_satype(&ip_protocol_ipcomp, logger);
}

static ipsec_spi_t pfkeyv2_get_ipsec_spi(ipsec_spi_t avoid UNUSED,
					 const ip_address *src,
					 const ip_address *dst,
					 const struct ip_protocol *proto,
					 bool tunnel_mode,
					 reqid_t reqid,
					 uintmax_t min, uintmax_t max,
					 const char *story UNUSED,	/* often SAID string */
					 struct logger *logger)
{
	/* GETSPI */
	/* send: <base, address, SPI range> */
	/* recv: <base, SA(*), address(SD)> */

	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_X_SA2 +
		       SIZEOF_SADB_ADDRESS * 2 +
		       SIZEOF_SADB_SPIRANGE];
	struct outbuf req;
	struct sadb_msg *base = msg_base(&req, __func__,
					 chunk2(reqbuf, sizeof(reqbuf)),
					 sadb_getspi, proto_satype(proto), logger);

	/*
	 * XXX: the PF_KEY_V2 RFC didn't leave space to specify REQID
	 * and/or transport mode (tunnel was assumed).
	 *
	 * SADB_X_SA2 provides a way to specify that (it's optional,
	 * but since the REQID is always specified, it might as well
	 * be included).
	 */
	put_sadb_x_sa2(&req,
		       (tunnel_mode ? ipsec_mode_tunnel : ipsec_mode_transport),
		       reqid);

	put_sadb_address(&req, sadb_ext_address_src, src);
	put_sadb_address(&req, sadb_ext_address_dst, dst);
	put_sadb_spirange(&req, min, max);

	struct inbuf resp;
	if (!msg_sendrecv(&req, base, &resp)) {
		return 0;
	}

	ipsec_spi_t spi = 0;
	while (resp.msgbase.len > 0) {

		shunk_t msgext;
		const struct sadb_ext *ext =
			get_sadb_ext(&resp.msgbase, &msgext, logger);
		if (msgext.ptr == NULL) {
			llog_pexpect(logger, HERE, "bad ext");
			return 0;
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {
		case sadb_ext_sa:
		{
			const struct sadb_sa *sa =
				hunk_get_thing(&msgext, const struct sadb_sa);
			if (sa == NULL) {
				llog_pexpect(logger, HERE, "getting sa");
				return 0;
			}
			ldbg_sadb_sa(logger, base->sadb_msg_satype, sa, "get ");
			spi = sa->sadb_sa_spi;
			break;
		}
		case sadb_ext_address_src:
		case sadb_ext_address_dst:
			/* ignore these */
			break;
		default:
			llog_pexpect(logger, HERE, "bad ext");
			break;
		}
	}
	return spi;
}

static bool pfkeyv2_del_ipsec_spi(ipsec_spi_t spi,
				  const struct ip_protocol *proto,
				  const ip_address *src_address,
				  const ip_address *dst_address,
				  const char *story UNUSED,
				  struct logger *logger)
{
	/* DEL */
	/* send: <base, SA(*), address(SD)> */
	/* recv: <base, SA(*), address(SD)> */

	/* base */

	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_SA +
		       SIZEOF_SADB_X_SA2 +
		       SIZEOF_SADB_ADDRESS * 2];
	struct outbuf req;
	struct sadb_msg *base = msg_base(&req, __func__,
					 chunk2(reqbuf, sizeof(reqbuf)),
					 sadb_delete, proto_satype(proto), logger);

	/* SA(*) */

	put_sadb_sa__spi(&req, spi);

	/* address(SD) */

	put_sadb_address(&req, sadb_ext_address_src, src_address);
	put_sadb_address(&req, sadb_ext_address_dst, dst_address);

	struct inbuf recv;
	if (!msg_sendrecv(&req, base, &recv)) {
		llog_pexpect(logger, HERE, "bad");
		return false;
	}

	return true;
}

static bool pfkeyv2_add_sa(const struct kernel_sa *k,
			   bool replace,
			   struct logger *logger)
{
	/* UPDATE <base, SA, (lifetime(HSC),) address(SD),
	   (address(P),) key(AE), (identity(SD),) (sensitivity)> */
	/* ADD <base, SA, (lifetime(HS),) address(SD), (address(P),)
	   key(AE), (identity(SD),) (sensitivity)> */

	enum sadb_type type = (replace ? sadb_update : sadb_add);

	/*
	 * .esatype:
	 *
	 * Will IPCOMP ever happen, since sensible code will compress
	 * than encrypt, it should be either AH or ESP on the wire
	 * (but contradicting this is a setkey examples showing how to
	 * do the reverse - compress the encrypted payload - ewww).
	 *
	 * Technicall, it can be UDP that goes over the wire, not
	 * AH/ESP.
	 */
	const struct ip_protocol *proto = (k->esatype == ET_IPCOMP ? &ip_protocol_ipcomp :
					   k->esatype == ET_AH ? &ip_protocol_ah :
					   k->esatype == ET_ESP ? &ip_protocol_esp :
					   NULL);
	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_SA +
		       SIZEOF_SADB_LIFETIME * 3 +
		       SIZEOF_SADB_ADDRESS * 3 +
		       SIZEOF_SADB_KEY * 2 +
		       SIZEOF_SADB_IDENT * 2 +
		       SIZEOF_SADB_SENS];
	struct outbuf req;
	struct sadb_msg *base = msg_base(&req, __func__,
					 chunk2(reqbuf, sizeof(reqbuf)),
					 type, proto_satype(proto), logger);

	/* SA */

	put_sadb_sa(&req, k->spi,
		    base->sadb_msg_satype,
		    sadb_sastate_larval/*XXX: sadb_sastate_mature*/,
		    k->replay_window,
		    k->integ, k->encrypt, k->ipcomp);

	/*
	 * X_SA2
	 *
	 * This is needed to specify the stuff that should have been
	 * included in SA, notably tunnel vs transport and reqid
	 *
	 * Tunnel only applies to the inner most encapsulation.
	 * Right?  Why?  Which means it applies to the packet
	 * interface.
	 *
	 * XXX: why not just set "tunnel" on the inner-most kernel_sa?
	 */
	put_sadb_x_sa2(&req,
		       (k->level == 0 && k->tunnel ?  ipsec_mode_tunnel : ipsec_mode_transport),
		       k->reqid);

	/* address(SD) */

	put_sadb_address(&req, sadb_ext_address_src, k->src.address);
	put_sadb_address(&req, sadb_ext_address_dst, k->dst.address);

	/* (address(P)) */

	/* key(AE[C]) (AUTH/INTEG/IPCOMP) */
	switch (k->esatype) {
	case ET_AH:
		put_sadb_key(&req, sadb_ext_key_auth, shunk2(k->authkey, k->authkeylen));
		break;
	case ET_ESP:
		put_sadb_key(&req, sadb_ext_key_encrypt, shunk2(k->enckey, k->enckeylen));
		put_sadb_key(&req, sadb_ext_key_auth, shunk2(k->authkey, k->authkeylen));
		break;
	case ET_IPCOMP:
		break;
	default:
		llog_passert(logger, HERE, "bad key(A)");
	}

	/* (lifetime(HSC)) */

	put_sadb_ext(&req, sadb_lifetime, sadb_ext_lifetime_hard,
		     .sadb_lifetime_addtime = deltasecs(k->sa_lifetime));
	put_sadb_ext(&req, sadb_lifetime, sadb_ext_lifetime_soft,
		     .sadb_lifetime_addtime =  deltasecs(k->sa_lifetime));

	/* (identity(SD)) */

	/* (sensitivity) */

	/* UPDATE */
        /* <base, SA, (lifetime(HSC),) address(SD), (address(P),)
	   (identity(SD),) (sensitivity)> */
	/* ADD */
	/* <base, SA, (lifetime(HS),) address(SD), (identity(SD),)
	   (sensitivity)> */

	struct inbuf recv;
	if (!msg_sendrecv(&req, base, &recv)) {
		llog_pexpect(logger, HERE, "bad");
		return false;
	}

	return true;
}

static bool pfkeyv2_get_sa(const struct kernel_sa *k,
			   uint64_t *bytes,
			   uint64_t *add_time,
			   struct logger *logger)
{
	/* GET */
	/* <base, SA(*), address(SD)> */
	/* <base, SA, (lifetime(HSC),) address(SD), (address(P),) key(AE),
           (identity(SD),) (sensitivity)> */

	/* <base> */

	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_SA +
		       SIZEOF_SADB_ADDRESS * 2];
	struct outbuf req;
	struct sadb_msg *base = msg_base(&req, __func__,
					 chunk2(reqbuf, sizeof(reqbuf)),
					 sadb_get, proto_satype(k->proto), logger);

	/* SA(*) */

	put_sadb_sa__spi(&req, k->spi);

	/* address(SD) */

	put_sadb_address(&req, sadb_ext_address_src, k->src.address);
	put_sadb_address(&req, sadb_ext_address_dst, k->dst.address);

	struct inbuf resp;
	if (!msg_sendrecv(&req, base, &resp)) {
		llog_pexpect(logger, HERE, "bad");
		return false;
	}

	while (resp.msgbase.len > 0) {

		shunk_t msgext;
		const struct sadb_ext *ext =
			get_sadb_ext(&resp.msgbase, &msgext, logger);
		if (msgext.ptr == NULL) {
			llog_pexpect(logger, HERE, "bad ext");
			return false;
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {
		case sadb_ext_lifetime_current:
		{
			const struct sadb_lifetime *lifetime =
				hunk_get_thing(&msgext, const struct sadb_lifetime);
			if (lifetime == NULL) {
				llog_pexpect(logger, HERE, "getting policy");
				return 0;
			}
			ldbg_sadb_lifetime(logger, lifetime, "get ");
			*bytes = lifetime->sadb_lifetime_bytes;
			*add_time = lifetime->sadb_lifetime_addtime;
			break;
		}
		case sadb_ext_address_dst:
		case sadb_ext_address_src:
		case sadb_ext_key_auth:
		case sadb_ext_key_encrypt:
		case sadb_ext_sa:
		case sadb_x_ext_sa2:
		case sadb_x_ext_nat_t_type:
		case sadb_ext_lifetime_hard:
		case sadb_ext_lifetime_soft:
			/* ignore these */
			break;
		default:
			ldbg_sadb_ext(logger, ext, "get_sa ");
			llog_pexpect(logger, HERE, "bad ext");
			break;
		}
	}

	return false;
}

static struct sadb_x_ipsecrequest *put_sadb_x_ipsecrequest(struct outbuf *msg,
							   const struct kernel_policy *kernel_policy,
							   enum ipsec_mode mode,
							   const struct kernel_policy_rule *rule)
{
	/*
	 * XXX: sadb_x_ipsecrequest screwed up the LEN parameter; it's
	 * in bytes.
	 */
	struct sadb_x_ipsecrequest *x_ipsecrequest =
		put_sadb(msg, sadb_x_ipsecrequest,
			 .sadb_x_ipsecrequest_proto = rule->proto,
			 .sadb_x_ipsecrequest_mode = mode,
			 .sadb_x_ipsecrequest_level = ipsec_level_require,
			 .sadb_x_ipsecrequest_reqid = /*rule->reqid*/0);
	/*
	 * setkey(8) man page says that transport mode doesn't require
	 * policy addresses (presumably the packet's address can be
	 * used).
	 *
	 * draft-schilcher-mobike-pfkey-extension-01 goes further and
	 * states: In the case that transport mode is used, no
	 * additional addresses are specified.
	 */
	if (mode == IPSEC_MODE_TUNNEL) {
		put_ip_sockaddr(msg, &kernel_policy->src.host);
		put_ip_sockaddr(msg, &kernel_policy->dst.host);
	}
	padup_sadb(msg, x_ipsecrequest);
	/* patch up mess? */
	x_ipsecrequest->sadb_x_ipsecrequest_len *= sizeof(uint64_t);
	return x_ipsecrequest;
}

static struct sadb_x_policy *put_sadb_x_policy(struct outbuf *req,
					       enum kernel_policy_op op,
					       enum ipsec_policy policy_type,
					       const struct kernel_policy *kernel_policy)
{

	enum ipsec_dir policy_dir =
		((op & KERNEL_POLICY_INBOUND) ? ipsec_dir_inbound :
		 (op & KERNEL_POLICY_OUTBOUND) ? ipsec_dir_outbound :
		 pexpect(0));

	struct sadb_x_policy *x_policy =
		put_sadb_ext(req, sadb_x_policy, sadb_x_ext_policy,
			     .sadb_x_policy_type = policy_type,
			     .sadb_x_policy_dir = policy_dir);

	if (kernel_policy != NULL && kernel_policy->nr_rules > 0) {
		pexpect((op & KERNEL_POLICY_ADD) ||
			(op & KERNEL_POLICY_REPLACE));
		pexpect(policy_type == ipsec_policy_ipsec);
		/*
		 * XXX: Only the first rule gets the worm; er tunnel
		 * flag.
		 *
		 * Should the caller take care of this?
		 */
		enum ipsec_mode mode = (kernel_policy->mode == ENCAP_MODE_TUNNEL ? ipsec_mode_tunnel :
					ipsec_mode_transport);
		for (unsigned i = 1; i <= kernel_policy->nr_rules; i++) {
			const struct kernel_policy_rule *rule = &kernel_policy->rule[i];
			put_sadb_x_ipsecrequest(req, kernel_policy, mode, rule);
			mode = ipsec_mode_transport;
		}
	} else if (policy_type == ipsec_policy_ipsec) {
		pexpect(op & KERNEL_POLICY_DELETE);
	}

	padup_sadb(req, x_policy);
	return x_policy;
}

static bool pfkeyv2_raw_policy(enum kernel_policy_op op,
			       enum expect_kernel_policy what_about_inbound UNUSED,
			       const ip_selector *src_client,
			       const ip_selector *dst_client,
			       enum shunt_policy shunt_policy,
			       const struct kernel_policy *kernel_policy,
			       deltatime_t use_lifetime UNUSED,
			       uint32_t sa_priority UNUSED,
			       const struct sa_marks *sa_marks UNUSED,
			       const struct pluto_xfrmi *xfrmi UNUSED,
			       const shunk_t sec_label UNUSED,
			       struct logger *logger)
{
	/* SPDADD */
	/* <base, policy, address(SD), [lifetime(HS)]> */
	/* <base, policy, address(SD), [lifetime(HS)]> */

	enum sadb_type type = ((op & KERNEL_POLICY_ADD) ? sadb_x_spdadd :
			       (op & KERNEL_POLICY_DELETE) ? sadb_x_spddelete :
			       (op & KERNEL_POLICY_REPLACE) ? sadb_x_spdupdate :
			       pexpect(0));
	/* what NetBSD expects */
	enum sadb_satype satype = sadb_satype_unspec;
	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_X_POLICY +
		       SIZEOF_SADB_ADDRESS * 2 +
		       SIZEOF_SADB_LIFETIME * 2];
	struct outbuf req;
	struct sadb_msg *base = msg_base(&req, __func__,
					 chunk2(reqbuf, sizeof(reqbuf)),
					 type, satype, logger);

	/* address(SD) */

	put_sadb_selector(&req, sadb_ext_address_src, src_client);
	put_sadb_selector(&req, sadb_ext_address_dst, dst_client);

	/* [lifetime(HSC)] */

	put_sadb_ext(&req, sadb_lifetime, sadb_ext_lifetime_hard);

	/* policy */

	enum ipsec_policy policy_type = UINT_MAX;
	switch (shunt_policy) {
	case SHUNT_PASS:
		policy_type = ipsec_policy_none;
		break;
	case SHUNT_UNSET:
		policy_type = ipsec_policy_ipsec;
		/* XXX: XFRM also considers delete here? */
		break;
	case SHUNT_HOLD:
		pexpect(0);
		return true; /* lie */
	case SHUNT_TRAP:
		policy_type = ipsec_policy_ipsec;
		break;
	case SHUNT_DROP:
	case SHUNT_REJECT:
	case SHUNT_NONE:
		policy_type = ipsec_policy_discard;
		break;
	}
	pexpect(policy_type != UINT_MAX);

	put_sadb_x_policy(&req, op, policy_type, kernel_policy);

	/* send/req */

	struct inbuf resp;
	if (!msg_sendrecv(&req, base, &resp)) {
		llog_pexpect(logger, HERE, "receiving");
		return false;
	}

	return true;
}

static bool process_address(shunk_t *ext_cursor, ip_address *addr, ip_port *port, struct logger *logger)
{
	shunk_t address_cursor;
	const struct sadb_address *address =
		get_sadb_address(ext_cursor, &address_cursor, logger);
	if (address == NULL) {
		return false;
	}
	ldbg_sadb_address(logger, address, "  ");
	if (!get_sadb_sockaddr_address_port(&address_cursor, addr, port, logger)) {
		return false;
	}
	address_buf ab;
	port_buf pb;
	ldbg(logger, "    %s:%s", str_address(addr, &ab), str_hport(*port, &pb));
	return true;
}

static void process_acquire(shunk_t base_cursor, struct logger *logger)
{
	ip_address src_address = unset_address;
	ip_address dst_address = unset_address;
	ip_port src_port, dst_port;

	while (base_cursor.len > 0) {

		shunk_t ext_cursor;
		const struct sadb_ext *ext =
			get_sadb_ext(&base_cursor, &ext_cursor, logger);
		if (ext == NULL) {
			llog_pexpect(logger, HERE, "bad ext");
			return;
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {

		case sadb_ext_address_src:
			if (!process_address(&ext_cursor, &src_address, &src_port, logger)) {
				return;
			}
			break;
		case sadb_ext_address_dst:
			if (!process_address(&ext_cursor, &dst_address, &dst_port, logger)) {
				return;
			}
			break;
		case sadb_x_ext_policy:
		case sadb_ext_proposal:
			ldbg_sadb_ext(logger, ext, "ignore: ");
			break;
		default:
			ldbg_sadb_ext(logger, ext, "huh? ");
			break;
		}
	}

	if (address_is_unset(&src_address) || address_is_unset(&dst_address)) {
		ldbg(logger, "something isn't set");
		return;
	}

	ip_packet packet = packet_from_raw(HERE,
					   address_type(&src_address),
					   &src_address.bytes,
					   &dst_address.bytes,
					   &ip_protocol_all,
					   src_port,
					   dst_port);
	initiate_ondemand(&packet,
			  /*by_acquire*/true,
			  /*background?*/true/*no whack so doesn't matter*/,
			  null_shunk,
			  logger);
}

static void process_pending(chunk_t msg, struct logger *logger)
{
	ldbg_msg(logger, msg.ptr, msg.len, "pending ");

	shunk_t cursor = HUNK_AS_SHUNK(msg);
	shunk_t base_cursor;
	const struct sadb_msg *base = get_sadb_msg(&cursor, &base_cursor, logger);
	if (base == NULL) {
		llog_pexpect(logger, HERE, "no base");
	}

	switch (base->sadb_msg_type) {
	case sadb_acquire:
		process_acquire(base_cursor, logger);
		break;
	}
}

static void process_pending_queue(struct logger *logger)
{
	struct pending *pending;
	FOR_EACH_LIST_ENTRY_OLD2NEW(&pending_queue, pending) {
		remove_list_entry(&pending->entry);
		process_pending(pending->msg, logger);
		free_chunk_content(&pending->msg);
		pfree(pending);
	}
}

static void pfkeyv2_process_msg(int fd UNUSED, struct logger *logger)
{
	ldbg(logger, "processing message");
	struct inbuf msg;
	if (!recv_msg(&msg, "process", logger)) {
		return;
	}
	queue_msg(&msg);
	process_pending_queue(logger);
}

static const char *pfkeyv2_protostack_names[] = {
	"pfkeyv2",
	"pfkey",
#ifndef KERNEL_BSDKAME /* provide compatible name */
	"bsdkame",
#endif
	NULL,
};

const struct kernel_ops pfkeyv2_kernel_ops = {
	.protostack_names = pfkeyv2_protostack_names,
	.updown_name = "bsd",
	.interface_name = "PF_KEY v2",
	.overlap_supported = false,	/* XXX: delete this? */
	.sha2_truncbug_support = false,
	.esn_supported = false,		/* but is on FreeBSD and OpenBSD? */
	.replay_window = 64,
	.async_fdp = &pfkeyv2_fd,	/* XXX: fix code using this not checking for >0 */
	.route_fdp = NULL,		/* XXX: what is this? */

	.init = pfkeyv2_init,
	.get_ipsec_spi = pfkeyv2_get_ipsec_spi,
	.del_ipsec_spi = pfkeyv2_del_ipsec_spi,
	.add_sa = pfkeyv2_add_sa,
	.get_sa = pfkeyv2_get_sa,
	.raw_policy = pfkeyv2_raw_policy,
	.process_msg = pfkeyv2_process_msg,
};
