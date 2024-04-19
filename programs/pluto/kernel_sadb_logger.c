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

#include "kernel_sadb.h"

#include "lswlog.h"
#include "ip_protocol.h"
#include "ip_sockaddr.h"
#include "ip_info.h"

typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;
typedef uint64_t u64_t;

/*
 * XXX: the double macro is so that the parameters (which might be
 * defines) are expanded before being passed on.  For instance, given:
 *
 *   #define foo bar
 *   J(P, foo, F)
 *
 * will expand to:
 *
 *   J2(P, bar, F)
 */

#define JAM(P, T, F) JAM_2(P, T, F)
#define JAM_2(P, T, F) jam(buf, " "#F"=%"PRI##P, (P##_t)m->T##_##F)

#define JAM_RAW(T, F) JAM_RAW_2(T, F)
#define JAM_RAW_2(T, F)							\
	{								\
		jam(buf, " "#F"=");					\
		jam_hex_bytes(buf, &m->T##_##F, sizeof(m->T##_##F));	\
	}

#define JAM_SPARSE(E, T, F)						\
	{								\
		jam(buf, " "#F"=%lu", (long unsigned)m->T##_##F);	\
		const char *name = sparse_name(E, m->T##_##F);		\
		if (name != NULL) {					\
			jam(buf, "(%s)", name);				\
		}							\
	}

#define JAM_SPARSE_SPARSE(NAMES, I0, T, F)				\
	{								\
		jam(buf, " "#F"=%lu", (long unsigned)m->T##_##F);	\
		const char *name = sparse_sparse_name(NAMES, I0, m->T##_##F); \
		if (name != NULL) {					\
			jam(buf, "(%s)", name);				\
		}							\
	}

#define JAM_SPARSE_LSET(NAMES, T, F)					\
	{								\
		jam(buf, " "#F"=%lu=", (long unsigned)m->T##_##F);	\
		jam_sparse_lset(buf, NAMES, m->T##_##F);		\
	}

#define JAM_HEADER(T)							\
	struct logjam logjam;						\
	struct jambuf *buf = jambuf_from_logjam(&logjam, logger,	\
						0, NULL, rc_flags);	\
	jam_string(buf, what);						\
	jam(buf, #T" @%p", m);

#define JAM_FOOTER()				\
	logjam_to_logger(&logjam);

#define JAM_HEADER_SADB(T)					\
	JAM_HEADER(T);						\
	JAM_LEN(T, len);					\
	JAM_SPARSE(&sadb_exttype_names, T, exttype);

#define JAM_SADB(T, F)							\
	JAM_SPARSE(&sadb_##F##_names, T, F)

#define JAM_IPSEC(T, F)							\
	JAM_SPARSE(&ipsec_##F##_names, T, F)

#define JAM_LEN_MULTIPLIER(T, F, LEN_MULTIPLIER)			\
	jam(buf, " "#F"=%"PRIu16"(%zu)",				\
	    m->T##_##F, m->T##_##F * LEN_MULTIPLIER)
#define JAM_LEN(T, F)					\
	JAM_LEN_MULTIPLIER(T, F, sizeof(uint64_t))

void llog_sadb_address(lset_t rc_flags, struct logger *logger,
		       const struct sadb_address *m, const char *what)
{
	JAM_HEADER_SADB(sadb_address);

#ifdef __OpenBSD__
	JAM_RAW(sadb_address, reserved);
#else
	JAM_SADB(sadb_address, proto);
	JAM(u8, sadb_address, prefixlen);
#endif

	JAM_FOOTER();
}

void llog_sadb_alg(lset_t rc_flags, struct logger *logger,
		   enum sadb_exttype exttype,
		   const struct sadb_alg *m,
		   const char *what)
{
	JAM_HEADER(sadb_alg);

	JAM_SPARSE_SPARSE(&sadb_alg_names, exttype, sadb_alg, id);
	JAM(u8, sadb_alg, ivlen);
	JAM(u16, sadb_alg, minbits);
	JAM(u16, sadb_alg, maxbits);
	JAM_RAW(sadb_alg, reserved);

	JAM_FOOTER();
}

void llog_sadb_comb(lset_t rc_flags, struct logger *logger,
		    const struct sadb_comb *m, const char *what)
{
	JAM_HEADER(sadb_comb);

	JAM_SPARSE(&sadb_aalg_names, sadb_comb, auth);
	JAM_SPARSE(&sadb_ealg_names, sadb_comb, encrypt);
	JAM(u16, sadb_comb, flags);
	JAM(u16, sadb_comb, auth_minbits);
	JAM(u16, sadb_comb, auth_maxbits);
	JAM(u16, sadb_comb, encrypt_minbits);
	JAM(u16, sadb_comb, encrypt_maxbits);
	JAM_RAW(sadb_comb, reserved);
	JAM(u32, sadb_comb, soft_allocations);
	JAM(u32, sadb_comb, hard_allocations);
	JAM(u64, sadb_comb, soft_bytes);
	JAM(u64, sadb_comb, hard_bytes);
	JAM(u64, sadb_comb, soft_addtime);
	JAM(u64, sadb_comb, hard_addtime);
	JAM(u64, sadb_comb, soft_usetime);
	JAM(u64, sadb_comb, hard_usetime);

	JAM_FOOTER();
}

void llog_sadb_ext(lset_t rc_flags, struct logger *logger,
		   const struct sadb_ext *m, const char *what)
{
	JAM_HEADER(sadb_ext);

	JAM_LEN(sadb_ext, len);
	JAM_SPARSE(&sadb_exttype_names, sadb_ext, type);

	JAM_FOOTER();
}

void llog_sadb_ident(lset_t rc_flags, struct logger *logger,
		     const struct sadb_ident *m, const char *what)
{
	JAM_HEADER_SADB(sadb_ident);

	JAM(u16, sadb_ident, type);
	JAM_RAW(sadb_ident, reserved);
	JAM(u64, sadb_ident, id);

	JAM_FOOTER();
}

void llog_sadb_key(lset_t rc_flags, struct logger *logger,
		   const struct sadb_key *m, const char *what)
{
	JAM_HEADER_SADB(sadb_key);

	JAM(u16, sadb_key, bits);
	JAM_RAW(sadb_key, reserved);

	JAM_FOOTER();
}

void llog_sadb_lifetime(lset_t rc_flags, struct logger *logger,
			const struct sadb_lifetime *m, const char *what)
{
	JAM_HEADER_SADB(sadb_lifetime);

	JAM(u32, sadb_lifetime, allocations);
	JAM(u64, sadb_lifetime, bytes);
	JAM(u64, sadb_lifetime, addtime);
	JAM(u64, sadb_lifetime, usetime);

	JAM_FOOTER();
}

void llog_sadb_msg(lset_t rc_flags, struct logger *logger,
		   const struct sadb_msg *m, const char *what)
{
	JAM_HEADER(sadb_msg);

	JAM(u8, sadb_msg, version);
	JAM_SADB(sadb_msg, type);
	JAM(u8, sadb_msg, errno);
	JAM_SADB(sadb_msg, satype);
	JAM_LEN(sadb_msg, len);
	JAM_RAW(sadb_msg, reserved);
	JAM(u32, sadb_msg, seq);
	JAM(u32, sadb_msg, pid);

	JAM_FOOTER();
}

void llog_sadb_prop(lset_t rc_flags, struct logger *logger,
		    const struct sadb_prop *m, const char *what)
{
	JAM_HEADER_SADB(sadb_prop);

#ifdef sadb_prop_num
	JAM(u8, sadb_prop, num);
#endif
	JAM(u8, sadb_prop, replay);
	JAM_RAW(sadb_prop, reserved);

	JAM_FOOTER();
}

void llog_sadb_sa(lset_t rc_flags, struct logger *logger,
		  enum sadb_satype satype,
		  const struct sadb_sa *m,
		  const char *what)
{
	JAM_HEADER_SADB(sadb_sa);

	jam(buf, " spi=%u(%x)", ntohl(m->sadb_sa_spi), ntohl(m->sadb_sa_spi));
	JAM(u8, sadb_sa, replay);
	JAM_SPARSE(&sadb_sastate_names, sadb_sa, state);
	JAM_SPARSE_SPARSE(&sadb_satype_aalg_names, satype, sadb_sa, auth);
	JAM_SPARSE_SPARSE(&sadb_satype_ealg_names, satype, sadb_sa, encrypt);
	JAM_SPARSE_LSET(&sadb_saflag_names, sadb_sa, flags);

	JAM_FOOTER();
}

void llog_sadb_sens(lset_t rc_flags, struct logger *logger,
		    const struct sadb_sens *m, const char *what)
{
	JAM_HEADER_SADB(sadb_sens);

	JAM(u32, sadb_sens, dpd);
	JAM(u8, sadb_sens, sens_level);
	JAM(u8, sadb_sens, sens_len);
	JAM(u8, sadb_sens, integ_level);
	JAM(u8, sadb_sens, integ_len);
	JAM_RAW(sadb_sens, reserved);

	JAM_FOOTER();
}

void llog_sadb_spirange(lset_t rc_flags, struct logger *logger,
			const struct sadb_spirange *m, const char *what)
{
	JAM_HEADER_SADB(sadb_spirange);

	JAM(u32, sadb_spirange, min);
	JAM(u32, sadb_spirange, max);
	JAM_RAW(sadb_spirange, reserved);

	JAM_FOOTER();
}

void llog_sadb_supported(lset_t rc_flags, struct logger *logger,
			 const struct sadb_supported *m, const char *what)
{
	JAM_HEADER_SADB(sadb_supported);

	JAM_RAW(sadb_supported, reserved);

	JAM_FOOTER();
}

#ifdef SADB_X_EXT_POLICY
void llog_sadb_x_ipsecrequest(lset_t rc_flags, struct logger *logger,
			      const struct sadb_x_ipsecrequest *m, const char *what)
{
	JAM_HEADER(sadb_x_ipsecrequest);

	JAM_LEN_MULTIPLIER(sadb_x_ipsecrequest, len, sizeof(uint8_t)); /* XXX: screwup */
	JAM_IPSEC(sadb_x_ipsecrequest, proto);
	JAM_IPSEC(sadb_x_ipsecrequest, mode);
	JAM_IPSEC(sadb_x_ipsecrequest, level);
#ifdef sadb_x_ipsecrequest_reserved1
	JAM_RAW(sadb_x_ipsecrequest, reserved1);
#endif
	JAM(u16, sadb_x_ipsecrequest, reqid);
#ifdef sadb_x_ipsecrequest_reserved1
	JAM_RAW(sadb_x_ipsecrequest, reserved2);
#endif

	JAM_FOOTER();
}
#endif

#ifdef SADB_X_EXT_NAT_T_FRAG
void llog_sadb_x_nat_t_frag(lset_t rc_flags, struct logger *logger,
			    const struct sadb_x_nat_t_frag *m, const char *what)
{
	JAM_HEADER_SADB(sadb_x_nat_t_frag);

	JAM(u16, sadb_x_nat_t_frag, fraglen);
	JAM_RAW(sadb_x_nat_t_frag, reserved);

	JAM_FOOTER();
}
#endif

#ifdef SADB_X_EXT_NAT_T_PORT
void llog_sadb_x_nat_t_port(lset_t rc_flags, struct logger *logger,
			    const struct sadb_x_nat_t_port *m, const char *what)
{
	JAM_HEADER_SADB(sadb_x_nat_t_port);

	JAM(u16, sadb_x_nat_t_port, port);
	JAM_RAW(sadb_x_nat_t_port, reserved);

	JAM_FOOTER();
}
#endif

#ifdef SADB_X_EXT_NAT_T_TYPE
void llog_sadb_x_nat_t_type(lset_t rc_flags, struct logger *logger,
			    const struct sadb_x_nat_t_type *m, const char *what)
{
	JAM_HEADER_SADB(sadb_x_nat_t_type);

	JAM(u8, sadb_x_nat_t_type, type);
	JAM_RAW(sadb_x_nat_t_type, reserved);

	JAM_FOOTER();
}
#endif

#ifdef SADB_X_EXT_POLICY
void llog_sadb_x_policy(lset_t rc_flags, struct logger *logger,
			const struct sadb_x_policy *m, const char *what)
{
	JAM_HEADER_SADB(sadb_x_policy);

	JAM_SPARSE(&ipsec_policy_names, sadb_x_policy, type); /* POLICY <> TYPE */
	/* XXX: broken; needs sparse_sparse_names; */
	JAM_IPSEC(sadb_x_policy, dir);
#if defined sadb_x_policy_scope
	JAM(u8, sadb_x_policy, scope);
#elif defined sadb_x_policy_flags
	JAM(u8, sadb_x_policy, flags);
#else
	JAM_RAW(sadb_x_policy, reserved);
#endif
	JAM(u32, sadb_x_policy, id);
#ifdef sadb_x_policy_priority
	JAM(u32, sadb_x_policy, priority);
#else
	JAM_RAW(sadb_x_policy, reserved2);
#endif

	JAM_FOOTER();
}
#endif

#ifdef SADB_X_EXT_PROTOCOL
void llog_sadb_protocol(lset_t rc_flags, struct logger *logger,
			const struct sadb_protocol *m, const char *what)
{
	JAM_HEADER_SADB(sadb_protocol);

	JAM_SPARSE_SPARSE(sadb_protocol_proto_names, m->sadb_protocol_exttype,
			  sadb_protocol, proto);
	JAM_SPARSE(sadb_protocol_direction_names, sadb_protocol, direction);
	JAM(u8, sadb_protocol, flags);
	JAM_RAW(sadb_protocol, reserved2);

	JAM_FOOTER();
};
#endif

#ifdef SADB_X_EXT_SA2
void llog_sadb_x_sa2(lset_t rc_flags, struct logger *logger,
		     const struct sadb_x_sa2 *m, const char *what)
{
	JAM_HEADER_SADB(sadb_x_sa2);

	JAM_IPSEC(sadb_x_sa2, mode);
	JAM_RAW(sadb_x_sa2, reserved1);
	JAM_RAW(sadb_x_sa2, reserved2);
	JAM(u32, sadb_x_sa2, sequence);
	JAM(u32, sadb_x_sa2, reqid);

	JAM_FOOTER();
}
#endif

#ifdef SADB_X_EXT_SA_REPLAY
void llog_sadb_x_sa_replay(lset_t rc_flags, struct logger *logger,
			   const struct sadb_x_sa_replay *m, const char *what)
{
	JAM_HEADER_SADB(sadb_x_sa_replay);

	JAM(u32, sadb_x_sa_replay, replay);

	JAM_FOOTER();
}
#endif

#ifdef SADB_X_EXT_COUNTER
void llog_sadb_x_counter(lset_t rc_flags, struct logger *logger,
			 const struct sadb_x_counter *m, const char *what)
{
	JAM_HEADER_SADB(sadb_x_counter);

	JAM(u32,  sadb_x_counter, pad);
	JAM(u64, sadb_x_counter, ipackets);	/* Input IPsec packets */
	JAM(u64, sadb_x_counter, opackets);	/* Output IPsec packets */
	JAM(u64, sadb_x_counter, ibytes);	/* Input bytes */
	JAM(u64, sadb_x_counter, obytes);	/* Output bytes */
	JAM(u64, sadb_x_counter, idrops);	/* Dropped on input */
	JAM(u64, sadb_x_counter, odrops);	/* Dropped on output */
	JAM(u64, sadb_x_counter, idecompbytes);	/* Input bytes, decompressed */
	JAM(u64, sadb_x_counter, ouncompbytes);	/* Output bytes, uncompressed */

	JAM_FOOTER();
}
#endif

#ifdef SADB_X_EXT_REPLAY /* OpenBSD */
void llog_sadb_x_replay(lset_t rc_flags, struct logger *logger,
			const struct sadb_x_replay *m, const char *what)
{
	JAM_HEADER_SADB(sadb_x_replay);

	JAM_RAW(sadb_x_replay, reserved);
	JAM(u64, sadb_x_replay, count); /* number of replays detected? */

	JAM_FOOTER();
}
#endif

#ifdef SADB_X_EXT_UDPENCAP /* OpenBSD */
void llog_sadb_x_udpencap(lset_t rc_flags, struct logger *logger,
			const struct sadb_x_udpencap *m, const char *what)
{
	JAM_HEADER_SADB(sadb_x_udpencap);

	JAM(u16, sadb_x_udpencap, port);
	JAM_RAW(sadb_x_udpencap, reserved);

	JAM_FOOTER();
}
#endif

void llog_sadb(lset_t rc_flags, struct logger *logger,
	       const void *ptr, size_t len, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	LDBG_va_list(logger, fmt, ap);
	va_end(ap);

	shunk_t msg_cursor = shunk2(ptr, len);

	shunk_t base_cursor;
	const struct sadb_msg *base = get_sadb_msg(&msg_cursor, &base_cursor, logger);
	if (base == NULL) {
		llog_passert(logger, HERE, "wrong base");
	}

	llog_sadb_msg(rc_flags, logger, base, " ");

	while (base_cursor.len > 0) {

		shunk_t ext_cursor; /* includes SADB_EXT */
		const struct sadb_ext *ext =
			get_sadb_ext(&base_cursor, &ext_cursor, logger);
		if (ext == NULL) {
			llog_passert(logger, HERE, "bad ext");
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {

		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
#ifdef SADB_X_EXT_SRC_FLOW
		case SADB_X_EXT_SRC_FLOW:
#endif
#ifdef SADB_X_EXT_DST_FLOW
		case SADB_X_EXT_DST_FLOW:
#endif
#ifdef SADB_X_EXT_SRC_MASK
		case SADB_X_EXT_SRC_MASK:
#endif
#ifdef SADB_X_EXT_DST_MASK
		case SADB_X_EXT_DST_MASK:
#endif
		{
			shunk_t address_cursor;
			const struct sadb_address *address =
				get_sadb_address(&ext_cursor, &address_cursor, logger);
			if (address == NULL) {
				return;
			}
			llog_sadb_address(rc_flags, logger, address, "  ");
			ip_address addr;
			ip_port port;
			if (!get_sadb_sockaddr_address_port(&address_cursor, &addr, &port, logger)) {
				return;
			}
			address_buf ab;
			port_buf pb;
			DBG_log("    %s:%s", str_address_wrapped(&addr, &ab), str_hport(port, &pb));
			/* no PEXPECT(logger, address_cursor.len == 0); may be padded */
			break;
		}

		case SADB_EXT_KEY_ENCRYPT:
		case SADB_EXT_KEY_AUTH:
		{
			shunk_t key_cursor;
			const struct sadb_key *key =
				get_sadb_key(&ext_cursor, &key_cursor, logger);
			if (key == NULL) {
				return;
			}
			llog_sadb_key(rc_flags, logger, key, "  ");
			LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
				jam(buf, "   ");
				jam_dump_hunk(buf, key_cursor);
			}
			/* no PEXPECT(logger, address_cursor.len == 0); allow any length+padding */
			break;
		}

		case SADB_EXT_LIFETIME_SOFT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_CURRENT:
#ifdef SADB_X_EXT_LIFETIME_LASTUSE
		case SADB_X_EXT_LIFETIME_LASTUSE:
#endif
		{
			shunk_t lifetime_cursor;
			const struct sadb_lifetime *lifetime =
				get_sadb_lifetime(&ext_cursor, &lifetime_cursor, logger);
			if (lifetime == NULL) {
				return;
			}
			llog_sadb_lifetime(rc_flags, logger, lifetime, "  ");
			PEXPECT(logger, lifetime_cursor.len == 0); /* nothing following */
			break;
		}

		case SADB_EXT_PROPOSAL:
		{
			shunk_t prop_cursor;
			const struct sadb_prop *prop =
				get_sadb_prop(&ext_cursor, &prop_cursor, logger);
			if (prop == NULL) {
				return;
			}
			llog_sadb_prop(rc_flags, logger, prop, "  ");

			unsigned nr_comb = 0;
			while (prop_cursor.len > 0) {
				const struct sadb_comb *comb =
					hunk_get_thing(&prop_cursor, const struct sadb_comb);
				if (comb == NULL) {
					break;
				}
				nr_comb++;
				llog_sadb_comb(rc_flags, logger, comb, "   ");
			}
			PEXPECT(logger, prop_cursor.len == 0); /* nothing left */
			/* from the RFC */
			PEXPECT(logger,
				nr_comb == ((prop->sadb_prop_len * sizeof(uint64_t) -
					     sizeof(struct sadb_prop)) /
					    sizeof(struct sadb_comb)));
			break;
		}

		case SADB_EXT_SA:
		{
			shunk_t sa_cursor;
			const struct sadb_sa *sa =
				get_sadb_sa(&ext_cursor, &sa_cursor, logger);
			if (sa == NULL) {
				return;
			}
			llog_sadb_sa(rc_flags, logger, base->sadb_msg_satype, sa, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}

		case SADB_EXT_SPIRANGE:
		{
			shunk_t spirange_cursor;
			const struct sadb_spirange *spirange =
				get_sadb_spirange(&ext_cursor, &spirange_cursor, logger);
			if (spirange == NULL) {
				return;
			}
			llog_sadb_spirange(rc_flags, logger, spirange, "  ");
			PEXPECT(logger, spirange_cursor.len == 0); /* nothing following */
			break;
		}

		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
#ifdef SADB_X_EXT_SUPPORTED_COMP
		case SADB_X_EXT_SUPPORTED_COMP:
#endif
		{
			shunk_t supported_cursor;
			const struct sadb_supported *supported =
				get_sadb_supported(&ext_cursor, &supported_cursor, logger);
			if (supported == NULL) {
				return;
			}
			llog_sadb_supported(rc_flags, logger, supported, "  ");

			unsigned nr_algs = 0;
			while (supported_cursor.len > 0) {
				const struct sadb_alg *alg =
					hunk_get_thing(&supported_cursor, const struct sadb_alg);
				if (alg == NULL) {
					break;
				}
				nr_algs++;
				llog_sadb_alg(rc_flags, logger, exttype, alg, "   ");
			}
			PEXPECT(logger, supported_cursor.len == 0); /* nothing left */
			/* from the RFC */
			PEXPECT(logger,
				nr_algs == ((supported->sadb_supported_len * sizeof(uint64_t) -
					     sizeof(struct sadb_supported)) / sizeof(struct sadb_alg)));
			break;
		}

#ifdef SADB_X_EXT_POLICY
		case SADB_X_EXT_POLICY:
		{
			shunk_t x_policy_cursor;
			const struct sadb_x_policy *x_policy =
				get_sadb_x_policy(&ext_cursor, &x_policy_cursor, logger);
			if (x_policy == NULL) {
				return;
			}
			llog_sadb_x_policy(rc_flags, logger, x_policy, "  ");

			while (x_policy_cursor.len > 0) {
				shunk_t x_ipsecrequest_cursor;
				const struct sadb_x_ipsecrequest *x_ipsecrequest =
					get_sadb_x_ipsecrequest(&x_policy_cursor, &x_ipsecrequest_cursor, logger);
				if (x_ipsecrequest == NULL) {
					break;
				}
				llog_sadb_x_ipsecrequest(rc_flags, logger, x_ipsecrequest, "   ");
				while (x_ipsecrequest_cursor.len > 0) {
					/* can't assume sockaddr is aligned */
					ip_address address;
					ip_port port;
					if (!get_sadb_sockaddr_address_port(&x_ipsecrequest_cursor,
									    &address, &port, logger)) {
						break;
					}
					address_buf ab;
					port_buf pb;
					DBG_log("     %s:%s", str_address_wrapped(&address, &ab), str_hport(port, &pb));
				}
			}
			PEXPECT(logger, ext_cursor.len == 0);
			break;
		}
#endif

#ifdef SADB_X_EXT_NAT_T_TYPE
		case SADB_X_EXT_NAT_T_TYPE:
		{
			shunk_t x_nat_t_type_cursor;
			const struct sadb_x_nat_t_type *x_nat_t_type =
				get_sadb_x_nat_t_type(&ext_cursor, &x_nat_t_type_cursor, logger);
			if (x_nat_t_type == NULL) {
				return;
			}
			llog_sadb_x_nat_t_type(rc_flags, logger, x_nat_t_type, "  ");
			PEXPECT(logger, x_nat_t_type_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_SA2
		case SADB_X_EXT_SA2:
		{
			shunk_t x_sa2_cursor;
			const struct sadb_x_sa2 *x_sa2 =
				get_sadb_x_sa2(&ext_cursor, &x_sa2_cursor, logger);
			if (x_sa2 == NULL) {
				return;
			}
			llog_sadb_x_sa2(rc_flags, logger, x_sa2, "  ");
			PEXPECT(logger, x_sa2_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_SA_REPLAY
		case SADB_X_EXT_SA_REPLAY:
		{
			shunk_t sa_cursor;
			const struct sadb_x_sa_replay *x_sa_replay =
				get_sadb_x_sa_replay(&ext_cursor, &sa_cursor, logger);
			if (x_sa_replay == NULL) {
				return;
			}
			llog_sadb_x_sa_replay(rc_flags, logger, x_sa_replay, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_COUNTER
		case SADB_X_EXT_COUNTER:
		{
			shunk_t sa_cursor;
			const struct sadb_x_counter *x_counter =
				get_sadb_x_counter(&ext_cursor, &sa_cursor, logger);
			if (x_counter == NULL) {
				return;
			}
			llog_sadb_x_counter(rc_flags, logger, x_counter, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_PROTOCOL
#ifdef SADB_X_EXT_FLOW_TYPE
		case SADB_X_EXT_FLOW_TYPE:
#endif
		case SADB_X_EXT_PROTOCOL:
		{
			shunk_t sa_cursor;
			const struct sadb_protocol *protocol =
				get_sadb_protocol(&ext_cursor, &sa_cursor, logger);
			if (protocol == NULL) {
				return;
			}
			llog_sadb_protocol(rc_flags, logger, protocol, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_REPLAY /* OpenBSD */
		case SADB_X_EXT_REPLAY:
		{
			shunk_t sa_cursor;
			const struct sadb_x_replay *x_replay =
				get_sadb_x_replay(&ext_cursor, &sa_cursor, logger);
			if (x_replay == NULL) {
				return;
			}
			llog_sadb_x_replay(rc_flags, logger, x_replay, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_UDPENCAP
		case SADB_X_EXT_UDPENCAP:
		{
			shunk_t sa_cursor;
			const struct sadb_x_udpencap *x_udpencap =
				get_sadb_x_udpencap(&ext_cursor, &sa_cursor, logger);
			if (x_udpencap == NULL) {
				return;
			}
			llog_sadb_x_udpencap(rc_flags, logger, x_udpencap, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}
#endif

		default:
		{
			llog_sadb_ext(ERROR_FLAGS, logger, ext, PEXPECT_PREFIX);
			llog_pexpect(logger, HERE, "unexpected payload");
			break;
		}
		}
	}
}
