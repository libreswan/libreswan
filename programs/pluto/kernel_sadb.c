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

#define J(P, T, F) J2(P, T, F)
#define J2(P, T, F) jam(buf, " "#F"=%"PRI##P, (P##_t)m->T##_##F)

#define JX(T, F) JX2(T, F)
#define JX2(T, F)							\
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

#define JAM_SADB(T, F)							\
	JAM_SPARSE(sadb_##F##_names, T, F)

#define JAM_IPSEC(T, F)							\
	JAM_SPARSE(ipsec_##F##_names, T, F)

#define JAM_LEN_MULTIPLIER(T, F, LEN_MULTIPLIER)			\
	jam(buf, " "#F"=%"PRIu16"(%zu)",				\
	    m->T##_##F, m->T##_##F * LEN_MULTIPLIER)
#define JAM_LEN(T, F)					\
	JAM_LEN_MULTIPLIER(T, F, sizeof(uint64_t))

void DBG_sadb_alg(struct logger *logger,
		  enum sadb_exttype exttype,
		  const struct sadb_alg *m,
		  const char *what)
{
	char tmp[200];
	struct jambuf buf = ARRAY_AS_JAMBUF(tmp);
	jam_string(&buf, what);
	jam_sadb_alg(&buf, exttype, m);
	jambuf_to_logger(&buf, logger, DEBUG_STREAM);
}

void DBG_sadb_sa(struct logger *logger,
		 enum sadb_satype satype,
		 const struct sadb_sa *m,
		 const char *what)
{
	char tmp[200];
	struct jambuf buf = ARRAY_AS_JAMBUF(tmp);
	jam_string(&buf, what);
	jam_sadb_sa(&buf, satype, m);
	jambuf_to_logger(&buf, logger, DEBUG_STREAM);
}

void jam_sadb_address(struct jambuf *buf, const struct sadb_address *m)
{
	jam(buf, "sadb_address @%p:", m);
	JAM_LEN(sadb_address, len);
	JAM_SADB(sadb_address, exttype);
#ifdef __OpenBSD__
	JX(sadb_address, reserved);
#else
	JAM_SADB(sadb_address, proto);
	J(u8, sadb_address, prefixlen);
#endif
}

void jam_sadb_alg(struct jambuf *buf, enum sadb_exttype exttype, const struct sadb_alg *m)
{
	jam(buf, "sadb_alg @%p", m);
	JAM_SPARSE_SPARSE(sadb_alg_names, exttype, sadb_alg, id);
	J(u8, sadb_alg, ivlen);
	J(u16, sadb_alg, minbits);
	J(u16, sadb_alg, maxbits);
	JX(sadb_alg, reserved);
}

void jam_sadb_comb(struct jambuf *buf, const struct sadb_comb *m)
{
	jam(buf, "sadb_comb @%p", m);
	JAM_SPARSE(sadb_aalg_names, sadb_comb, auth);
	JAM_SPARSE(sadb_ealg_names, sadb_comb, encrypt);
	J(u16, sadb_comb, flags);
	J(u16, sadb_comb, auth_minbits);
	J(u16, sadb_comb, auth_maxbits);
	J(u16, sadb_comb, encrypt_minbits);
	J(u16, sadb_comb, encrypt_maxbits);
	JX(sadb_comb, reserved);
	J(u32, sadb_comb, soft_allocations);
	J(u32, sadb_comb, hard_allocations);
	J(u64, sadb_comb, soft_bytes);
	J(u64, sadb_comb, hard_bytes);
	J(u64, sadb_comb, soft_addtime);
	J(u64, sadb_comb, hard_addtime);
	J(u64, sadb_comb, soft_usetime);
	J(u64, sadb_comb, hard_usetime);
}

void jam_sadb_ext(struct jambuf *buf, const struct sadb_ext *m)
{
	jam(buf, "sadb_ext @%p", m);
	JAM_LEN(sadb_ext, len);
	JAM_SPARSE(sadb_exttype_names, sadb_ext, type);
}

void jam_sadb_ident(struct jambuf *buf, const struct sadb_ident *m)
{
	jam(buf, "sadb_ident @%p", m);
	JAM_LEN(sadb_ident, len);
	JAM_SADB(sadb_ident, exttype);
	J(u16, sadb_ident, type);
	JX(sadb_ident, reserved);
	J(u64, sadb_ident, id);
}

void jam_sadb_key(struct jambuf *buf, const struct sadb_key *m)
{
	jam(buf, "sadb_key @%p", m);
	JAM_LEN(sadb_key, len);
	JAM_SADB(sadb_key, exttype);
	J(u16, sadb_key, bits);
	JX(sadb_key, reserved);
}

void jam_sadb_lifetime(struct jambuf *buf, const struct sadb_lifetime *m)
{
	jam(buf, "sadb_lifetime @%p:", m);
	JAM_LEN(sadb_lifetime, len);
	JAM_SADB(sadb_lifetime, exttype);
	J(u32, sadb_lifetime, allocations);
	J(u64, sadb_lifetime, bytes);
	J(u64, sadb_lifetime, addtime);
	J(u64, sadb_lifetime, usetime);
}

void jam_sadb_msg(struct jambuf *buf, const struct sadb_msg *m)
{
	jam(buf, "sadb_msg @%p:", m);
	J(u8, sadb_msg, version);
	JAM_SADB(sadb_msg, type);
	J(u8, sadb_msg, errno);
	JAM_SADB(sadb_msg, satype);
	JAM_LEN(sadb_msg, len);
	JX(sadb_msg, reserved);
	J(u32, sadb_msg, seq);
	J(u32, sadb_msg, pid);
}

void jam_sadb_prop(struct jambuf *buf, const struct sadb_prop *m)
{
	jam(buf, "sadb_prop @%p", m);
	JAM_LEN(sadb_prop, len);
	JAM_SADB(sadb_prop, exttype);
#ifdef sadb_prop_num
	J(u8, sadb_prop, num);
#endif
	J(u8, sadb_prop, replay);
	JX(sadb_prop, reserved);
}

void jam_sadb_sa(struct jambuf *buf, enum sadb_satype satype, const struct sadb_sa *m)
{
	jam(buf, "sadb_sa @%p:", m);
	JAM_LEN(sadb_sa, len);
	JAM_SADB(sadb_sa, exttype);
	jam(buf, " spi=%u(%x)", ntohl(m->sadb_sa_spi), ntohl(m->sadb_sa_spi));
	J(u8, sadb_sa, replay);
	JAM_SPARSE(sadb_sastate_names, sadb_sa, state);
	JAM_SPARSE_SPARSE(sadb_satype_aalg_names, satype, sadb_sa, auth);
	JAM_SPARSE_SPARSE(sadb_satype_ealg_names, satype, sadb_sa, encrypt);
	JAM_SPARSE_LSET(sadb_saflag_names, sadb_sa, flags);
}

void jam_sadb_sens(struct jambuf *buf, const struct sadb_sens *m)
{
	jam(buf, "sadb_sens @%p", m);
	JAM_LEN(sadb_sens, len);
	JAM_SADB(sadb_sens, exttype);
	J(u32, sadb_sens, dpd);
	J(u8, sadb_sens, sens_level);
	J(u8, sadb_sens, sens_len);
	J(u8, sadb_sens, integ_level);
	J(u8, sadb_sens, integ_len);
	JX(sadb_sens, reserved);
}

void jam_sadb_spirange(struct jambuf *buf, const struct sadb_spirange *m)
{
	jam(buf, "sadb_spirange @%p", m);
	JAM_LEN(sadb_spirange, len);
	JAM_SADB(sadb_spirange, exttype);
	J(u32, sadb_spirange, min);
	J(u32, sadb_spirange, max);
	JX(sadb_spirange, reserved);
}

void jam_sadb_supported(struct jambuf *buf, const struct sadb_supported *m)
{
	jam(buf, "sadb_supported @%p", m);
	JAM_LEN(sadb_supported, len);
	JAM_SADB(sadb_supported, exttype);
	JX(sadb_supported, reserved);
}

#ifdef SADB_X_EXT_POLICY
void jam_sadb_x_ipsecrequest(struct jambuf *buf, const struct sadb_x_ipsecrequest *m)
{
	jam(buf, "sadb_x_ipsecrequest @%p", m);
	JAM_LEN_MULTIPLIER(sadb_x_ipsecrequest, len, sizeof(uint8_t)); /* XXX: screwup */
	JAM_IPSEC(sadb_x_ipsecrequest, proto);
	JAM_IPSEC(sadb_x_ipsecrequest, mode);
	JAM_IPSEC(sadb_x_ipsecrequest, level);
#ifdef sadb_x_ipsecrequest_reserved1
	J(u16, sadb_x_ipsecrequest, reserved1);
#endif
	J(u16, sadb_x_ipsecrequest, reqid);
#ifdef sadb_x_ipsecrequest_reserved1
	J(u16, sadb_x_ipsecrequest, reserved2);
#endif
}
#endif

#ifdef SADB_X_EXT_NAT_T_FRAG
void jam_sadb_x_nat_t_frag(struct jambuf *buf, const struct sadb_x_nat_t_frag *m)
{
	jam(buf, "sadb_x_nat_t_frag @%p", m);
	JAM_LEN(sadb_x_nat_t_frag, len);
	JAM_SADB(sadb_x_nat_t_frag, exttype);
	J(u16, sadb_x_nat_t_frag, fraglen);
	JX(sadb_x_nat_t_frag, reserved);
}
#endif

#ifdef SADB_X_EXT_NAT_T_PORT
void jam_sadb_x_nat_t_port(struct jambuf *buf, const struct sadb_x_nat_t_port *m)
{
	jam(buf, "sadb_x_nat_t_port @%p", m);
	JAM_LEN(sadb_x_nat_t_port, len);
	JAM_SADB(sadb_x_nat_t_port, exttype);
	J(u16, sadb_x_nat_t_port, port);
	JX(sadb_x_nat_t_port, reserved);
}
#endif

#ifdef SADB_X_EXT_NAT_T_TYPE
void jam_sadb_x_nat_t_type(struct jambuf *buf, const struct sadb_x_nat_t_type *m)
{
	jam(buf, "sadb_x_nat_t_type @%p", m);
	JAM_LEN(sadb_x_nat_t_type, len);
	JAM_SADB(sadb_x_nat_t_type, exttype);
	J(u8, sadb_x_nat_t_type, type);
	JX(sadb_x_nat_t_type, reserved);
}
#endif

#ifdef SADB_X_EXT_POLICY
void jam_sadb_x_policy(struct jambuf *buf, const struct sadb_x_policy *m)
{
	jam(buf, "sadb_x_policy @%p:", m);
	JAM_LEN(sadb_x_policy, len);
	JAM_SADB(sadb_x_policy, exttype);
	JAM_SPARSE(ipsec_policy_names, sadb_x_policy, type); /* POLICY <> TYPE */
	/* XXX: broken; needs sparse_sparse_names; */
	JAM_IPSEC(sadb_x_policy, dir);
#ifdef sadb_x_policy_scope
	J(u8, sadb_x_policy, scope);
#else
	JX(sadb_x_policy, reserved);
#endif
	J(u32, sadb_x_policy, id);
#ifdef sadb_x_policy_priority
	J(u32, sadb_x_policy, priority);
#else
	JX(sadb_x_policy, reserved2);
#endif
}
#endif

#ifdef SADB_X_EXT_PROTOCOL
void jam_sadb_protocol(struct jambuf *buf, const struct sadb_protocol *m)
{
	jam(buf, "sadb_protocol @%p:", m);
	JAM_LEN(sadb_protocol, len);
	JAM_SADB(sadb_protocol, exttype);
	JAM_SPARSE_SPARSE(sadb_protocol_proto_names, m->sadb_protocol_exttype,
			  sadb_protocol, proto);
	JAM_SPARSE(sadb_protocol_direction_names, sadb_protocol, direction);
	J(u8, sadb_protocol, flags);
	J(u8, sadb_protocol, reserved2);
};
#endif

#ifdef SADB_X_EXT_SA2
void jam_sadb_x_sa2(struct jambuf *buf, const struct sadb_x_sa2 *m)
{
	jam(buf, "sadb_x_sa2 @%p:", m);
	JAM_LEN(sadb_x_sa2, len);
	JAM_SADB(sadb_x_sa2, exttype);
	JAM_IPSEC(sadb_x_sa2, mode);
	J(u8,  sadb_x_sa2, reserved1);
	J(u16, sadb_x_sa2, reserved2);
	J(u32, sadb_x_sa2, sequence);
	J(u32, sadb_x_sa2, reqid);
}
#endif

#ifdef SADB_X_EXT_SA_REPLAY
void jam_sadb_x_sa_replay(struct jambuf *buf, const struct sadb_x_sa_replay *m)
{
	jam(buf, "sadb_x_sa_replay @%p:", m);
	JAM_LEN(sadb_x_sa_replay, len);
	JAM_SADB(sadb_x_sa_replay, exttype);
	J(u32, sadb_x_sa_replay, replay);
}
#endif

#ifdef SADB_X_EXT_COUNTER
void jam_sadb_x_counter(struct jambuf *buf, const struct sadb_x_counter *m)
{
	jam(buf, "sadb_x_counter @%p:", m);
	JAM_LEN(sadb_x_counter, len);
	JAM_SADB(sadb_x_counter, exttype);
	J(u32,  sadb_x_counter, pad);
	J(u64, sadb_x_counter, ipackets);	/* Input IPsec packets */
	J(u64, sadb_x_counter, opackets);	/* Output IPsec packets */
	J(u64, sadb_x_counter, ibytes);	/* Input bytes */
	J(u64, sadb_x_counter, obytes);	/* Output bytes */
	J(u64, sadb_x_counter, idrops);	/* Dropped on input */
	J(u64, sadb_x_counter, odrops);	/* Dropped on output */
	J(u64, sadb_x_counter, idecompbytes);	/* Input bytes, decompressed */
	J(u64, sadb_x_counter, ouncompbytes);	/* Output bytes, uncompressed */
}
#endif

#ifdef SADB_X_EXT_REPLAY
void jam_sadb_x_replay(struct jambuf *buf, const struct sadb_x_replay *m)
{
	jam(buf, "sadb_x_replay @%p:", m);
	JAM_LEN(sadb_x_replay, len);
	JAM_SADB(sadb_x_replay, exttype);
	JX(sadb_x_replay, reserved);
	J(u64, sadb_x_replay, count);
}
#endif

bool get_sadb_sockaddr_address_port(shunk_t *cursor,
				    ip_address *address,
				    ip_port *port,
				    struct logger *logger)
{
	err_t err = sockaddr_to_address_port(cursor->ptr, cursor->len,
					     address, port);
	if (err != NULL) {
		llog_pexpect(logger, HERE, "invalid sockaddr: %s", err);
		return false;
	}
	const struct ip_info *afi = address_type(address);
	cursor->ptr += afi->sockaddr_size;
	cursor->len -= afi->sockaddr_size;
	return true;
}

void DBG_msg(struct logger *logger, const void *ptr, size_t len, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	DBG_va_list(fmt, ap);
	va_end(ap);

	shunk_t msg_cursor = shunk2(ptr, len);

	shunk_t base_cursor;
	const struct sadb_msg *base = get_sadb_msg(&msg_cursor, &base_cursor, logger);
	if (base == NULL) {
		llog_passert(logger, HERE, "wrong base");
	}

	DBG_sadb_msg(logger, base, " ");

	while (base_cursor.len > 0) {

		shunk_t ext_cursor; /* includes SADB_EXT */
		const struct sadb_ext *ext =
			get_sadb_ext(&base_cursor, &ext_cursor, logger);
		if (ext == NULL) {
			llog_passert(logger, HERE, "bad ext");
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {

		case sadb_ext_address_src:
		case sadb_ext_address_dst:
#ifdef SADB_X_EXT_SRC_FLOW
		case sadb_x_ext_src_flow:
#endif
#ifdef SADB_X_EXT_DST_FLOW
		case sadb_x_ext_dst_flow:
#endif
#ifdef SADB_X_EXT_SRC_MASK
		case sadb_x_ext_src_mask:
#endif
#ifdef SADB_X_EXT_DST_MASK
		case sadb_x_ext_dst_mask:
#endif
		{
			shunk_t address_cursor;
			const struct sadb_address *address =
				get_sadb_address(&ext_cursor, &address_cursor, logger);
			if (address == NULL) {
				return;
			}
			DBG_sadb_address(logger, address, "  ");
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

		case sadb_ext_key_encrypt:
		case sadb_ext_key_auth:
		{
			shunk_t key_cursor;
			const struct sadb_key *key =
				get_sadb_key(&ext_cursor, &key_cursor, logger);
			if (key == NULL) {
				return;
			}
			DBG_sadb_key(logger, key, "  ");
			LDBGP(logger, DBG_CRYPT, buf) {
				jam(buf, "   ");
				jam_dump_hunk(buf, key_cursor);
			}
			/* no PEXPECT(logger, address_cursor.len == 0); allow any length+padding */
			break;
		}

		case sadb_ext_lifetime_soft:
		case sadb_ext_lifetime_hard:
		case sadb_ext_lifetime_current:
#ifdef SADB_X_EXT_LIFETIME_LASTUSE
		case sadb_x_ext_lifetime_lastuse:
#endif
		{
			shunk_t lifetime_cursor;
			const struct sadb_lifetime *lifetime =
				get_sadb_lifetime(&ext_cursor, &lifetime_cursor, logger);
			if (lifetime == NULL) {
				return;
			}
			DBG_sadb_lifetime(logger, lifetime, "  ");
			PEXPECT(logger, lifetime_cursor.len == 0); /* nothing following */
			break;
		}

		case sadb_ext_proposal:
		{
			shunk_t prop_cursor;
			const struct sadb_prop *prop =
				get_sadb_prop(&ext_cursor, &prop_cursor, logger);
			if (prop == NULL) {
				return;
			}
			DBG_sadb_prop(logger, prop, "  ");

			unsigned nr_comb = 0;
			while (prop_cursor.len > 0) {
				const struct sadb_comb *comb =
					hunk_get_thing(&prop_cursor, const struct sadb_comb);
				if (comb == NULL) {
					break;
				}
				nr_comb++;
				DBG_sadb_comb(logger, comb, "   ");
			}
			PEXPECT(logger, prop_cursor.len == 0); /* nothing left */
			/* from the RFC */
			PEXPECT(logger,
				nr_comb == ((prop->sadb_prop_len * sizeof(uint64_t) -
					     sizeof(struct sadb_prop)) /
					    sizeof(struct sadb_comb)));
			break;
		}

		case sadb_ext_sa:
		{
			shunk_t sa_cursor;
			const struct sadb_sa *sa =
				get_sadb_sa(&ext_cursor, &sa_cursor, logger);
			if (sa == NULL) {
				return;
			}
			DBG_sadb_sa(logger, base->sadb_msg_satype, sa, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}

		case sadb_ext_spirange:
		{
			shunk_t spirange_cursor;
			const struct sadb_spirange *spirange =
				get_sadb_spirange(&ext_cursor, &spirange_cursor, logger);
			if (spirange == NULL) {
				return;
			}
			DBG_sadb_spirange(logger, spirange, "  ");
			PEXPECT(logger, spirange_cursor.len == 0); /* nothing following */
			break;
		}

		case sadb_ext_supported_auth:
		case sadb_ext_supported_encrypt:
#ifdef SADB_X_EXT_SUPPORTED_COMP
		case sadb_x_ext_supported_comp:
#endif
		{
			shunk_t supported_cursor;
			const struct sadb_supported *supported =
				get_sadb_supported(&ext_cursor, &supported_cursor, logger);
			if (supported == NULL) {
				return;
			}
			DBG_sadb_supported(logger, supported, "  ");

			unsigned nr_algs = 0;
			while (supported_cursor.len > 0) {
				const struct sadb_alg *alg =
					hunk_get_thing(&supported_cursor, const struct sadb_alg);
				if (alg == NULL) {
					break;
				}
				nr_algs++;
				DBG_sadb_alg(logger, exttype, alg, "   ");
			}
			PEXPECT(logger, supported_cursor.len == 0); /* nothing left */
			/* from the RFC */
			PEXPECT(logger,
				nr_algs == ((supported->sadb_supported_len * sizeof(uint64_t) -
					     sizeof(struct sadb_supported)) / sizeof(struct sadb_alg)));
			break;
		}

#ifdef SADB_X_EXT_POLICY
		case sadb_x_ext_policy:
		{
			shunk_t x_policy_cursor;
			const struct sadb_x_policy *x_policy =
				get_sadb_x_policy(&ext_cursor, &x_policy_cursor, logger);
			if (x_policy == NULL) {
				return;
			}
			DBG_sadb_x_policy(logger, x_policy, "  ");

			while (x_policy_cursor.len > 0) {
				shunk_t x_ipsecrequest_cursor;
				const struct sadb_x_ipsecrequest *x_ipsecrequest =
					get_sadb_x_ipsecrequest(&x_policy_cursor, &x_ipsecrequest_cursor, logger);
				if (x_ipsecrequest == NULL) {
					break;
				}
				DBG_sadb_x_ipsecrequest(logger, x_ipsecrequest, "   ");
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
		case sadb_x_ext_nat_t_type:
		{
			shunk_t x_nat_t_type_cursor;
			const struct sadb_x_nat_t_type *x_nat_t_type =
				get_sadb_x_nat_t_type(&ext_cursor, &x_nat_t_type_cursor, logger);
			if (x_nat_t_type == NULL) {
				return;
			}
			DBG_sadb_x_nat_t_type(logger, x_nat_t_type, "  ");
			PEXPECT(logger, x_nat_t_type_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_SA2
		case sadb_x_ext_sa2:
		{
			shunk_t x_sa2_cursor;
			const struct sadb_x_sa2 *x_sa2 =
				get_sadb_x_sa2(&ext_cursor, &x_sa2_cursor, logger);
			if (x_sa2 == NULL) {
				return;
			}
			DBG_sadb_x_sa2(logger, x_sa2, "  ");
			PEXPECT(logger, x_sa2_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_SA_REPLAY
		case sadb_x_ext_sa_replay:
		{
			shunk_t sa_cursor;
			const struct sadb_x_sa_replay *x_sa_replay =
				get_sadb_x_sa_replay(&ext_cursor, &sa_cursor, logger);
			if (x_sa_replay == NULL) {
				return;
			}
			DBG_sadb_x_sa_replay(logger, x_sa_replay, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_COUNTER
		case sadb_x_ext_counter:
		{
			shunk_t sa_cursor;
			const struct sadb_x_counter *x_counter =
				get_sadb_x_counter(&ext_cursor, &sa_cursor, logger);
			if (x_counter == NULL) {
				return;
			}
			DBG_sadb_x_counter(logger, x_counter, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_PROTOCOL
#ifdef SADB_X_EXT_FLOW_TYPE
		case sadb_x_ext_flow_type:
#endif
		case sadb_x_ext_protocol:
		{
			shunk_t sa_cursor;
			const struct sadb_protocol *protocol =
				get_sadb_protocol(&ext_cursor, &sa_cursor, logger);
			if (protocol == NULL) {
				return;
			}
			DBG_sadb_protocol(logger, protocol, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}
#endif

#ifdef SADB_X_EXT_REPLAY
		case sadb_x_ext_replay:
		{
			shunk_t sa_cursor;
			const struct sadb_x_replay *x_replay =
				get_sadb_x_replay(&ext_cursor, &sa_cursor, logger);
			if (x_replay == NULL) {
				return;
			}
			DBG_sadb_x_replay(logger, x_replay, "  ");
			PEXPECT(logger, sa_cursor.len == 0); /* nothing following */
			break;
		}
#endif

		default:
		{
			LLOG_JAMBUF(ERROR_FLAGS, logger, buf) {
				jam_string(buf, "EXPECTATION FAILED: unexpected payload: ");
				jam_logger_prefix(buf, logger);
				jam_sadb_ext(buf, ext);
				jam(buf, " "PRI_WHERE, pri_where(HERE));
			}
			break;
		}
		}
	}
}

const struct sadb_ext *get_sadb_ext(shunk_t *msgbase,
				    shunk_t *msgext,
				    struct logger *logger)
{
	shunk_t tmp = *msgbase;
	const struct sadb_ext *ext =
		hunk_get_thing(&tmp, const struct sadb_ext);
	PASSERT(logger, ext != NULL);

	size_t len = ext->sadb_ext_len * sizeof(uint64_t);
	if (len == 0) {
		llog_passert(logger, HERE, "have zero bytes");
	}
	if (msgbase->len < len) {
		llog_passert(logger, HERE, "have %zu bytes but should be %zu",
			     msgbase->len, len);
	}

	/* note: include EXT read above; will re-read */
	*msgext = shunk2(msgbase->ptr, len);

	/* then advance */
	msgbase->ptr += len;
	msgbase->len -= len;

	return ext;
}

/*
 * XXX: the x_ipsecrequest extension messed up the convention by
 * storing the nr-bytes in len.  Hence LEN_MULTIPLIER.
 */

#define GET_SADB(TYPE, LEN_MULTIPLIER) X_GET_SADB(TYPE, LEN_MULTIPLIER)
#define X_GET_SADB(TYPE, LEN_MULTIPLIER)				\
	const struct TYPE *get_##TYPE(shunk_t *cursor,			\
				      shunk_t *type_cursor,		\
				      struct logger *logger)		\
	{								\
		*type_cursor = null_shunk;				\
		if (sizeof(struct TYPE) > cursor->len) {		\
			llog_pexpect(logger, HERE,			\
				     "%zu-byte buffer too small for %zu-byte "#TYPE, \
				     cursor->len, sizeof(struct TYPE));	\
			return NULL;					\
		}							\
		/* SADB stream is aligned */				\
		const struct TYPE *type = cursor->ptr;			\
		size_t type_len = type->TYPE##_len * LEN_MULTIPLIER;	\
		if (type_len < sizeof(struct TYPE)) {			\
			llog_pexpect(logger, HERE,			\
				     "%zu-byte "#TYPE" bigger than "#TYPE"_len=%u(%zu-bytes)", \
				     sizeof(struct TYPE), type->TYPE##_len, type_len); \
			return NULL;					\
		}							\
		if (type_len > (cursor)->len) {				\
			llog_pexpect(logger, HERE,			\
				     "%zu-byte buffer too small for "#TYPE"_len=%u(%zu-bytes)", \
				     cursor->len, type->TYPE##_len, type_len); \
			return NULL;					\
		}							\
		/* type_cursor */					\
		(type_cursor)->ptr = (cursor)->ptr + sizeof(struct TYPE); \
		(type_cursor)->len = type_len - sizeof(struct TYPE);	\
		/* now skip to next field */				\
		(cursor)->ptr += type_len;				\
		(cursor)->len -= type_len;				\
		return type;						\
	}

GET_SADB(sadb_address, sizeof(uint64_t));
GET_SADB(sadb_key, sizeof(uint64_t));
GET_SADB(sadb_lifetime, sizeof(uint64_t));
GET_SADB(sadb_msg, sizeof(uint64_t));
GET_SADB(sadb_prop, sizeof(uint64_t));
GET_SADB(sadb_sa, sizeof(uint64_t));
GET_SADB(sadb_spirange, sizeof(uint64_t));
GET_SADB(sadb_supported, sizeof(uint64_t));
#ifdef SADB_X_EXT_POLICY
GET_SADB(sadb_x_ipsecrequest, sizeof(uint8_t)); /* XXX: see rfc, screwup */
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE
GET_SADB(sadb_x_nat_t_type, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_POLICY
GET_SADB(sadb_x_policy, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_SA2
GET_SADB(sadb_x_sa2, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_SA_REPLAY
GET_SADB(sadb_x_sa_replay, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_COUNTER
GET_SADB(sadb_x_counter, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_PROTOCOL
GET_SADB(sadb_protocol, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_REPLAY
GET_SADB(sadb_x_replay, sizeof(uint64_t));
#endif

#define DD(TYPE, ...)						\
	void DBG_##TYPE(struct logger *logger,			\
			const struct TYPE *m,			\
			const char *what)			\
	{							\
		char tmp[200];					\
		struct jambuf buf = ARRAY_AS_JAMBUF(tmp);	\
		jam_string(&buf, what);				\
		jam_##TYPE(&buf, m);				\
		jambuf_to_logger(&buf, logger, DEBUG_STREAM);	\
	}							\
								\
	void ldbg_##TYPE(struct logger *logger,			\
			 const struct TYPE *m,			\
			 const char *what)			\
	{							\
		if (DBGP(DBG_BASE)) {				\
			DBG_##TYPE(logger, m, what);		\
		}						\
	}

DD(sadb_address);
DD(sadb_comb);
DD(sadb_ext);
DD(sadb_key);
DD(sadb_lifetime);
DD(sadb_msg);
DD(sadb_prop);
DD(sadb_spirange);
DD(sadb_supported);
#ifdef SADB_X_EXT_POLICY
DD(sadb_x_ipsecrequest);
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE
DD(sadb_x_nat_t_type);
#endif
#ifdef SADB_X_EXT_POLICY
DD(sadb_x_policy);
#endif
#ifdef SADB_X_EXT_SA2
DD(sadb_x_sa2);
#endif
#ifdef SADB_X_EXT_SA_REPLAY
DD(sadb_x_sa_replay)
#endif
#ifdef SADB_X_EXT_COUNTER
DD(sadb_x_counter);
#endif
#ifdef SADB_X_EXT_PROTOCOL
DD(sadb_protocol);
#endif
#ifdef SADB_X_EXT_REPLAY
DD(sadb_x_replay)
#endif

#undef DD
