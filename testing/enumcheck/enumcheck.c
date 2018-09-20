#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "lswtool.h"

#define PREFIX "         "

enum where {
	OPTIONAL,
	PRESENT,
	ABSENT,
};

static void test_enum(enum_names *enum_test, int i,
		      enum where where)
{
	/* find a name, if any, for this value */
	const char *name = enum_name(enum_test, i);
	switch (where) {
	case OPTIONAL:
		if (name == NULL) {
			return;
		}
		break;
	case PRESENT:
		if (name == NULL) {
			printf("name for %d missing (should be present)\n", i);
			return;
		}
		break;
	case ABSENT:
		if (name != NULL) {
			printf("name for %d present (should be absent)\n", i);
		}
		return;
	}
	printf("  %3d -> %s\n", i, name);

	/*
	 * So that it is easy to see what was tested, print something
	 * for every comparison.
	 */

	if (i < 0) {
		/* we are cheating: don't do the other checks */
		return;
	}

	LSWBUF(buf) {
		printf(PREFIX "lswlog_enum %d: ", i);
		lswlog_enum(buf, enum_test, i);
		if (streq(name, buf->array)) {
			printf("OK\n");
		} else {
			printf("ERROR\n");
		}
	}

	{
		printf(PREFIX "search %s: ", name);
		int e = enum_search(enum_test, name);
		if (e != i) {
			printf("%d ERROR\n", e);
		} else {
			printf("OK\n");
		}
	}

	{
		printf(PREFIX "match %s: ", name);
		int e = enum_match(enum_test, shunk1(name));
		if (e != i) {
			printf("%d ERROR\n", e);
		} else {
			printf("OK\n");
		}
	}

	if (strchr(name, '(') != NULL) {
		char *clone = clone_str(name, "trunc_name");
		shunk_t trunc_name = shunk2(clone, strcspn(clone, "("));
		passert(clone[trunc_name.len] == '(');
		clone[trunc_name.len] = '*';
		printf(PREFIX "match "PRI_SHUNK" [trunc]: ",
		       PRI_shunk(trunc_name));
		int e = enum_match(enum_test, trunc_name);
		pfree(clone);
		if (e != i) {
			printf("%d ERROR\n", e);
		} else {
			printf("OK\n");
		}
	}

	printf(PREFIX "short_name %d: ", i);
	const char *short_name = enum_short_name(enum_test, i);
	if (short_name == NULL) {
		printf("ERROR\n");
		return;
	} else {
		printf(" OK\n");
	}

	LSWBUF(buf) {
		printf(PREFIX "lswlog_enum_short %d: ", i);
		lswlog_enum_short(buf, enum_test, i);
		if (streq(short_name, buf->array)) {
			printf("OK\n");
		} else {
			printf("ERROR\n");
		}
	}

	if (streq(short_name, name)) {
		/* remaining tests redundant */
		return;
	}

	{
		printf(PREFIX "match %s [short]: ", short_name);
		int e = enum_match(enum_test, shunk1(short_name));
		if (e != i) {
			printf("%d ERROR\n", e);
		} else {
			printf("OK\n");
		}
	}

	if (strchr(short_name, '(') != NULL) {
		char *trunc_short_name = clone_str(short_name, "trunc_short_name");
		*strchr(trunc_short_name, '(') = '\0';
		printf(PREFIX "match %s [short+trunc]: ", trunc_short_name);
		int e = enum_match(enum_test, shunk1(trunc_short_name));
		pfree(trunc_short_name);
		if (e != i) {
			printf("%d ERROR\n", e);
		} else {
			printf("OK\n");
		}
	}
}

static void test_enum_range(char *enumname, enum_names *enum_test, int floor, int long roof)
{
	printf("  %s:\n", enumname);
	for (int i = floor; i < roof; i++) {
		test_enum(enum_test, i, OPTIONAL);
	}
	printf("\n");
}

static void test_enums(char *enumname, enum_names *enum_test)
{
	printf("  %s:\n", enumname);
	int first = -1;
	int last = -1;
	for (int i = next_enum(enum_test, -1);
	     i >= 0; i = next_enum(enum_test, i)) {
		if (first < 0) {
			first = i;
		} else if (i <= first) {
			printf("enum %d <= first %d\n", i, first);
		}
		if (i <= last) {
			printf("enum %d <= last %d\n", i, last);
		}
		last = i;
		test_enum(enum_test, i, PRESENT);
	}
	test_enum(enum_test, last + 1, ABSENT);
	printf("\n");
}

static void test_enum_enum(const char *title, enum_enum_names *een,
			   unsigned long table, enum_names *en,
			   unsigned long val, bool val_ok)
{
	printf("%s:\n", title);

	{
		printf(PREFIX "enum_enum_table %lu: ", table);
		if (en == enum_enum_table(een, table)) {
			printf("OK\n");
		} else {
			printf("ERROR\n");
		}
	}

	printf(PREFIX "enum_enum_name %lu %lu: ", table, val);
	const char *name = enum_enum_name(een, table, val);
	if ((val_ok) == (name != NULL)) {
		printf("OK\n");
	} else {
		printf("ERROR\n");
	}

	printf(PREFIX "enum_name table %lu: ", val);
	if (en == NULL) {
		printf("N/A\n");
	} else if (name == enum_name(en, val)) {
		printf("OK\n");
	} else {
		printf("ERROR\n");
	}

	LSWBUF(buf) {
		printf(PREFIX "lswlog_enum_enum %lu %lu: ", table, val);
		lswlog_enum_enum(buf, een, table, val);
		/* ??? clang says that name might be NULL */
		if (val_ok && name == NULL) {
			printf("name == NULL\n");
		} else if (val_ok && streq(buf->array, name)) {
			printf("OK\n");
		} else if (strlen(buf->array) > 0) {
			printf("OK\n");
		} else {
			printf("ERROR [empty]\n");
		}
	}

	LSWBUF(buf) {
		printf(PREFIX "lswlog_enum_enum_short %lu %lu: ", table, val);
		lswlog_enum_enum_short(buf, een, table, val);
		if (val_ok && streq(buf->array, enum_short_name(en, val))) {
			printf("OK\n");
		} else if (strlen(buf->array) > 0) {
			printf("OK\n");
		} else {
			printf("ERROR [empty]\n");
		}
	}

}

static void test_enum_lset(const char *name, const enum_names *en, lset_t val)
{
	printf("  %s %" PRIxLSET ":\n", name, val);
	LSWLOG_FILE(stdout, buf) {
		lswlogs(buf, "\t<<");
		lswlog_enum_lset_short(buf, en, "+", val);
		lswlogs(buf, ">>");
	}
}

int main(int argc UNUSED, char *argv[])
{
	tool_init_log(argv[0]);

	/* don't hold back */
	setbuf(stdout, NULL);

	printf("pluto enum_names:\n\n");
	test_enums("connection_kind_names", &connection_kind_names);
	test_enums("certpolicy_type_names", &certpolicy_type_names);

	printf("IETF registry enum_names:\n\n");
	test_enum_range("version_names", &version_names, 0, 256);
	test_enums("doi_names", &doi_names);
	test_enums("ikev1_payload_names", &ikev1_payload_names);
	test_enums("ikev2_payload_names", &ikev2_payload_names);
	test_enums("payload_names_ikev1orv2", &payload_names_ikev1orv2);
	test_enums("ikev1_exchange_names", &ikev1_exchange_names);
	test_enums("ikev2_exchange_names", &ikev2_exchange_names);
	test_enums("exchange_names_ikev1orv2", &exchange_names_ikev1orv2);
	test_enums("ikev1_protocol_names", &ikev1_protocol_names);
	test_enums("ikev2_protocol_names", &ikev2_protocol_names);
	test_enums("ikev2_del_protocol_names", &ikev2_del_protocol_names);
	test_enums("isakmp_transformid_names", &isakmp_transformid_names);
	test_enums("ah_transformid_names", &ah_transformid_names);
	test_enums("esp_transformid_names", &esp_transformid_names);
	test_enums("ipcomp_transformid_names", &ipcomp_transformid_names);
	test_enum_range("oakley_attr_names", &oakley_attr_names, 0, 256);
	test_enum_range("ipsec_attr_names", &ipsec_attr_names, 0, 256);
	test_enums("sa_lifetime_names", &sa_lifetime_names);
	test_enums("oakley_lifetime_names", &oakley_lifetime_names);
	test_enum_range("oakley_auth_names", &oakley_auth_names, 0, 256);
	test_enum_range("oakley_enc_names", &oakley_enc_names, 0, 256);
	test_enums("oakley_hash_names", &oakley_hash_names);
	test_enums("oakley_group_names", &oakley_group_names);
	test_enum_range("ikev1_notify_names", &ikev1_notify_names, 0, 16384);
	test_enum_range("ikev2_notify_names", &ikev2_notify_names, 0, 16384);
	test_enums("ikev2_ts_type_names", &ikev2_ts_type_names);
	test_enums("ikev2_cp_type_names", &ikev2_cp_type_names);
	test_enums("ikev2_cp_attribute_type_names", &ikev2_cp_attribute_type_names);
	test_enums("pkk_names", &pkk_names);
	test_enum_range("enc_mode_names", &enc_mode_names, 0, 256);
	test_enums("auth_alg_names", &auth_alg_names);
	test_enums("xauth_type_names", &xauth_type_names);
	test_enum_range("xauth_attr_names", &xauth_attr_names, 0, 256);
	test_enums("attr_msg_type_names", &attr_msg_type_names);
	test_enums("ikev2_sec_proto_id_names", &ikev2_sec_proto_id_names);
	test_enums("ikev2_auth_names", &ikev2_auth_names);
	test_enum_range("ikev2_trans_type_encr_names", &ikev2_trans_type_encr_names, 0, 256);
	test_enums("ikev2_trans_type_prf_names", &ikev2_trans_type_prf_names);
	test_enums("ikev2_trans_type_integ_names", &ikev2_trans_type_integ_names);
	test_enums("ikev2_trans_type_esn_names", &ikev2_trans_type_esn_names);
	test_enums("ikev2_trans_type_names", &ikev2_trans_type_names);
	test_enum_range("ikev2_trans_attr_descs", &ikev2_trans_attr_descs, 0, 256);
	test_enums("ike_cert_type_names", &ike_cert_type_names);
	test_enums("ikev2_cert_type_names", &ikev2_cert_type_names);
	test_enum_range("modecfg_attr_names", &modecfg_attr_names, 0, 256);
	test_enum_range("ike_idtype_names_extended", &ike_idtype_names_extended, -10, 0);
	test_enum_range("ike_idtype_names_extended", &ike_idtype_names_extended0, 0, 256);
	test_enums("ike_idtype_names", &ike_idtype_names);
	test_enums("ikev2_idtype_names", &ikev2_idtype_names);

	/*
	 * Some hard-wired checks of enum_enum_name.  If a lookup
	 * should fail, pass NULL for the enum table.
	 */
	test_enum_enum("IKEv2 transforms", &v2_transform_ID_enums,
		       IKEv2_TRANS_TYPE_ENCR, &ikev2_trans_type_encr_names,
		       IKEv2_ENCR_3DES, true);
	test_enum_enum("IKEv2 transforms", &v2_transform_ID_enums,
		       IKEv2_TRANS_TYPE_ROOF, NULL,
		       1, false);
	test_enum_enum("IKEv2 transforms", &v2_transform_ID_enums,
		       IKEv2_TRANS_TYPE_PRF, &ikev2_trans_type_prf_names,
		       IKEv2_PRF_INVALID, false);
	printf("\n");

	printf("lswlog_enum_lset_short:\n\n");
	test_enum_lset("debug", &debug_names, DBG_CRYPT|DBG_CRYPT_LOW);
	printf("\n");

	report_leaks();
	exit(0);
}
