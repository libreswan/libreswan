#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "lset_names.h"

#define PREFIX "         "

static void test_enum(char *enumname, enum_names *enum_test, int floor, int long roof)
{
	printf("  %s:\n", enumname);
	for (int i = floor; i < roof; i++) {
		/* find a name, if any, for this value */
		const char *name = enum_name(enum_test, i);
		if (name == NULL) {
			continue;
		}

		printf("  %3d -> %s\n", i, name);

		/*
		 * So that it is easy to see what was tested, print
		 * something for every comparision.
		 */

		if (i < 0) {
			/* we are cheating: don't do the other checks */
			continue;
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
			int e = enum_match(enum_test, name);
			if (e != i) {
				printf("%d ERROR\n", e);
			} else {
				printf("OK\n");
			}
		}

		if (strchr(name, '(') != NULL) {
			char *trunc_name = clone_str(name, "trunc_name");
			*strchr(trunc_name, '(') = '\0';
			printf(PREFIX "match %s [trunc]: ", trunc_name);
			int e = enum_match(enum_test, trunc_name);
			pfree(trunc_name);
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
			continue;
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
			continue;
		}

		{
			printf(PREFIX "match %s [short]: ", short_name);
			int e = enum_match(enum_test, short_name);
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
			int e = enum_match(enum_test, trunc_short_name);
			pfree(trunc_short_name);
			if (e != i) {
				printf("%d ERROR\n", e);
			} else {
				printf("OK\n");
			}
		}
	}
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
		if (val_ok && streq(buf->array, name)) {
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

static void test_lset(const char *name, const struct lset_names *names)
{
	printf("%s:\n", name);
	printf("\tcheck: ");
	lset_names_check(names);
	printf("ok\n");
	LSWLOG_FILE(stdout, buf) {
		lswlogs(buf, "\tflags: ");
		lswlog_lset_flags(buf, names, LRANGE(0, names->roof - 1));
		lswlogs(buf, "\n");
	}
}

int main(int argc UNUSED, char *argv[])
{
	tool_init_log(argv[0]);

	/* don't hold back */
	setbuf(stdout, NULL);

	printf("pluto enum_names:\n\n");
	test_enum("connection_kind_names", &connection_kind_names, 0, 256);
	test_enum("certpolicy_type_names", &certpolicy_type_names, 0, 256);

	printf("IETF registry enum_names:\n\n");
	test_enum("version_names", &version_names, 0, 256);
	test_enum("doi_names", &doi_names, 0, 256);
	test_enum("ikev1_payload_names", &ikev1_payload_names, 0, 256);
	test_enum("ikev2_payload_names", &ikev2_payload_names, 0, 256);
	test_enum("payload_names_ikev1orv2", &payload_names_ikev1orv2, 0, 256);
	test_enum("ikev1_exchange_names", &ikev1_exchange_names, 0, 256);
	test_enum("ikev2_exchange_names", &ikev2_exchange_names, 0, 256);
	test_enum("exchange_names_ikev1orv2", &exchange_names_ikev1orv2, 0, 256);
	test_enum("ikev1_protocol_names", &ikev1_protocol_names, 0, 256);
	test_enum("ikev2_protocol_names", &ikev2_protocol_names, 0, 256);
	test_enum("ikev2_del_protocol_names", &ikev2_del_protocol_names, 0, 256);
	test_enum("isakmp_transformid_names", &isakmp_transformid_names, 0, 256);
	test_enum("ah_transformid_names", &ah_transformid_names, 0, 256);
	test_enum("esp_transformid_names", &esp_transformid_names, 0, 256);
	test_enum("ipcomp_transformid_names", &ipcomp_transformid_names, 0, 256);
	test_enum("oakley_attr_names", &oakley_attr_names, 0, 256);
	test_enum("ipsec_attr_names", &ipsec_attr_names, 0, 256);
	test_enum("sa_lifetime_names", &sa_lifetime_names, 0, 256);
	test_enum("oakley_lifetime_names", &oakley_lifetime_names, 0, 256);
	test_enum("oakley_auth_names", &oakley_auth_names, 0, 256);
	test_enum("oakley_enc_names", &oakley_enc_names, 0, 256);
	test_enum("oakley_hash_names", &oakley_hash_names, 0, 256);
	test_enum("oakley_group_names", &oakley_group_names, 0, 256);
	test_enum("ikev1_notify_names", &ikev1_notify_names, 0, 16384);
	test_enum("ikev2_notify_names", &ikev2_notify_names, 0, 16384);
	test_enum("ikev2_ts_type_names", &ikev2_ts_type_names, 0, 256);
	test_enum("ikev2_cp_type_names", &ikev2_cp_type_names, 0, 256);
	test_enum("ikev2_cp_attribute_type_names", &ikev2_cp_attribute_type_names, 0, 256);
	test_enum("ppk_names", &ppk_names, 0, 256);
	test_enum("enc_mode_names", &enc_mode_names, 0, 256);
	test_enum("auth_alg_names", &auth_alg_names, 0, 256);
	test_enum("xauth_type_names", &xauth_type_names, 0, 256);
	test_enum("xauth_attr_names", &xauth_attr_names, 0, 256);
	test_enum("attr_msg_type_names", &attr_msg_type_names, 0, 256);
	test_enum("ikev2_sec_proto_id_names", &ikev2_sec_proto_id_names, 0, 256);
	test_enum("ikev2_auth_names", &ikev2_auth_names, 0, 256);
	test_enum("ikev2_trans_type_encr_names", &ikev2_trans_type_encr_names, 0, 256);
	test_enum("ikev2_trans_type_prf_names", &ikev2_trans_type_prf_names, 0, 256);
	test_enum("ikev2_trans_type_integ_names", &ikev2_trans_type_integ_names, 0, 256);
	test_enum("ikev2_trans_type_esn_names", &ikev2_trans_type_esn_names, 0, 256);
	test_enum("ikev2_trans_type_names", &ikev2_trans_type_names, 0, 256);
	test_enum("ikev2_trans_attr_descs", &ikev2_trans_attr_descs, 0, 256);
	test_enum("ike_cert_type_names", &ike_cert_type_names, 0, 256);
	test_enum("ikev2_cert_type_names", &ikev2_cert_type_names, 0, 256);
	test_enum("modecfg_attr_names", &modecfg_attr_names, 0, 256);
	test_enum("ike_idtype_names_extended", &ike_idtype_names_extended, -10, 0);
	test_enum("ike_idtype_names_extended", &ike_idtype_names_extended0, 0, 256);
	test_enum("ike_idtype_names", &ike_idtype_names, 0, 256);
	test_enum("ikev2_idtype_names", &ikev2_idtype_names, 0, 256);

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

	test_lset("debug", &debug_lset_names);

	report_leaks();
	tool_close_log();
	exit(0);
}
