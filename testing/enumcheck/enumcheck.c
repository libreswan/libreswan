#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"

static void test_enum(char *enumname, enum_names *enum_test, int max)
{
	printf("  %s:\n", enumname);
	for (int i = 0; i < max; i++) {
		const char *name = enum_name(enum_test, i);
		if (name == NULL) {
			continue;
		}

		printf("  %3d -> %s\n", i, name);
		const char *prefix = "        ";

		/*
		 * So that it is easy to see what was tested, print
		 * something for every comparision.
		 *
		 * "break" is used to make bailing early easier
		 */
		do {
			int e;

			printf("%s search %s: ", prefix, name);
			e = enum_search(enum_test, name);
			if (e != i) {
				printf("%d ERROR\n", e);
				break;
			}
			printf("OK\n");

			e = enum_match(enum_test, name);
			printf("%s match %s: ", prefix, name);
			if (e != i) {
				printf("%d ERROR\n", e);
				break;
			}
			printf("OK\n");

			if (strchr(name, '(')) {
				char *trunc_name = clone_str(name, "trunc_name");
				*strchr(trunc_name, '(') = '\0';
				e = enum_match(enum_test, trunc_name);
				printf("%s match %s: ", prefix, trunc_name);
				pfree(trunc_name);
				if (e != i) {
					printf("%d ERROR\n", e);
					break;
				}
				printf("OK\n");
			}

			const char *short_name = enum_short_name(enum_test, i);
			if (short_name != name) {
				if (short_name == NULL) {
					printf("%s short_name %d: ERROR\n",
					       prefix, e);
					break;
				}

				e = enum_match(enum_test, short_name);
				printf("%s match %s: ", prefix, short_name);
				if (e != i) {
					printf("%d ERROR\n", e);
					break;
				}
				printf("OK\n");

				if (strchr(short_name, '(')) {
					char *trunc_short_name = clone_str(short_name, "trunc_short_name");
					*strchr(trunc_short_name, '(') = '\0';
					e = enum_match(enum_test, trunc_short_name);
					printf("%s match %s: ", prefix, trunc_short_name);
					pfree(trunc_short_name);
					if (e != i) {
						printf("%d ERROR\n", e);
						break;
					}
					printf("OK\n");
				}
			}
		} while (FALSE);

	}
	printf("\n");
}

int main(int argc UNUSED, char *argv[])
{
	tool_init_log(argv[0]);

	/* don't hold back */
	setbuf(stdout, NULL);

	printf("pluto enum_names:\n\n");
	test_enum("connection_kind_names", &connection_kind_names, 256);
	test_enum("certpolicy_type_names", &certpolicy_type_names, 256);

	printf("IETF registry enum_names:\n\n");
	test_enum("version_names", &version_names, 256);
	test_enum("doi_names", &doi_names, 256);
	test_enum("ikev1_payload_names", &ikev1_payload_names, 256);
	test_enum("ikev2_payload_names", &ikev2_payload_names, 256);
	test_enum("payload_names_ikev1orv2", &payload_names_ikev1orv2, 256);
	test_enum("ikev1_exchange_names", &ikev1_exchange_names, 256);
	test_enum("ikev2_exchange_names", &ikev2_exchange_names, 256);
	test_enum("exchange_names_ikev1orv2", &exchange_names_ikev1orv2, 256);
	test_enum("ikev1_protocol_names", &ikev1_protocol_names, 256);
	test_enum("ikev2_protocol_names", &ikev2_protocol_names, 256);
	test_enum("ikev2_del_protocol_names", &ikev2_del_protocol_names, 256);
	test_enum("isakmp_transformid_names", &isakmp_transformid_names, 256);
	test_enum("ah_transformid_names", &ah_transformid_names, 256);
	test_enum("esp_transformid_names", &esp_transformid_names, 256);
	test_enum("ipcomp_transformid_names", &ipcomp_transformid_names, 256);
	test_enum("oakley_attr_names", &oakley_attr_names, 256);
	test_enum("ipsec_attr_names", &ipsec_attr_names, 256);
	test_enum("sa_lifetime_names", &sa_lifetime_names, 256);
	test_enum("oakley_lifetime_names", &oakley_lifetime_names, 256);
	test_enum("oakley_auth_names", &oakley_auth_names, 256);
	test_enum("oakley_enc_names", &oakley_enc_names, 256);
	test_enum("oakley_hash_names", &oakley_hash_names, 256);
	test_enum("oakley_group_names", &oakley_group_names, 256);
	test_enum("ikev1_notify_names", &ikev1_notify_names, 16384);
	test_enum("ikev2_notify_names", &ikev2_notify_names, 16384);
	test_enum("ikev2_ts_type_names", &ikev2_ts_type_names, 256);
	test_enum("ikev2_cp_type_names", &ikev2_cp_type_names, 256);
	test_enum("ikev2_cp_attribute_type_names", &ikev2_cp_attribute_type_names, 256);
	test_enum("ppk_names", &ppk_names, 256);
	test_enum("enc_mode_names", &enc_mode_names, 256);
	test_enum("auth_alg_names", &auth_alg_names, 256);
	test_enum("xauth_type_names", &xauth_type_names, 256);
	test_enum("xauth_attr_names", &xauth_attr_names, 256);
	test_enum("attr_msg_type_names", &attr_msg_type_names, 256);
	test_enum("ikev2_sec_proto_id_names", &ikev2_sec_proto_id_names, 256);
	test_enum("ikev2_auth_names", &ikev2_auth_names, 256);
	test_enum("ikev2_trans_type_encr_names", &ikev2_trans_type_encr_names, 256);
	test_enum("ikev2_trans_type_prf_names", &ikev2_trans_type_prf_names, 256);
	test_enum("ikev2_trans_type_integ_names", &ikev2_trans_type_integ_names, 256);
	test_enum("ikev2_trans_type_esn_names", &ikev2_trans_type_esn_names, 256);
	test_enum("ikev2_trans_type_names", &ikev2_trans_type_names, 256);
	test_enum("ikev2_trans_attr_descs", &ikev2_trans_attr_descs, 256);
	test_enum("ike_cert_type_names", &ike_cert_type_names, 256);
	test_enum("ikev2_cert_type_names", &ikev2_cert_type_names, 256);
	test_enum("modecfg_attr_names", &modecfg_attr_names, 256);
	test_enum("ike_idtype_names", &ike_idtype_names, 256);
	test_enum("ikev2_idtype_names", &ikev2_idtype_names, 256);

	report_leaks();
	tool_close_log();
	exit(0);
}
