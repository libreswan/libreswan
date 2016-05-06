#define PRINT_SA_DEBUG 1
#include "../../../lib/libswan/alg_info.c"

char *progname;

void exit_tool(int stat)
{
	exit(stat);
}

void do_test(char *enumname, enum_names *enum_test, int max) {
	int i = 0;

	fprintf(stdout, "%s:\n", enumname);
	for (i; i < max; i++) {
		int found;
		const char *name = enum_name(enum_test, i);
		if (name != NULL) {
			found = enum_search(enum_test, name);
				fprintf(stdout,"%s: [%5d] -> %s -> %d\n",
				found == i ? "OK" : "ERROR",
				i, name, found);
		}
	}
	fprintf(stdout,"\n");
	fflush(stdout);
}

int main(int argc, char *argv[]) {

	progname = argv[0];

	tool_init_log();

	fprintf(stdout, "pluto enum_names:\n");
	do_test("connection_kind_names", &connection_kind_names, 256);
	do_test("certpolicy_type_names", &certpolicy_type_names, 256);

	fprintf(stdout, "IETF registry enum_names:\n");
	do_test("version_names", &version_names, 256);
	do_test("doi_names", &doi_names, 256);
	do_test("ikev1_payload_names", &ikev1_payload_names, 256);
	do_test("ikev2_payload_names", &ikev2_payload_names, 256);
	do_test("payload_names_ikev1orv2", &payload_names_ikev1orv2, 256);
	do_test("ikev1_exchange_names", &ikev1_exchange_names, 256);
	do_test("ikev2_exchange_names", &ikev2_exchange_names, 256);
	do_test("exchange_names_ikev1orv2", &exchange_names_ikev1orv2, 256);
	do_test("ikev1_protocol_names", &ikev1_protocol_names, 256);
	do_test("ikev2_protocol_names", &ikev2_protocol_names, 256);
	do_test("ikev2_del_protocol_names", &ikev2_del_protocol_names, 256);
	do_test("isakmp_transformid_names", &isakmp_transformid_names, 256);
	do_test("ah_transformid_names", &ah_transformid_names, 256);
	do_test("esp_transformid_names", &esp_transformid_names, 256);
	do_test("ipcomp_transformid_names", &ipcomp_transformid_names, 256);
	do_test("oakley_attr_names", &oakley_attr_names, 256);
	do_test("ipsec_attr_names", &ipsec_attr_names, 256);
	do_test("sa_lifetime_names", &sa_lifetime_names, 256);
	do_test("oakley_lifetime_names", &oakley_lifetime_names, 256);
	do_test("oakley_auth_names", &oakley_auth_names, 256);
	do_test("oakley_enc_names", &oakley_enc_names, 256);
	do_test("oakley_hash_names", &oakley_hash_names, 256);
	do_test("oakley_group_names", &oakley_group_names, 256);
	do_test("ikev1_notify_names", &ikev1_notify_names, 16384);
	do_test("ikev2_notify_names", &ikev2_notify_names, 16384);
	do_test("ikev2_ts_type_names", &ikev2_ts_type_names, 256);
	do_test("ikev2_cp_type_names", &ikev2_cp_type_names, 256);
	do_test("ikev2_cp_attribute_type_names", &ikev2_cp_attribute_type_names, 256);
	do_test("ppk_names", &ppk_names, 256);
	do_test("enc_mode_names", &enc_mode_names, 256);
	do_test("auth_alg_names", &auth_alg_names, 256);
	do_test("xauth_type_names", &xauth_type_names, 256);
	do_test("xauth_attr_names", &xauth_attr_names, 256);
	do_test("attr_msg_type_names", &attr_msg_type_names, 256);
	do_test("ikev2_sec_proto_id_names", &ikev2_sec_proto_id_names, 256);
	do_test("ikev2_auth_names", &ikev2_auth_names, 256);
	do_test("ikev2_trans_type_encr_names", &ikev2_trans_type_encr_names, 256);
	do_test("ikev2_trans_type_prf_names", &ikev2_trans_type_prf_names, 256);
	do_test("ikev2_trans_type_integ_names", &ikev2_trans_type_integ_names, 256);
	do_test("ikev2_trans_type_esn_names", &ikev2_trans_type_esn_names, 256);
	do_test("ikev2_trans_type_names", &ikev2_trans_type_names, 256);
	do_test("ikev2_trans_attr_descs", &ikev2_trans_attr_descs, 256);
	do_test("ike_cert_type_names", &ike_cert_type_names, 256);
	do_test("ikev2_cert_type_names", &ikev2_cert_type_names, 256);
	do_test("modecfg_attr_names", &modecfg_attr_names, 256);
	do_test("ike_idtype_names", &ike_idtype_names, 256);
	do_test("ikev2_idtype_names", &ikev2_idtype_names, 256);

	report_leaks();
	tool_close_log();
	exit(0);
}
