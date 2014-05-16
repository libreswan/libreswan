#define AGGRESSIVE 1
#define PRINT_SA_DEBUG 1
#include "../../../lib/libswan/alg_info.c"

#if 0
/* work in progress */
#include "../../../programs/pluto/plutoalg.c"
#include "../../../programs/pluto/ike_alg.c"
#endif

char *progname;

void exit_tool(int stat)
{
	exit(stat);
}

void do_test(const char *algstr, int ttype) {
	struct alg_info *aie;
	char err_buf[256];	/* ??? big enough? */
	char algbuf[256];

	printf("[%*s] ", 20, algstr);
	switch(ttype) {
	case PROTO_IPSEC_ESP:
		aie = (struct alg_info *)alg_info_esp_create_from_str(
			algstr, &err);
		break;
	case PROTO_IPSEC_AH:
		aie = (struct alg_info *)alg_info_ah_create_from_str(
			algstr, err_buf, sizeof(err_buf));
		break;
#ifdef WORK_IN_PROGRESS
	case PROTO_ISAKMP:
		aie = (struct alg_info *)alg_info_ike_create_from_str(
			algstr, err_buf, sizeof(err_buf));
		break;
#endif
	}
	passert(aie != NULL);
	alg_info_snprint(algbuf, 256, aie);
	if (err_buf[0] != '\0')
		printf("ERROR: alg=%s  error=%s\n", algbuf, err_buf);
	else
		printf("   OK: alg=%s\n", algbuf);
	alg_info_free(aie);
}

main(int argc, char *argv[]) {

	progname = argv[0];

	tool_init_log();

	/* esp= */
	do_test("3des-sha1;modp1024", PROTO_IPSEC_ESP);
	do_test("3des-sha1;modp1536", PROTO_IPSEC_ESP);
	do_test("3des-sha1;modp2048", PROTO_IPSEC_ESP);
	do_test("3des-sha1;dh22", PROTO_IPSEC_ESP);
	do_test("3des-sha1;dh23", PROTO_IPSEC_ESP);
	do_test("3des-sha1;dh24", PROTO_IPSEC_ESP);
	do_test("3des-sha1", PROTO_IPSEC_ESP);
	do_test("null-sha1", PROTO_IPSEC_ESP);
	do_test("aes256-sha1", PROTO_IPSEC_ESP);
	do_test("aes128-sha1", PROTO_IPSEC_ESP);
	do_test("aes-sha1", PROTO_IPSEC_ESP);
	do_test("aes-sha", PROTO_IPSEC_ESP);
	do_test("aes", PROTO_IPSEC_ESP);
	do_test("aes256-sha", PROTO_IPSEC_ESP);
	do_test("aes256-sha2", PROTO_IPSEC_ESP);
	do_test("aes256-sha2_256", PROTO_IPSEC_ESP);
	do_test("aes256-sha2_384", PROTO_IPSEC_ESP);
	do_test("aes256-sha2_512", PROTO_IPSEC_ESP);
	do_test("camellia", PROTO_IPSEC_ESP);
	do_test("aes_ccm_a-128-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_a-192-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_a-256-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_b-128-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_b-192-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_b-256-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_c-128-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_c-192-null", PROTO_IPSEC_ESP);
	do_test("aes_ccm_c-256-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_a-128-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_a-192-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_a-256-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_b-128-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_b-192-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_b-256-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_c-128-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_c-192-null", PROTO_IPSEC_ESP);
	do_test("aes_gcm_c-256-null", PROTO_IPSEC_ESP);
	do_test("aes_ctr", PROTO_IPSEC_ESP);
	do_test("serpent", PROTO_IPSEC_ESP);
	do_test("twofish", PROTO_IPSEC_ESP);
	do_test("blowfish", PROTO_IPSEC_ESP); /* obsoleted */
	do_test("des-sha1", PROTO_IPSEC_ESP); /* obsoleted */
	do_test("mars", PROTO_IPSEC_ESP);
	/* do_test("modp1536", PROTO_IPSEC_ESP); should we support this?  */

	/* ah= */
	do_test("md5", PROTO_IPSEC_AH);
	do_test("sha", PROTO_IPSEC_AH);
	do_test("sha1", PROTO_IPSEC_AH);
	do_test("sha2", PROTO_IPSEC_AH);
	/* these should fail - but not by passert() */
	do_test("aes-sha1", PROTO_IPSEC_AH);
	do_test("vanityhash1", PROTO_IPSEC_AH);

#ifdef WORK_IB_PROGRESS
	/* ike= */
	do_test("3des-sha1", PROTO_ISAKMP);
#endif

	/* should not fail but do */
	do_test("id3", PROTO_IPSEC_ESP); /* alternative spelling for 3DES */
	do_test("id12", PROTO_IPSEC_ESP); /* alternative spelling for AES */


	report_leaks();
	tool_close_log();
	exit(0);
}
