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
			algstr, err_buf, sizeof(err_buf));
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
	algbuf[0] = '\0';
	if (aie != NULL)
		alg_info_snprint(algbuf, sizeof(algbuf), aie);
	if (err_buf[0] != '\0') {
		printf("ERROR: alg=%s  error=%s\n", algbuf, err_buf);
	} else {
		passert(aie != NULL);
		printf("   OK: alg=%s\n", algbuf);
	}
	if (aie != NULL)
		alg_info_free(aie);
}

main(int argc, char *argv[]) {

	progname = argv[0];

	tool_init_log();

	/* esp= */
	fprintf(stdout, "\n---- ESP tests that should succeed ----\n");
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
	do_test("mars", PROTO_IPSEC_ESP);
	do_test("modp1536", PROTO_IPSEC_ESP);
	fprintf(stdout, "\n---- ESP tests that should fail----\n");
	do_test("3des168-sha1", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("aes224-sha1", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("aes512-sha1", PROTO_IPSEC_ESP); /* should get rejected */
	do_test("blowfish", PROTO_IPSEC_ESP); /* obsoleted */
	do_test("des-sha1", PROTO_IPSEC_ESP); /* obsoleted */
	do_test("vanitycipher", PROTO_IPSEC_ESP);
	/* we no longer support IDxxx because we cannot know block/key sizes */
	do_test("id3", PROTO_IPSEC_ESP); /* alternative spelling for 3DES */
	do_test("id12", PROTO_IPSEC_ESP); /* alternative spelling for AES */

	/* aliases */
	do_test("aes-sha", PROTO_IPSEC_ESP);
	do_test("ase-sah", PROTO_IPSEC_ESP);
	do_test("aes-sah1", PROTO_IPSEC_ESP);

	do_test("aesccma-128-null", PROTO_IPSEC_ESP);
	do_test("ccm_a-128-null", PROTO_IPSEC_ESP);
	do_test("ccma-128-null", PROTO_IPSEC_ESP);
	do_test("aesccmb-128-null", PROTO_IPSEC_ESP);
	do_test("ccm_b-128-null", PROTO_IPSEC_ESP);
	do_test("ccmb-128-null", PROTO_IPSEC_ESP);
	do_test("aesccmc-128-null", PROTO_IPSEC_ESP);
	do_test("ccm_c-128-null", PROTO_IPSEC_ESP);
	do_test("ccmc-128-null", PROTO_IPSEC_ESP);

	do_test("aesgcma-128-null", PROTO_IPSEC_ESP);
	do_test("gcm_a-128-null", PROTO_IPSEC_ESP);
	do_test("gcma-128-null", PROTO_IPSEC_ESP);
	do_test("aesgcmb-128-null", PROTO_IPSEC_ESP);
	do_test("gcm_b-128-null", PROTO_IPSEC_ESP);
	do_test("gcmb-128-null", PROTO_IPSEC_ESP);
	do_test("aesgcmc-128-null", PROTO_IPSEC_ESP);
	do_test("gcm_c-128-null", PROTO_IPSEC_ESP);
	do_test("gcmc-128-null", PROTO_IPSEC_ESP);

	/* ah= */
	fprintf(stdout, "\n---- AH tests that should succeed ----\n");
	do_test("md5", PROTO_IPSEC_AH);
	do_test("sha", PROTO_IPSEC_AH);
	do_test("sha1", PROTO_IPSEC_AH);
	do_test("sha2", PROTO_IPSEC_AH);
	fprintf(stdout, "\n---- AH tests that should fail ----\n");
	do_test("null", PROTO_IPSEC_AH);
	do_test("aes-sha1", PROTO_IPSEC_AH);
	do_test("vanityhash1", PROTO_IPSEC_AH);
	do_test("aes_gcm_c-256", PROTO_IPSEC_AH);
	do_test("id3", PROTO_IPSEC_AH);

#ifdef WORK_IN_PROGRESS
	/* ike= */
	fprintf(stdout, "\n---- IKE tests ----\n");
	do_test("3des-sha1", PROTO_ISAKMP);
#endif

	report_leaks();
	tool_close_log();
	exit(0);
}
