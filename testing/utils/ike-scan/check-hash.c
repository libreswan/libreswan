/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2005 Roy Hills,
 * NTA Monitor Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * If this license is unacceptable to you, I may be willing to negotiate
 * alternative licenses (contact ike-scan@nta-monitor.com).
 *
 * You are encouraged to send comments, improvements or suggestions to
 * me at ike-scan@nta-monitor.com.
 *
 * $Id: check-hash.c,v 1.1.1.1 2005/01/13 18:45:14 mcr Exp $
 *
 * check-hash -- Check message digest (HASH) functions
 *
 * Author:	Roy Hills
 * Date:	25 April 2004
 *
 *	Check the various message digest (HASH) functions using the test
 *	vectors given in the appropriate RFC.
 */

#include "ike-scan.h"
#define NUM_HMAC_TESTS 1
#define HMAC_SPEED_ITERATIONS 100000
#define HASH_SPEED_ITERATIONS 500000

int main(void)
{
/*
 *	MD5 test vectors from RFC 1321 "The MD5 Message-Digest Algorithm"
 */
	static const char *md5_tests[] = {
		"",
		"a",
		"abc",
		"message digest",
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		NULL
	};
	static const char *md5_results[] = {
		"d41d8cd98f00b204e9800998ecf8427e",
		"0cc175b9c0f1b6a831c399e269772661",
		"900150983cd24fb0d6963f7d28e17f72",
		"f96b697d7cb7938d525a2f31aaf161d0",
		"c3fcd3d76192e4007dfb496cca67e13b",
		"d174ab98d277d9f5a5611c2c9f419d9f",
		"57edf4a22be3c955ac49da2e2107b67a"
	};
/*
 *	SHA1 test vectors from RFC 3174 "US Secure Hash Algorithm 1 (SHA1)"
 */
	static const char *sha1_tests[] = {
		"abc",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		NULL
	};
	static const char *sha1_results[] = {
		"a9993e364706816aba3e25717850c26c9cd0d89d",
		"84983e441c3bd26ebaae4aa1f95129e5e54670f1",
	};
/*
 *	HMAC-MD5 test vectors from RFC 2104
 *	"HMAC: Keyed-Hashing for Message Authentication"
 */
	static const struct hmac_md5_test_struct {
		unsigned char key[16];
		int key_len;
		unsigned char data[64];
		int data_len;
		char *digest;
	} hmac_md5_tests[NUM_HMAC_TESTS] = {
		{ "Jefe",
		  4,
		  "what do ya want for nothing?",
		  28,
		  "750c783e6ab0b503eaa86e310a5db738" }
	};

/*
 *	HMAC-SHA1 test vectors from RFC 2202
 *	"Test Cases for HMAC-MD5 and HMAC-SHA-1"
 */
	static const struct hmac_sha1_test_struct {
		unsigned char key[20];
		int key_len;
		unsigned char data[64];
		int data_len;
		char *digest;
	} hmac_sha1_tests[NUM_HMAC_TESTS] = {
		{ "Jefe",
		  4,
		  "what do ya want for nothing?",
		  28,
		  "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" }
	};

	const char **testp;
	const char **resultp;
	int i;

	int error = 0;

#ifdef HAVE_OPENSSL
	printf("\nUsing OpenSSL hash and HMAC functions.\n");
#else
	printf("\nUsing built-in hash and HMAC functions.\n");
#endif

	printf("\nChecking MD5 hash function...\n");
	testp = md5_tests;
	resultp = md5_results;
	while (*testp != NULL) {
		const char *expected;
		char *actual;
		printf("\"%s\"\t", *testp);
		expected = *resultp;
		actual =
			hexstring(MD5((const unsigned char *) *testp,
				      strlen(*testp),
				      NULL), 16);
		if (strcmp(actual, expected)) {
			error++;
			printf("FAIL (expected %s, got %s)\n", expected,
			       actual);
		} else {
			printf("ok\n");
		}
		testp++;
		resultp++;
	}

	printf("\nChecking SHA1 hash function...\n");
	testp = sha1_tests;
	resultp = sha1_results;
	while (*testp != NULL) {
		const char *expected;
		char *actual;
		printf("\"%s\"\t", *testp);
		expected = *resultp;
		actual =
			hexstring(SHA1((const unsigned char *) *testp,
				       strlen(*testp),
				       NULL), 20);
		if (strcmp(actual, expected)) {
			error++;
			printf("FAIL (expected %s, got %s)\n", expected,
			       actual);
		} else {
			printf("ok\n");
		}
		testp++;
		resultp++;
	}

	printf("\nChecking HMAC-MD5 keyed hash function...\n");
	for (i = 0; i < NUM_HMAC_TESTS; i++) {
		const char *expected;
		char *actual;
		printf("\"%s\" \"%s\"\t", hmac_md5_tests[i].key,
		       hmac_md5_tests[i].data);
		expected = hmac_md5_tests[i].digest;
		actual = hexstring(hmac_md5(hmac_md5_tests[i].data,
					    hmac_md5_tests[i].data_len,
					    hmac_md5_tests[i].key,
					    hmac_md5_tests[i].key_len,
					    NULL), 16);
		if (strcmp(actual, expected)) {
			error++;
			printf("FAIL (expected %s, got %s)\n", expected,
			       actual);
		} else {
			printf("ok\n");
		}
	}

	printf("\nChecking HMAC-SHA1 keyed hash function...\n");
	for (i = 0; i < NUM_HMAC_TESTS; i++) {
		const char *expected;
		char *actual;
		printf("\"%s\" \"%s\"\t", hmac_sha1_tests[i].key,
		       hmac_sha1_tests[i].data);
		expected = hmac_sha1_tests[i].digest;
		actual = hexstring(hmac_sha1(hmac_sha1_tests[i].data,
					     hmac_sha1_tests[i].data_len,
					     hmac_sha1_tests[i].key,
					     hmac_sha1_tests[i].key_len,
					     NULL), 20);
		if (strcmp(actual, expected)) {
			error++;
			printf("FAIL (expected %s, got %s)\n", expected,
			       actual);
		} else {
			printf("ok\n");
		}
	}

	printf("\nChecking HMAC-MD5 PSK cracking speed...\n");
	do {
/*
 *	The values below are observed values from a Firewall-1 system
 *	using IKE Aggressive mode with PSK authentication and MD5 hash.
 *	The ID used was "test", and the valid pre-shared key is "abc123".
 *      The expected hash_r is "f995ec2968f695aeb1d4e4b437f49d26".
 */
		char *g_xr_hex =
			"9c1e0e07828af45086a4eb559ad8dafb7d655bab38656609426653565ef7e332bed7212cf24a05048032240256a169a68ee304ca500abe073d150bc50239350446ab568132aebcf34acd25ce23b30d0de9f8e7a89c22ce0dec2dabf0409bc25f0988d5d956916dce220c630d2a1fda846667fdecb20b2dc2d5c5b8273a07095c";
		char *g_xi_hex =
			"6f8c74c15bb4dd09b7af8d1c23e7b381a38dddcd4c5afb3b1335ff766f0267df8fdca0ea907ef4482d8164506817d10ba4aed8f108d32c1b082b91772df956bcd5f7a765759bada21c11f28429c48fcd7267be7b3aea96421528b9432110fff607a65b7c41091e5d1a10e143d4701147d7cfc211ba5853cf800d12a11d129724";
		char *cky_r_hex = "6d08132c8abb6931";
		char *cky_i_hex = "eac82ea45cbe59e6";
		char *sai_b_hex =
			"00000001000000010000002c01010001000000240101000080010001800200018003000180040002800b0001000c000400007080";
		char *idir_b_hex = "01000000ac100202";
		char *ni_b_hex = "64745a975dbcd95c2abf7d2eeeb93ac4633a03f1";
		char *nr_b_hex = "502c0b3872518fa1e7ff8f5a28a3d797f65e2cb1";

		unsigned char *g_xr;
		unsigned char *g_xi;
		unsigned char *cky_r;
		unsigned char *cky_i;
		unsigned char *sai_b;
		unsigned char *idir_b;
		unsigned char *ni_b;
		unsigned char *nr_b;

		size_t g_xr_len;
		size_t g_xi_len;
		size_t cky_r_len;
		size_t cky_i_len;
		size_t sai_b_len;
		size_t idir_b_len;
		size_t ni_b_len;
		size_t nr_b_len;

		unsigned char *skeyid;
		unsigned char *hash_r;

		unsigned char *skeyid_data;
		unsigned char *hash_r_data;

		size_t skeyid_data_len;
		size_t hash_r_data_len;

		unsigned char *cp;

		unsigned char *psk = (unsigned char *) "abc123"; /* correct key */
		size_t psk_len = 6;

		struct timeval start_time;
		struct timeval end_time;
		struct timeval elapsed_time;
		double elapsed_seconds;

		g_xr = hex2data(g_xr_hex, &g_xr_len);
		g_xi = hex2data(g_xi_hex, &g_xi_len);
		cky_r = hex2data(cky_r_hex, &cky_r_len);
		cky_i = hex2data(cky_i_hex, &cky_i_len);
		sai_b = hex2data(sai_b_hex, &sai_b_len);
		idir_b = hex2data(idir_b_hex, &idir_b_len);
		ni_b = hex2data(ni_b_hex, &ni_b_len);
		nr_b = hex2data(nr_b_hex, &nr_b_len);

		skeyid_data_len = ni_b_len + nr_b_len;
		skeyid_data = Malloc(skeyid_data_len);
		cp = skeyid_data;
		memcpy(cp, ni_b, ni_b_len);
		cp += ni_b_len;
		memcpy(cp, nr_b, nr_b_len);
		skeyid = Malloc(16);
		hash_r_data_len = g_xr_len + g_xi_len + cky_r_len + cky_i_len +
				  sai_b_len + idir_b_len;
		hash_r_data = Malloc(hash_r_data_len);
		cp = hash_r_data;
		memcpy(cp, g_xr, g_xr_len);
		cp += g_xr_len;
		memcpy(cp, g_xi, g_xi_len);
		cp += g_xi_len;
		memcpy(cp, cky_r, cky_r_len);
		cp += cky_r_len;
		memcpy(cp, cky_i, cky_i_len);
		cp += cky_i_len;
		memcpy(cp, sai_b, sai_b_len);
		cp += sai_b_len;
		memcpy(cp, idir_b, idir_b_len);
		hash_r = Malloc(16);

		Gettimeofday(&start_time);
		for (i = 0; i < HMAC_SPEED_ITERATIONS; i++) {
			hmac_md5(skeyid_data, skeyid_data_len, psk, psk_len,
				 skeyid);
			hmac_md5(hash_r_data, hash_r_data_len, skeyid, 16,
				 hash_r);
		}
		Gettimeofday(&end_time);
		timeval_diff(&end_time, &start_time, &elapsed_time);
		elapsed_seconds = elapsed_time.tv_sec +
				  (elapsed_time.tv_usec / 1000000.0);
		printf(
			"%u MD5 HASH_R calculations in %.6f seconds (%.2f per sec)\n",
			HMAC_SPEED_ITERATIONS, elapsed_seconds,
			HMAC_SPEED_ITERATIONS / elapsed_seconds);
	} while (0);

	printf("\nChecking HMAC-SHA1 PSK cracking speed...\n");
	do {
/*
 *	The values below are observed values from a Firewall-1 NG AI system
 *	using IKE Aggressive mode with PSK authentication and SHA1 hash.
 *	The ID used was "test", and the valid pre-shared key is "abc123".
 *      The expected hash_r is "543ea42889c07b17390cc6f0440246c0148422df".
 */
		char *g_xr_hex =
			"6c5559243259d5293df34a766561b8ffa78a9f8ee03d8a05916aadeeba9997864e0cd712f2a08104366c5e48f391ee7ce7b0ac08c59b8001c888c9f0343fd7d7d2d1da8e672c4ff05a7dd3c4eb6adc09bec712128ed951f7fcde2c31431643eb04d5ffc0be68e17aa80168e9635cb6f4c80af8ea1432c2b095b25f3d79ac4e55";
		char *g_xi_hex =
			"857209de96faf07bad57ff1aba648a2c61a6802e4db3ab54c5593fa8abd9b1304bbb0fe2b5ff5d63565c7d10c1073d22adbd51fb70fc4f35568ede01678f32b24a41940040f263964ee0a70fe8e43295a18390117fdf46d56d24d7d4b40987fe4a1bfe8a0d61205c42c76b2aab9dbf4c20505da02fa4759dc84c717c55f87b9f";
		char *cky_r_hex = "963c61ef1778b6c5";
		char *cky_i_hex = "efa6639971a91c08";
		char *sai_b_hex =
			"00000001000000010000002c01010001000000240101000080010001800200028003000180040002800b0001000c000400007080";
		char *idir_b_hex = "01000000ac100202";
		char *ni_b_hex = "6d62656f72fd1c53cda7337d0612aeebe3529a09";
		char *nr_b_hex = "8e83c48eb087b8276b4bb2976ea23bf426abde8f";

		unsigned char *g_xr;
		unsigned char *g_xi;
		unsigned char *cky_r;
		unsigned char *cky_i;
		unsigned char *sai_b;
		unsigned char *idir_b;
		unsigned char *ni_b;
		unsigned char *nr_b;

		size_t g_xr_len;
		size_t g_xi_len;
		size_t cky_r_len;
		size_t cky_i_len;
		size_t sai_b_len;
		size_t idir_b_len;
		size_t ni_b_len;
		size_t nr_b_len;

		unsigned char *skeyid;
		unsigned char *hash_r;

		unsigned char *skeyid_data;
		unsigned char *hash_r_data;

		size_t skeyid_data_len;
		size_t hash_r_data_len;

		unsigned char *cp;

		unsigned char *psk = (unsigned char *) "abc123"; /* correct key */
		size_t psk_len = 6;

		struct timeval start_time;
		struct timeval end_time;
		struct timeval elapsed_time;
		double elapsed_seconds;

		g_xr = hex2data(g_xr_hex, &g_xr_len);
		g_xi = hex2data(g_xi_hex, &g_xi_len);
		cky_r = hex2data(cky_r_hex, &cky_r_len);
		cky_i = hex2data(cky_i_hex, &cky_i_len);
		sai_b = hex2data(sai_b_hex, &sai_b_len);
		idir_b = hex2data(idir_b_hex, &idir_b_len);
		ni_b = hex2data(ni_b_hex, &ni_b_len);
		nr_b = hex2data(nr_b_hex, &nr_b_len);

		skeyid_data_len = ni_b_len + nr_b_len;
		skeyid_data = Malloc(skeyid_data_len);
		cp = skeyid_data;
		memcpy(cp, ni_b, ni_b_len);
		cp += ni_b_len;
		memcpy(cp, nr_b, nr_b_len);
		skeyid = Malloc(20);
		hash_r_data_len = g_xr_len + g_xi_len + cky_r_len + cky_i_len +
				  sai_b_len + idir_b_len;
		hash_r_data = Malloc(hash_r_data_len);
		cp = hash_r_data;
		memcpy(cp, g_xr, g_xr_len);
		cp += g_xr_len;
		memcpy(cp, g_xi, g_xi_len);
		cp += g_xi_len;
		memcpy(cp, cky_r, cky_r_len);
		cp += cky_r_len;
		memcpy(cp, cky_i, cky_i_len);
		cp += cky_i_len;
		memcpy(cp, sai_b, sai_b_len);
		cp += sai_b_len;
		memcpy(cp, idir_b, idir_b_len);
		hash_r = Malloc(20);

		Gettimeofday(&start_time);
		for (i = 0; i < HMAC_SPEED_ITERATIONS; i++) {
			hmac_sha1(skeyid_data, skeyid_data_len, psk, psk_len,
				  skeyid);
			hmac_sha1(hash_r_data, hash_r_data_len, skeyid, 20,
				  hash_r);
		}
		Gettimeofday(&end_time);
		timeval_diff(&end_time, &start_time, &elapsed_time);
		elapsed_seconds = elapsed_time.tv_sec +
				  (elapsed_time.tv_usec / 1000000.0);
		printf(
			"%u SHA1 HASH_R calculations in %.6f seconds (%.2f per sec)\n",
			HMAC_SPEED_ITERATIONS, elapsed_seconds,
			HMAC_SPEED_ITERATIONS / elapsed_seconds);
	} while (0);

	printf("\nChecking MD5 hash speed...\n");
	do {
		size_t hash_data_len;
		unsigned char *hash_result;
		struct timeval start_time;
		struct timeval end_time;
		struct timeval elapsed_time;
		double elapsed_seconds;
		unsigned char hash_speed_data[] = "12345678";
		size_t memcpy_len;

		hash_data_len = strlen((char *) hash_speed_data);
		memcpy_len = hash_data_len > 16 ? 16 : hash_data_len;
		Gettimeofday(&start_time);
		for (i = 0; i < HASH_SPEED_ITERATIONS; i++) {
			hash_result =
				MD5(hash_speed_data, hash_data_len, NULL);
			memcpy(hash_speed_data, hash_result, memcpy_len);
		}
		Gettimeofday(&end_time);
		timeval_diff(&end_time, &start_time, &elapsed_time);
		elapsed_seconds = elapsed_time.tv_sec +
				  (elapsed_time.tv_usec / 1000000.0);
		printf("%u MD5 calculations in %.6f seconds (%.2f per sec)\n",
		       HASH_SPEED_ITERATIONS, elapsed_seconds,
		       HASH_SPEED_ITERATIONS / elapsed_seconds);
	} while (0);

	printf("\nChecking SHA1 hash speed...\n");
	do {
		size_t hash_data_len;
		unsigned char *hash_result;
		struct timeval start_time;
		struct timeval end_time;
		struct timeval elapsed_time;
		double elapsed_seconds;
		unsigned char hash_speed_data[] = "12345678";
		size_t memcpy_len;

		hash_data_len = strlen((char *) hash_speed_data);
		memcpy_len = hash_data_len > 20 ? 20 : hash_data_len;
		Gettimeofday(&start_time);
		for (i = 0; i < HASH_SPEED_ITERATIONS; i++) {
			hash_result =
				SHA1(hash_speed_data, hash_data_len, NULL);
			memcpy(hash_speed_data, hash_result, memcpy_len);
		}
		Gettimeofday(&end_time);
		timeval_diff(&end_time, &start_time, &elapsed_time);
		elapsed_seconds = elapsed_time.tv_sec +
				  (elapsed_time.tv_usec / 1000000.0);
		printf("%u SHA1 calculations in %.6f seconds (%.2f per sec)\n",
		       HASH_SPEED_ITERATIONS, elapsed_seconds,
		       HASH_SPEED_ITERATIONS / elapsed_seconds);
	} while (0);

	if (error)
		return EXIT_FAILURE;
	else
		return EXIT_SUCCESS;
}
