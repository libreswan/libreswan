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
 * $Id: utils.c,v 1.1.1.1 2005/01/13 18:45:14 mcr Exp $
 *
 * Author: Roy Hills
 * Date: 5 April 2004
 *
 * This file contains various utility functions used by ike-scan.
 *
 * These functions were originally in ike-scan.c, but were moved to utils.c
 * because ike-scan.c was gettign rather large.
 */

#include "ike-scan.h"

static char rcsid[] = "$Id: utils.c,v 1.1.1.1 2005/01/13 18:45:14 mcr Exp $";   /* RCS ID for ident(1) */

/*
 *	timeval_diff -- Calculates the difference between two timevals
 *	and returns this difference in a third timeval.
 *
 *	Inputs:
 *
 *	a       = First timeval
 *	b       = Second timeval
 *	diff    = Difference between timevals (a - b).
 *
 *	Returns:
 *
 *	None.
 */
void timeval_diff(struct timeval *a, struct timeval *b, struct timeval *diff)
{

	/* Perform the carry for the later subtraction by updating b. */
	if (a->tv_usec < b->tv_usec) {
		int nsec = (b->tv_usec - a->tv_usec) / 1000000 + 1;
		b->tv_usec -= 1000000 * nsec;
		b->tv_sec += nsec;
	}
	if (a->tv_usec - b->tv_usec > 1000000) {
		int nsec = (a->tv_usec - b->tv_usec) / 1000000;
		b->tv_usec += 1000000 * nsec;
		b->tv_sec -= nsec;
	}

	/* Compute the time difference
	   tv_usec is certainly positive. */
	diff->tv_sec = a->tv_sec - b->tv_sec;
	diff->tv_usec = a->tv_usec - b->tv_usec;
}

/*
 *	times_close_enough -- Check if two times are less than fuzz ms apart
 *
 *	Inputs:
 *
 *	t1	First time value
 *	t2	Second time value
 *	fuzz	Fuzz value
 *
 *	Returns:
 *
 *	1 if t1 and t2 are within fuzz ms of each other.  Otherwise 0.
 */
int times_close_enough(struct timeval *t1, struct timeval *t2, unsigned fuzz)
{
	struct timeval diff;
	int diff_ms;

	timeval_diff(t1, t2, &diff); /* diff = t1 - t2 */
	diff_ms = abs(1000 * diff.tv_sec + diff.tv_usec / 1000);
	if (diff_ms <= fuzz)
		return 1;
	else
		return 0;
}

/*
 *	hstr_i -- Convert two-digit hex string to unsigned integer
 *
 *	Inputs:
 *
 *	cptr	Two-digit hex string
 *
 *	Returns:
 *
 *	Number corresponding to input hex value.
 *
 *	An input of "0A" or "0a" would return 10.
 *	Note that this function does no sanity checking, it's up to the
 *	caller to ensure that *cptr points to at least two hex digits.
 *
 *	This function is a modified version of hstr_i at www.snippets.org.
 */
unsigned int hstr_i(const char *cptr)
{
	unsigned int i;
	unsigned int j = 0;
	int k;

	for (k = 0; k < 2; k++) {
		i = *cptr++ - '0';
		if (9 < i)
			i -= 7;
		j <<= 4;
		j |= (i & 0x0f);
	}
	return j;
}

/*
 *	hex2data -- Convert hex string to binary data
 *
 *	Inputs:
 *
 *	string		The string to convert
 *	data_len	(output) The length of the resultant binary data
 *
 *	Returns:
 *
 *	Pointer to the binary data.
 *
 *	The returned pointer points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.  If the length of
 *	the inputs string is not even, the function will return NULL and
 *	set data_len to 0.
 */
unsigned char *hex2data(const char *string, size_t *data_len)
{
	unsigned char *data;
	unsigned char *cp;
	unsigned i;
	size_t len;

	if (strlen(string) % 2 ) { /* Length is odd */
		*data_len = 0;
		return NULL;
	}

	len = strlen(string) / 2;
	data = Malloc(len);
	cp = data;
	for (i = 0; i < len; i++)
		*cp++ = hstr_i(&string[i * 2]);
	*data_len = len;
	return data;
}

/*
 *	hex_or_str -- Convert hex or string to binary data
 *
 *	Inputs:
 *
 *	string		The hex or string to convert
 *	data_len	(output) The length of the resultant binary data
 *
 *	Returns:
 *
 *	Pointer to the binary data, or NULL if an error occurred.
 *
 *	The input string must be in one of the following two formats:
 *
 *	0x<hex-data>	Input is in hex format
 *	string		Input is in string format
 *
 *	The returned pointer points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.  If the length of
 *	the inputs string is not even, the function will return NULL and
 *	set data_len to 0.
 */
unsigned char *hex_or_str(const char *string, size_t *data_len)
{

	if (strlen(string) < 1) { /* Input string too short */
		*data_len = 0;
		return NULL;
	}

	if (string[0] == '0' && string[1] == 'x') {     /* Hex input format */
		return hex2data((string + 2), data_len);
	} else {                                        /* Assume string input format */
		unsigned char *data;
		size_t len;

		len = strlen(string);
		data = Malloc(len);
		memcpy(data, string, len);
		*data_len = len;
		return data;
	}
}

/*
 * make_message -- allocate a sufficiently large string and print into it.
 *
 * Inputs:
 *
 * Format and variable number of arguments.
 *
 * Outputs:
 *
 * Pointer to the string,
 *
 * The code for this function is from the Debian Linux "woody" sprintf man
 * page.  Modified slightly to use wrapper functions for malloc and realloc.
 */
char *make_message(const char *fmt, ...)
{
	int n;
	/* Guess we need no more than 100 bytes. */
	size_t size = 100;
	char *p;
	va_list ap;

	p = Malloc(size);
	while (1) {
		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		n = vsnprintf(p, size, fmt, ap);
		va_end(ap);
		/* If that worked, return the string. */
		if (n > -1 && n < size)
			return p;

		/* Else try again with more space. */
		if (n > -1)             /* glibc 2.1 */
			size = n + 1;   /* precisely what is needed */
		else                    /* glibc 2.0 */
			size *= 2;      /* twice the old size */
		p = Realloc(p, size);
	}
}

/*
 *	numstr -- Convert an unsigned integer to a string
 *
 *	Inputs:
 *
 *	num	The number to convert
 *
 *	Returns:
 *
 *	Pointer to the string representation of the number.
 *
 *	This is used by the STR_OR_ID macro.
 *	I'm surprised that there is not a standard library function to do this.
 */
char *numstr(unsigned num)
{
	static char buf[21]; /* Large enough for biggest 64-bit integer */

	snprintf(buf, sizeof(buf), "%d", num);
	return buf;
}

/*
 *	printable -- Convert string to printable form using C-style escapes
 *
 *	Inputs:
 *
 *	string	Pointer to input string.
 *	size	Size of input string.  0 means that string is null-terminated.
 *
 *	Returns:
 *
 *	Pointer to the printable string.
 *
 *	Any non-printable characters are replaced by C-Style escapes, e.g.
 *	"\n" for newline.  As a result, the returned string may be longer than
 *	the one supplied.
 *
 *	This function makes two passes through the input string: one to
 *	determine the required output length, then a second to perform the
 *	conversion.
 *
 *	The pointer returned points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.
 */
char *printable(unsigned char *string, size_t size)
{
	char *result;
	char *r;
	unsigned char *cp;
	size_t outlen;
	unsigned i;

/*
 *	If the input string is NULL, return an empty string.
 */
	if (string == NULL) {
		result = Malloc(1);
		result[0] = '\0';
		return result;
	}
/*
 *	Determine required size of output string.
 */
	if (!size)
		size = strlen((char *) string);

	outlen = size;
	cp = string;
	for (i = 0; i < size; i++) {
		switch (*cp) {
		case '\\':
		case '\b':
		case '\f':
		case '\n':
		case '\r':
		case '\t':
		case '\v':
			outlen++;
			break;
		default:
			if (!isprint(*cp))
				outlen += 3;
		}
		cp++;
	}
	outlen++; /* One more for the ending NULL */

	result = Malloc(outlen);

	cp = string;
	r = result;
	for (i = 0; i < size; i++) {
		switch (*cp) {
		case '\\':
			*r++ = '\\';
			*r++ = '\\';
			break;
		case '\b':
			*r++ = '\\';
			*r++ = 'b';
			break;
		case '\f':
			*r++ = '\\';
			*r++ = 'f';
			break;
		case '\n':
			*r++ = '\\';
			*r++ = 'n';
			break;
		case '\r':
			*r++ = '\\';
			*r++ = 'r';
			break;
		case '\t':
			*r++ = '\\';
			*r++ = 't';
			break;
		case '\v':
			*r++ = '\\';
			*r++ = 'v';
			break;
		default:
			if (isprint(*cp)) {
				*r++ = *cp; /* Printable character */
			} else {
				*r++ = '\\';
				sprintf(r, "%.3o", *cp);
				r += 3;
			}
			break;
		}
		cp++;
	}
	*r = '\0';

	return result;
}

/*
 *	hexstring -- Convert data to printable hex string form
 *
 *	Inputs:
 *
 *	string	Pointer to input data.
 *	size	Size of input data.
 *
 *	Returns:
 *
 *	Pointer to the printable hex string.
 *
 *	Each byte in the input data will be represented by two hex digits
 *	in the output string.  Therefore the output string will be twice
 *	as long as the input data plus one extra byte for the trailing NULL.
 *
 *	The pointer returned points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.
 */
char *hexstring(unsigned char *data, size_t size)
{
	char *result;
	char *r;
	unsigned char *cp;
	unsigned i;

/*
 *	If the input data is NULL, return an empty string.
 */
	if (data == NULL) {
		result = Malloc(1);
		result[0] = '\0';
		return result;
	}
/*
 *	Create and return hex string.
 */
	result = Malloc(2 * size + 1);
	cp = data;
	r = result;
	for (i = 0; i < size; i++) {
		sprintf(r, "%.2x", *cp++);
		r += 2;
	}
	*r = '\0';

	return result;
}

/*
 *	print_times -- Print absolute and delta time for debugging
 *
 *	Inputs:
 *
 *	None.
 *
 *	Returns:
 *
 *	None.
 *
 *	This function is only used for debugging.  It should not be called
 *	from production code.
 */
void print_times(void)
{
	static struct timeval time_first;       /* When print_times() was first called */
	static struct timeval time_last;        /* When print_times() was last called */
	static int first_call = 1;
	struct timeval time_now;
	struct timeval time_delta1;
	struct timeval time_delta2;

	Gettimeofday(&time_now);

	if (first_call) {
		first_call = 0;
		time_first.tv_sec  = time_now.tv_sec;
		time_first.tv_usec = time_now.tv_usec;
		printf("%lu.%.6lu (0.000000) [0.000000]\n",
		       (unsigned long)time_now.tv_sec,
		       (unsigned long)time_now.tv_usec);
	} else {
		timeval_diff(&time_now, &time_last, &time_delta1);
		timeval_diff(&time_now, &time_first, &time_delta2);
		printf("%lu.%.6lu (%lu.%.6lu) [%lu.%.6lu]\n",
		       (unsigned long)time_now.tv_sec,
		       (unsigned long)time_now.tv_usec,
		       (unsigned long)time_delta1.tv_sec,
		       (unsigned long)time_delta1.tv_usec,
		       (unsigned long)time_delta2.tv_sec,
		       (unsigned long)time_delta2.tv_usec);
	}
	time_last.tv_sec  = time_now.tv_sec;
	time_last.tv_usec = time_now.tv_usec;
}

#ifndef HAVE_OPENSSL
/*
 *	MD5 -- Calculate MD5 hash of specified data
 *
 *	Inputs:
 *
 *	d	The data to hash
 *	n	The length of the data
 *	md	The resulting MD5 hash
 *
 *	Returns:
 *
 *	The MD5 hash.
 *
 *	This function is a wrapper for the MD5 routines in md5.c.  If ike-scan
 *	was compiled with OpenSSL, then the OpenSSL MD5 routines are used
 *	instead, and this wrapper is not used.
 */
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md)
{
	md5_state_t context;
	static unsigned char m[16];

	if (md == NULL) /* Use static storage if no buffer specified */
		md = m;

	md5_init(&context);
	md5_append(&context, d, n);
	md5_finish(&context, md);

	return md;
}
#endif

#ifndef HAVE_OPENSSL
/*
 *	SHA1 -- Calculate SHA1 hash of specified data
 *
 *	Inputs:
 *
 *	d	The data to hash
 *	n	The length of the data
 *	md	The resulting SHA1 hash
 *
 *	Returns:
 *
 *	The SHA1 hash.
 *
 *	This function is a wrapper for the SHA1 routines in sha1.c.  If ike-scan
 *	was compiled with OpenSSL, then the OpenSSL MD5 routines are used
 *	instead, and this wrapper is not used.
 */
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md)
{
	SHA1_CTX context;
	static unsigned char m[20];

	if (md == NULL) /* Use static storage if no buffer specified */
		md = m;

	SHA1Init(&context);
/*
 * SHA1Update's prototype doesn't use "const", so we use a cast to prevent
 * a warning.  It would really be better to fix sha1.[ch] so that they use
 * const, and I may do that some day.
 */
	SHA1Update(&context, (unsigned char *)d, n);
	SHA1Final(md, &context);

	return md;
}
#endif

/*
 *	hmac_md5 -- Calculate HMAC-MD5 keyed hash
 *
 *	Inputs:
 *
 *	text		The data to hash
 *	text_len	Length of the data in bytes
 *	key		The key
 *	key_len		Length of the key in bytes
 *	digest		The resulting HMAC-MD5 digest
 *
 *	Returns:
 *
 *	The HMAC-MD5 hash.
 *
 *	This function is based on the code from the RFC 2104 appendix.
 *
 *	We use #ifdef to select either the OpenSSL MD5 functions or the
 *	built-in MD5 functions depending on whether HAVE_OPENSSL is defined.
 *	This is faster that calling OpenSSL "HMAC" directly.
 */
unsigned char *hmac_md5(const unsigned char *text, size_t text_len,
			const unsigned char *key,
			size_t key_len, unsigned char *md)
{
	static unsigned char m[16];

#ifdef HAVE_OPENSSL
	MD5_CTX context;
#else
	md5_state_t context;
#endif
	unsigned char k_ipad[65];       /* inner padding -  key XORd with ipad */
	unsigned char k_opad[65];       /* outer padding -  key XORd with opad */
	unsigned char tk[16];
	int i;

	if (md == NULL) /* Use static storage if no buffer specified */
		md = m;

	/* if key is longer than 64 bytes reset it to key=MD5(key) */
	if (key_len > 64) {
#ifdef HAVE_OPENSSL
		MD5_CTX tctx;

		MD5_Init(&tctx);
		MD5_Update(&tctx, key, key_len);
		MD5_Final(tk, &tctx);
#else
		md5_state_t tctx;

		md5_init(&tctx);
		md5_append(&tctx, key, key_len);
		md5_finish(&tctx, tk);
#endif

		key = tk;
		key_len = 16;
	}
	/*
	 * the HMAC_MD5 transform looks like:
	 *
	 * MD5(K XOR opad, MD5(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected
	 */

	/* start out by storing key in pads */
	memset(k_ipad, '\0', sizeof k_ipad);
	memset(k_opad, '\0', sizeof k_opad);
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
#ifdef HAVE_OPENSSL
	/*
	 * perform inner MD5
	 */
	MD5_Init(&context);                     /* init context for 1st pass */
	MD5_Update(&context, k_ipad, 64);       /* start with inner pad */
	MD5_Update(&context, text, text_len);   /* then text of datagram */
	MD5_Final(md, &context);                /* finish up 1st pass */
	/*
	 * perform outer MD5
	 */
	MD5_Init(&context);                     /* init context for 2nd pass */
	MD5_Update(&context, k_opad, 64);       /* start with outer pad */
	MD5_Update(&context, md, 16);           /* then results of 1st hash */
	MD5_Final(md, &context);                /* finish up 2nd pass */
#else
	/*
	 * perform inner MD5
	 */
	md5_init(&context);                     /* init context for 1st pass */
	md5_append(&context, k_ipad, 64);       /* start with inner pad */
	md5_append(&context, text, text_len);   /* then text of datagram */
	md5_finish(&context, md);               /* finish up 1st pass */
	/*
	 * perform outer MD5
	 */
	md5_init(&context);                     /* init context for 2nd pass */
	md5_append(&context, k_opad, 64);       /* start with outer pad */
	md5_append(&context, md, 16);           /* then results of 1st hash */
	md5_finish(&context, md);               /* finish up 2nd pass */
#endif

	return md;
}

/*
 *	hmac_sha1 -- Calculate HMAC-SHA1 keyed hash
 *
 *	Inputs:
 *
 *	text		The data to hash
 *	text_len	Length of the data in bytes
 *	key		The key
 *	key_len		Length of the key in bytes
 *	digest		The resulting HMAC-SHA1 digest
 *
 *	Returns:
 *
 *	The HMAC-SHA1 hash.
 *
 *	This function is based on the code from the RFC 2104 appendix.
 *
 *	We use #ifdef to select either the OpenSSL SHA1 functions or the
 *	built-in SHA1 functions depending on whether HAVE_OPENSSL is defined.
 *	This is faster that calling OpenSSL "HMAC" directly.
 */
unsigned char *hmac_sha1(const unsigned char *text, size_t text_len,
			 const unsigned char *key,
			 size_t key_len, unsigned char *md)
{
	static unsigned char m[20];

#ifdef HAVE_OPENSSL
	SHA_CTX context;
#else
	SHA1_CTX context;
#endif
	unsigned char k_ipad[65];       /* inner padding -  key XORd with ipad */
	unsigned char k_opad[65];       /* outer padding -  key XORd with opad */
	unsigned char tk[20];
	int i;

	if (md == NULL) /* Use static storage if no buffer specified */
		md = m;

	/* if key is longer than 64 bytes reset it to key=SHA1(key) */
	if (key_len > 64) {
#ifdef HAVE_OPENSSL
		SHA_CTX tctx;

		SHA1_Init(&tctx);
		SHA1_Update(&tctx, key, key_len);
		SHA1_Final(tk, &tctx);
#else
		SHA1_CTX tctx;

		SHA1Init(&tctx);
		SHA1Update(&tctx, (unsigned char *)key, key_len);
		SHA1Final(tk, &tctx);
#endif

		key = tk;
		key_len = 20;
	}
	/*
	 * the HMAC_SHA1 transform looks like:
	 *
	 * SHA1(K XOR opad, SHA1(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected
	 */

	/* start out by storing key in pads */
	memset(k_ipad, '\0', sizeof k_ipad);
	memset(k_opad, '\0', sizeof k_opad);
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
#ifdef HAVE_OPENSSL
	/*
	 * perform inner SHA1
	 */
	SHA1_Init(&context);                    /* init context for 1st pass */
	SHA1_Update(&context, k_ipad, 64);      /* start with inner pad */
	SHA1_Update(&context, text, text_len);  /* then text of datagram */
	SHA1_Final(md, &context);               /* finish up 1st pass */
	/*
	 * perform outer SHA1
	 */
	SHA1_Init(&context);                    /* init context for 2nd pass */
	SHA1_Update(&context, k_opad, 64);      /* start with outer pad */
	SHA1_Update(&context, md, 20);          /* then results of 1st hash */
	SHA1_Final(md, &context);               /* finish up 2nd pass */
#else
	/*
	 * perform inner SHA1
	 */
	SHA1Init(&context);                                     /* init context for 1st pass */
	SHA1Update(&context, k_ipad, 64);                       /* start with inner pad */
	SHA1Update(&context, (unsigned char *)text, text_len);  /* then text of datagram */
	SHA1Final(md, &context);                                /* finish up 1st pass */
	/*
	 * perform outer SHA1
	 */
	SHA1Init(&context);                                     /* init context for 2nd pass */
	SHA1Update(&context, k_opad, 64);                       /* start with outer pad */
	SHA1Update(&context, md, 20);                           /* then results of 1st hash */
	SHA1Final(md, &context);                                /* finish up 2nd pass */
#endif

	return md;
}

/*
 *	sig_alarm -- Signal handler for SIGALRM
 *
 *	Inputs:
 *
 *	signo		The signal number (ignored)
 *
 *	Returns:
 *
 *	None.
 *
 *	This function is used as the signal handler for SIGALRM.
 *	It doesn't perform any processing; it merely returns to
 *	interrupt the current system call.
 */
void sig_alarm(int signo)
{
	return; /* just interrupt the current system call */
}

void utils_use_rcsid(void)
{
	fprintf(stderr, "%s\n", rcsid); /* Use rcsid to stop compiler optimising away */
}
