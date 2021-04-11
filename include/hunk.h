/* buffer (pointer+length) like structs, for libreswan
 *
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef HUNK_H
#define HUNK_H

#include <stdbool.h>
#include <stddef.h>		/* size_t */
#include <stdint.h>		/* uint8_t */

/*
 * Macros and functions for manipulating hunk like structures.  Any
 * struct containing .ptr and .len fields is considered a hunk.
 *
 * The two most common hunks are:
 *
 * chunk_t: for a writeable buffer; also the original structure and
 * why the DATA field is called .ptr (.data, as used by NSS would have
 * been better).
 *
 * shunk_t: for a readonly buffer; the S is for STRING and originally
 * for static constant string manipulation.
 *
 * However, it is also possible to use these macros to manipulate
 * pre-sized buffers such as ckaid_t and struct crypt_hash where .ptr
 * is an array (hence comment above about .data being a better
 * choice).
 *
 * To avoid repeated evaluation of functions, the macros below first
 * make a copy of the hunk being manipulated.  For structures such as
 * ckaid_t where that will copy the buffer contents, it is assumed
 * that the compiler will see that things are constant and eliminate
 * them.
 */

#define THING_AS_HUNK(THING) { .ptr = &(THING), .len = sizeof(THING), }
#define NULL_HUNK { .ptr = NULL, .len = 0, }
/* #define EMPTY_HUNK { .ptr = &buffer, .len = 0, } */

/*
 * hunk version of compare functions (or at least libreswan's
 * versions).
 *
 * (Confusingly and just like POSIX, *case* ignores case).
 *
 * Just like a NULL and EMPTY ("") string, a NULL (uninitialized) and
 * EMPTY (pointing somewhere but no bytes) are considered different.
 */

bool bytes_eq(const void *l_ptr, size_t l_len,
	      const void *r_ptr, size_t r_len);
bool case_eq(const void *l_ptr, size_t l_len,
	     const void *r_ptr, size_t r_len);

#define hunk_isempty(HUNK)			\
	({					\
		(HUNK).len == 0;		\
	})

#define hunk_eq(L,R)							\
	({								\
		typeof(L) l_ = L; /* evaluate once */			\
		typeof(R) r_ = R; /* evaluate once */			\
		bytes_eq(l_.ptr, l_.len, r_.ptr, r_.len);		\
	})

#define hunk_caseeq(L, R) /* case independent */			\
	({								\
		const typeof(L) l_ = L; /* evaluate once */		\
		const typeof(R) r_ = R; /* evaluate once */		\
		case_eq(l_.ptr, l_.len, r_.ptr, r_.len);		\
	})

#define hunk_streq(HUNK, STRING)					\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const char *string_ = STRING; /* evaluate once */	\
		bytes_eq(hunk_.ptr, hunk_.len, string_,			\
			 string_ != NULL ? strlen(string_) : 0);	\
	})

#define hunk_strcaseeq(HUNK, STRING) /* case independent */		\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const char *string_ = STRING; /* evaluate once */	\
		case_eq(hunk_.ptr, hunk_.len, string_,			\
			string_ != NULL ? strlen(string_) : 0);		\
	})

/* test the start */

#define hunk_starteq(HUNK, START)					\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const typeof(START) start_ = START; /* evaluate once */	\
		hunk_.len < start_.len ? false :			\
			bytes_eq(hunk_.ptr, start_.len,			\
				 start_.ptr, start_.len);		\
	})

#define hunk_casestarteq(HUNK, START) /* case independent */		\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const typeof(START) start_ = START; /* evaluate once */	\
		hunk_.len < start_.len ? false :			\
			case_eq(hunk_.ptr, start_.len,			\
				start_.ptr, start_.len);		\
	})

#define hunk_strstarteq(HUNK, STRING)					\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const char *string_ = STRING; /* evaluate once */	\
		size_t slen_ = string_ != NULL ? strlen(string_) : 0;	\
		hunk_.len < slen_ ? false :				\
			bytes_eq(hunk_.ptr, slen_, string_, slen_);	\
	})

#define hunk_strcasestarteq(HUNK, STRING)				\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const char *string_ = STRING; /* evaluate once */	\
		size_t slen_ = string_ != NULL ? strlen(string_) : 0;	\
		hunk_.len < slen_ ? false :				\
			case_eq(hunk_.ptr, slen_, string_, slen_);	\
	})

#define hunk_strnlen(HUNK)					\
	({							\
		typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		strnlen((const char *)hunk_.ptr, hunk_.len);	\
	})

/* misc */

#define hunk_memeq(HUNK, MEM, SIZE)					\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const void *mem_ = MEM; /* evaluate once */		\
		size_t size_ = SIZE; /* evaluate once */		\
		bytes_eq(hunk_.ptr, hunk_.len, mem_, size_);		\
	})

#define hunk_thingeq(SHUNK, THING) hunk_memeq(SHUNK, &(THING), sizeof(THING))

/*
 * Manipulate the hunk as an array of characters.
 */

/* returns '\0' when out of range */
#define hunk_char(HUNK, INDEX)						\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		size_t index_ = INDEX;/* evaluate once */		\
		const char *string_ = hunk_.ptr;			\
		index_ < hunk_.len ? string_[INDEX] : '\0';		\
	})

/* see hunkcheck.c */
bool char_isbdigit(char c);
bool char_isblank(char c);
bool char_isdigit(char c);
bool char_islower(char c);
bool char_isodigit(char c);
bool char_isprint(char c);
bool char_isspace(char c);
bool char_isupper(char c);
bool char_isxdigit(char c);

char  char_tolower(char c);
char  char_toupper(char c);

#define hunk_char_ischar(HUNK, OFFSET, CHARS)			\
	({							\
		unsigned char c_ = hunk_char(HUNK, OFFSET);	\
		strchr(CHARS, c_);				\
	})

#define memcpy_hunk(DST, HUNK, SIZE)					\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		passert(hunk_.len == SIZE);				\
		memcpy(DST, hunk_.ptr, SIZE);				\
	})

/*
 * Convert between uintmax_t and network-byte-ordered data.
 */

void hton_bytes(uintmax_t h, void *bytes, size_t size);
uintmax_t ntoh_bytes(const void *bytes, size_t size);

#define ntoh_hunk(HUNK)							\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		ntoh_bytes(hunk_.ptr, hunk_.len);			\
	})

#define hton_chunk(H, HUNK) /* writeable */				\
	({								\
		const chunk_t hunk_ = HUNK; /* evaluate once */		\
		hton_bytes(H, hunk_.ptr, hunk_.len);			\
	})

/*
 * convert a hunk into a NUL terminated string; NULL is NULL.
 */

char *clone_bytes_as_string(const void *ptr, size_t len, const char *name);
#define clone_hunk_as_string(HUNK, NAME)				\
	({								\
		typeof(HUNK) hunk_ = HUNK; /* evaluate once */		\
		clone_bytes_as_string(hunk_.ptr, hunk_.len, NAME);	\
	})

#endif
