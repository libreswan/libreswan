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
 * Confusingly, and just like POSIX, *case*() functions ignore case!
 *
 * Just like the C NULL and empty("") strings, NULL and non-NULL but
 * EMPTY hunks are considered non-equal vis:
 *
 *   NULL = {.ptr=NULL,.len=0);
 *   EMPTY = {.ptr="",.len=0);
 *   eq(NULL,NULL) -> TRUE
 *   eq(NULL,EMPTY) -> FALSE
 *   eq(EMPTY,NULL) -> FALSE
 *   eq(EMPTY,EMPTY) -> TRUE
 */

int raw_cmp(const void *l_ptr, size_t l_len,
	    const void *r_ptr, size_t r_len);

#define hunk_cmp(L, R)						\
	({							\
		typeof(L) l_ = L; /* evaluate once */		\
		typeof(R) r_ = R; /* evaluate once */		\
		raw_cmp(l_.ptr, l_.len, r_.ptr, r_.len);	\
	})

bool raw_eq(const void *l_ptr, size_t l_len,
	    const void *r_ptr, size_t r_len);
bool raw_caseeq(const void *l_ptr, size_t l_len,
		const void *r_ptr, size_t r_len);
bool raw_heq(const void *l_ptr, size_t l_len,
		const void *r_ptr, size_t r_len);

#define hunk_isempty(HUNK)			\
	({					\
		(HUNK).len == 0;		\
	})

#define hunk_eq(L,R)					\
	({						\
		typeof(L) l_ = L; /* evaluate once */	\
		typeof(R) r_ = R; /* evaluate once */	\
		raw_eq(l_.ptr, l_.len, r_.ptr, r_.len);	\
	})

#define hunk_caseeq(L, R) /* case independent */		\
	({							\
		const typeof(L) l_ = L; /* evaluate once */	\
		const typeof(R) r_ = R; /* evaluate once */	\
		raw_caseeq(l_.ptr, l_.len, r_.ptr, r_.len);	\
	})

#define hunk_heq(L, R) /* case independent */			\
	({							\
		const typeof(L) l_ = L; /* evaluate once */	\
		const typeof(R) r_ = R; /* evaluate once */	\
		raw_heq(l_.ptr, l_.len, r_.ptr, r_.len);	\
	})

#define hunk_streq(HUNK, STRING)					\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const char *string_ = STRING; /* evaluate once */	\
		raw_eq(hunk_.ptr, hunk_.len, string_,			\
		       string_ != NULL ? strlen(string_) : 0);		\
	})

#define hunk_strcaseeq(HUNK, STRING) /* case independent */		\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const char *string_ = STRING; /* evaluate once */	\
		raw_caseeq(hunk_.ptr, hunk_.len, string_,		\
			   string_ != NULL ? strlen(string_) : 0);	\
	})

#define hunk_strheq(HUNK, STRING) /* case and [-_] independent */	\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const char *string_ = STRING; /* evaluate once */	\
		raw_heq(hunk_.ptr, hunk_.len, string_,		\
			string_ != NULL ? strlen(string_) : 0);	\
	})

/*
 * Note: the starteq() functions return FALSE when either of the
 * parameters are NULL (which is inconsistent with the *eq() functions
 * above).
 *
 * The weak argument for this is that when *starteq() returns true, it
 * is safe to manipulate both pointers (and it means that *eat()
 * functions can be implemented using *starteq().
 */

bool raw_starteq(const void *ptr, size_t len, const void *eat, size_t eat_len);

#define hunk_starteq(HUNK, START)					\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const typeof(START) start_ = START; /* evaluate once */	\
		raw_starteq(hunk_.ptr, hunk_.len,			\
			    start_.ptr, start_.len);			\
	})

bool raw_casestarteq(const void *ptr, size_t len, const void *eat, size_t eat_len);

#define hunk_casestarteq(HUNK, START) /* case independent */		\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const typeof(START) start_ = START; /* evaluate once */	\
		raw_casestarteq(hunk_.ptr, hunk_.len,			\
				start_.ptr, start_.len);		\
	})

#define hunk_strstarteq(HUNK, STRING)					\
	hunk_starteq(HUNK, shunk1(STRING))

#define hunk_strcasestarteq(HUNK, STRING)				\
	hunk_casestarteq(HUNK, shunk1(STRING))

#define hunk_strnlen(HUNK)					\
	({							\
		typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		strnlen((const char *)hunk_.ptr, hunk_.len);	\
	})

/*
 * hunk version of functions that gobble up the start of a string (or
 * at least libreswan's versions).
 *
 * Confusingly and just like POSIX, the *case*() variant ignores case.
 *
 * Just like a NULL and EMPTY ("") string, a NULL (uninitialized) and
 * EMPTY (pointing somewhere but no bytes) are considered different.
 *
 * eat(NULL,NULL) is always false.
 */

#define hunk_eat(DINNER, EAT)						\
	({								\
		typeof(DINNER) _dinner = DINNER;			\
		typeof(EAT) _eat = EAT;					\
		bool _ok = raw_starteq(_dinner->ptr, _dinner->len,	\
				       _eat.ptr, _eat.len);		\
		if (_ok) {						\
			_dinner->ptr += _eat.len;			\
			_dinner->len -= _eat.len;			\
		}							\
		_ok;							\
	})

#define hunk_streat(DINNER, STREAT)		\
	hunk_eat(DINNER, shunk1(STREAT))

#define hunk_caseeat(DINNER, EAT)					\
	({								\
		typeof(DINNER) _dinner = DINNER;			\
		typeof(EAT) _eat = EAT;					\
		bool _ok = raw_casestarteq(_dinner->ptr, _dinner->len,	\
					   _eat.ptr, _eat.len);		\
		if (_ok) {						\
			_dinner->ptr += _eat.len;			\
			_dinner->len -= _eat.len;			\
		}							\
		_ok;							\
	})

#define hunk_strcaseeat(DINNER, STRCASEEAT)		\
	hunk_caseeat(DINNER, shunk1(STRCASEEAT))

/* misc */

#define hunk_memeq(HUNK, MEM, SIZE)					\
	({								\
		const typeof(HUNK) hunk_ = HUNK; /* evaluate once */	\
		const void *mem_ = MEM; /* evaluate once */		\
		size_t size_ = SIZE; /* evaluate once */		\
		raw_eq(hunk_.ptr, hunk_.len, mem_, size_);		\
	})

#define hunk_thingeq(SHUNK, THING) hunk_memeq(SHUNK, &(THING), sizeof(THING))

/*
 * Manipulate the hunk as an array of characters.
 */

/* returns '\0' when out of range */

#define hunk_char(HUNK, INDEX)						\
	({								\
		const typeof(HUNK) hc_hunk_ = HUNK; /* evaluate once */	\
		size_t hc_index_ = INDEX;/* evaluate once */		\
		const char *hc_char_ = hc_hunk_.ptr;			\
		hc_index_ < hc_hunk_.len ? hc_char_[INDEX] : '\0';	\
	})

/* returns the unsigned byte cast to int; or -1 when end-of-hunk */

#define hunk_byte(HUNK, INDEX)						\
	({								\
		const typeof(HUNK) hb_hunk_ = HUNK; /* evaluate once */	\
		size_t hb_index_ = INDEX;/* evaluate once */		\
		const uint8_t *hb_byte_ = hb_hunk_.ptr;			\
		hb_index_ < hb_hunk_.len ? hb_byte_[INDEX] : -1;	\
	})

/* hunk[FLOOR..ROOF) */

#define hunk_slice(HUNK, FLOOR, ROOF)			\
	({						\
		size_t _floor = FLOOR;			\
		size_t _roof = ROOF;			\
		typeof(HUNK) _hunk = HUNK;		\
		passert(_floor <= _roof);		\
		passert(_roof <= _hunk.len);		\
		typeof(HUNK) _slice = {			\
			_hunk.ptr + _floor,		\
			.len = _roof - _floor,		\
		};					\
		_slice;					\
	})

/*
 * Macros to treat a HUNK, pointing into a buffer, like a data stream:
 *
 * - initially .ptr is the start of the buffer, and .len is the
 *   buffer's size
 *
 * - .ptr is the cursor (next byte) and .len is the upper bound
 *
 * - get/put advance .ptr and reduce the .len
 *
 * - returns the get/put object as a pointer into the buffer
 *
 *   Caller is responsible for ensuring that pointer is aligned.
 *   For instance, PF_KEY V2 structures are kept 8-byte aligned.
 *
 * - returns NULL when end-of-buffer is reached
 */

#define hunk_get(HUNK, LEN)						\
	({								\
		size_t hg_len_ = LEN; /* evaluate once */		\
		typeof(HUNK) hg_hunk_ = HUNK; /* evaluate once */	\
		bool hg_ok_ = (hg_hunk_->len >= hg_len_);		\
		const void *hg_ptr_ = NULL;				\
		if (hg_ok_) {						\
			hg_ptr_ = hg_hunk_->ptr;			\
			hg_hunk_->ptr += hg_len_;			\
			hg_hunk_->len -= hg_len_;			\
		}							\
		hg_ptr_;						\
	})

#define hunk_get_thing(HUNK, TYPE)			\
	(TYPE *) hunk_get(HUNK, sizeof(TYPE))

/* returns POINTER to start of write; or NULL; see pfkey v2 code */

#define hunk_put(HUNK, PTR, LEN)					\
	({								\
		typeof(HUNK) hp_hunk_ = HUNK; /* evaluate once */	\
		size_t hp_len_ = LEN; /* evaluate once */		\
		const void *hp_src_ = PTR; /* evaluate once */		\
		void *hp_dst_ = NULL;					\
		if (hp_hunk_->len >= hp_len_) {				\
			/* can't assume memory alignment */		\
			hp_dst_ = hp_hunk_->ptr;			\
			memcpy(hp_dst_, hp_src_, hp_len_);		\
			hp_hunk_->len -= hp_len_;			\
			hp_hunk_->ptr += hp_len_;			\
		}							\
		/* XXX: can't assume alignment; but */			\
		(typeof(PTR)) hp_dst_;					\
	})

#define hunk_put_hunk(HUNK, DATA)					\
	({								\
		typeof(DATA) hph_hunk_ = DATA; /* evaluate once */	\
		hunk_put(HUNK, hph_hunk_.ptr, hph_hunk_.len);		\
	})

#define hunk_put_thing(HUNK, THING)		\
	(typeof(THING)*) hunk_put(HUNK, &(THING), sizeof(THING))

/*
 * Macros for filling in a HUNK like object (hunk like objects have an
 * array for .ptr, hence sizeof(.ptr) determines the upper bound).
 */

#define hunk_append_bytes(DST/*pointer*/, SRC_PTR, SRC_LEN)		\
	({								\
		typeof(SRC_PTR) src_ptr_ = SRC_PTR; /* evaluate once */	\
		size_t src_len_ = SRC_LEN; /* evaluate once */		\
		typeof(DST) dst_ = DST; /* evaluate once */		\
		passert(dst_->len + src_len_ <= sizeof(dst_->ptr/*array*/)); \
		typeof(dst_->ptr[0]) *dst_ptr_ = dst_->ptr + dst_->len;	\
		memcpy(dst_ptr_, src_ptr_, src_len_);			\
		dst_->len += src_len_;					\
		dst_ptr_;						\
	})

#define hunk_append_hunk(DST/*pointer*/, SRC/*value*/)		\
	({							\
		typeof(SRC) *src_ = &(SRC); /* evaluate once */	\
		hunk_append_bytes(DST, src_->ptr, src_->len);	\
	})

#define hunk_append_byte(DST/*pointer*/, BYTE, COUNT)			\
	({								\
		size_t count_ = COUNT;					\
		typeof(DST) dst_ = DST; /* evaluate once */		\
		passert(dst_->len + count_ <= sizeof(dst_->ptr)/*array*/); \
		typeof(dst_->ptr[0]) *dst_ptr_ = dst_->ptr + dst_->len;	\
		memset(dst_ptr_, BYTE, count_);				\
		dst_->len += count_;					\
		dst_ptr_;						\
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
