/*
 * header file for FreeS/WAN library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef _LSWTIME_H
#define _LSWTIME_H    /* seen it, no need to see it again */

#include <sys/time.h>
#include <time.h>

/*
 * UNDEFINED_TIME is meant to be an impossible exceptional time_t value.
 *
 * ??? On UNIX, 0 is a value that means 1970-01-01 00:00:00 +0000 (UTC).
 *
 * UNDEFINED_TIME is used as a real time_t value in certificate handling.
 * Perhaps this is sancioned by X.509.
 *
 * UNDEFINED_TIME is used as a mono time_t value in liveness_check().
 * 0 is PROBABLY safely distinct in this application.
 */
#define UNDEFINED_TIME  ((time_t)0)	/* ??? what a kludge! */

#define TIME_T_MAX  ((time_t) ((1ull << (sizeof(time_t) * BITS_PER_BYTE - 1)) - 1))

/*
 * Wrap time_t so that dimensional analysis will be enforced by the compiler.
 *
 * realtime_t: absolute UTC time.  Might be discontinuous due to clock adjustment.
 * monotime_t: absolute monotonic time.  No discontinuities (except for machine sleep?)
 * deltatime_t: relative time between events.  Presumed continuous.
 *
 * Try to stick to the operations implemented here.
 * A good compiler should produce identical code for these or for time_t values
 * but will catch nonsense operations through type enforcement.
 */

typedef struct { time_t delta_secs; } deltatime_t;
typedef struct { time_t real_secs; } realtime_t;
typedef struct { time_t mono_secs; } monotime_t;

/* delta time (interval) operations */

static inline deltatime_t deltatime(time_t secs) {
	deltatime_t d = { secs };
	return d;
}

static inline unsigned long deltamillisecs(deltatime_t d) {
	return d.delta_secs * 1000;
}

static inline time_t deltasecs(deltatime_t d) {
	return d.delta_secs;
}

static inline deltatime_t deltatimescale(int num, int denom, deltatime_t d) {
	/* ??? should check for overflow */
	return deltatime(deltasecs(d) * num / denom);
}

static inline bool deltaless(deltatime_t a, deltatime_t b)
{
	return deltasecs(a) < deltasecs(b);
}

static inline bool deltaless_tv_tv(const struct timeval a, const struct timeval b)
{
	return a.tv_sec < b.tv_sec ||
		( a.tv_sec == b.tv_sec && a.tv_usec < b.tv_usec);
}

static inline bool deltaless_tv_dt(const struct timeval a, const deltatime_t b)
{
	return a.tv_sec < deltasecs(b);
}

/* real time operations */

static inline realtime_t realtimesum(realtime_t t, deltatime_t d) {
	realtime_t s = { t.real_secs + d.delta_secs };
	return s;
}

static inline realtime_t undefinedrealtime(void)
{
	realtime_t u = { UNDEFINED_TIME };

	return u;
}

static inline bool isundefinedrealtime(realtime_t t)
{
	return t.real_secs == UNDEFINED_TIME;
}

static inline bool realbefore(realtime_t a, realtime_t b)
{
	return a.real_secs < b.real_secs;
}

static inline deltatime_t realtimediff(realtime_t a, realtime_t b) {
	deltatime_t d = { a.real_secs - b.real_secs };
	return d;
}

static inline realtime_t realnow(void)
{
	realtime_t t;

	time(&t.real_secs);
	return t;
}

#define REALTIMETOA_BUF     30	/* size of realtimetoa string buffer */
extern char *realtimetoa(const realtime_t rtm, bool utc, char *buf, size_t blen);

/* monotonic time operations */

static inline monotime_t monotimesum(monotime_t t, deltatime_t d) {
	monotime_t s = { t.mono_secs + d.delta_secs };
	return s;
}

static inline bool monobefore(monotime_t a, monotime_t b)
{
	return a.mono_secs < b.mono_secs;
}

static inline deltatime_t monotimediff(monotime_t a, monotime_t b) {
	deltatime_t d = { a.mono_secs - b.mono_secs };

	return d;
}

#endif /* _LIBRESWAN_H */
