/* randomness machinery
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: rnd.c,v 1.26 2005/09/26 03:21:55 mcr Exp $
 */

/* A true random number generator (we hope)
 *
 * Under LINUX ("linux" predefined), use /dev/urandom.
 * Under OpenBSD ("__OpenBSD__" predefined), use arc4random().
 * Otherwise use our own random number generator based on clock skew.
 *   I (ADK) first heard of the idea from John Ioannidis, who heard it
 *   from Matt Blaze and/or Jack Lacy.
 * ??? Why is mixing need for linux but not OpenBSD?
 */

/* Pluto's uses of randomness:
 *
 * - Setting up the "secret_of_the_day".  This changes every hour!  20
 *   bytes a shot.  It is used in building responder cookies.
 *
 * - generating initiator cookies (8 bytes, once per Phase 1 initiation).
 *
 * - 32 bytes per DH local secret.  Once per Main Mode exchange and once
 *   per Quick Mode Exchange with PFS.  (Size is our choice, with
 *   tradeoffs.)
 *
 * - 16 bytes per nonce we generate.  Once per Main Mode exchange and
 *   once per Quick Mode exchange.  (Again, we choose the size.)
 *
 * - 4 bytes per SPI number that we generate.  We choose the SPIs for all
 *   inbound SPIs, one to three per IPSEC SA (one for AH (rare, probably)
 *   one for ESP (almost always), and one for tunnel (very common)).
 *   I don't actually know how the kernel would generate these numbers --
 *   currently Pluto generates them; this isn't the way things will be
 *   done in the future.
 *
 * - 4 bytes per Message ID we need to generate.  One per Quick Mode
 *   exchange.  Eventually, one per informational exchange.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <time.h>

#include <openswan.h>

#include "sha1.h"
#include "constants.h"
#include "defs.h"
#include "rnd.h"
#include "log.h"
#include "timer.h"

static int random_fd = -1;
const char *random_devices[]={
#if defined(linux) 
  "/dev/hw_random",
  "/dev/urandom"
#elif defined(macintosh) || (defined(__MACH__) && defined(__APPLE__))
  "/dev/urandom",
  "/dev/random"
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
  "/dev/random"
#elif defined(__CYGWIN__)
  "/dev/random"
#endif
};

/* if we want to use ARC4, then the Makefile should have compiled rndarc4.c
 * rather than this file
 */

#define RANDOM_POOL_SIZE   SHA1_DIGEST_SIZE
static u_char random_pool[RANDOM_POOL_SIZE];

/* Generate (what we hope is) a true random byte using /dev/urandom  */
static u_char
generate_rnd_byte(void)
{
    u_char c;

    if (read(random_fd, &c, sizeof(c)) == -1)
	exit_log_errno((e, "read() failed in get_rnd_byte()"));

    return c;
}

#define RANDOM_POOL_SIZE   SHA1_DIGEST_SIZE
static u_char random_pool[RANDOM_POOL_SIZE];

static void
mix_pool(void)
{
    SHA1_CTX ctx;

    SHA1Init(&ctx);
    SHA1Update(&ctx, random_pool, RANDOM_POOL_SIZE);
    SHA1Final(random_pool, &ctx);
}

/*
 * Get a single random byte.
 */
static u_char
get_rnd_byte(void)
{
    random_pool[RANDOM_POOL_SIZE - 1] = generate_rnd_byte();
    random_pool[0] = generate_rnd_byte();
    mix_pool();
    return random_pool[0];
}


void
get_rnd_bytes(u_char *buffer, int length)
{
    int i;

    for (i = 0; i < length; i++)
	buffer[i] = get_rnd_byte();
}

/*
 * Initialize the random pool.
 */
void
init_rnd_pool(void)
{
    unsigned int i;
    unsigned int max_rnd_devices = elemsof(random_devices)+1;
    const char *rnd_dev;

    if(random_fd != -1) close(random_fd);
    random_fd = -1;

    for(i=0; random_fd == -1 && i<max_rnd_devices; i++) {
	DBG(DBG_CONTROL, DBG_log("opening %s", random_devices[i]));
	random_fd = open(random_devices[i], O_RDONLY);
	rnd_dev = random_devices[i];

	if (random_fd == -1) {
	    openswan_log("WARNING: open of %s failed: %s", random_devices[i]
			 , strerror(errno));
	}
    }

    if(random_fd == -1 || i == max_rnd_devices) {
	openswan_log("Failed to open any source of random. Unable to start any connections.");
	return;
    }

    openswan_log("using %s as source of random entropy", rnd_dev);

    fcntl(random_fd, F_SETFD, FD_CLOEXEC);

    get_rnd_bytes(random_pool, RANDOM_POOL_SIZE);
    mix_pool();

    /* start of rand(3) on the right foot */
    {
	unsigned int seed;

	get_rnd_bytes((void *)&seed, sizeof(seed));
	srand(seed);
    }
}

u_char    secret_of_the_day[SHA1_DIGEST_SIZE];

void
init_secret(void)
{
    /*
     * Generate the secret value for responder cookies, and
     * schedule an event for refresh.
     */
    get_rnd_bytes(secret_of_the_day, sizeof(secret_of_the_day));
    event_schedule(EVENT_REINIT_SECRET, EVENT_REINIT_SECRET_DELAY, NULL);
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
