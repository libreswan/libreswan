/* address pool, for libreswan
 *
 * addresspool management functions used with left/rightaddresspool= option.
 * Currently used for IKEv1 XAUTH/ModeConfig options if we are an XAUTH server.
 * And in IKEv2 to respond to Configuration Payload (CP) request.
 *
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019-2020  Andrew Cagney
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
 *
 */

/* Address Pools
 *
 * With XAUTH/CP, we need a way to allocate an address to a client.
 * This address must be unique on our system.
 * The pools of addresses to be used are declared in our config file.
 * Each connection may specify a pool as a range of IPv4 or IPv6 addresses.
 * All pools must be non-everlapping, but each pool may be
 * used for more than one connection.
 */

#include "lswalloc.h"
#include "connections.h"
#include "defs.h"
#include "constants.h"
#include "addresspool.h"
#include "monotime.h"
#include "ip_address.h"
#include "ip_range.h"
#include "log.h"
#include "state_db.h"

#define SENTINEL (unsigned)-1
#define ENTRY_UNUSED (unsigned)-2

struct entry {
	unsigned prev;
	unsigned next;
};

static const struct entry empty_entry = {
	.prev = ENTRY_UNUSED,
	.next = ENTRY_UNUSED,
};

struct list {
	unsigned first;
	unsigned last;
	unsigned nr;
};

static const struct list empty_list = {
	.nr = 0,
	.first = SENTINEL,
	.last = SENTINEL,
};

#define IS_INSERTED(WHAT, LIST) (WHAT->LIST.prev != ENTRY_UNUSED || \
				 WHAT->LIST.next != ENTRY_UNUSED)

#define IS_EMPTY(WHAT, LIST)						\
	({								\
		bool empty_ = (WHAT->LIST.nr == 0);			\
		if (empty_) {						\
			passert(WHAT->LIST.first == SENTINEL);		\
			passert(WHAT->LIST.last == SENTINEL);		\
		} else {						\
			passert(WHAT->LIST.first != SENTINEL);		\
			passert(WHAT->LIST.first < pool->nr_leases);	\
			passert(WHAT->LIST.last != SENTINEL);		\
			passert(WHAT->LIST.last < pool->nr_leases);	\
                }							\
	        empty_;							\
        })

#define HEAD(WHAT, LIST, ENTRY)						\
	({								\
		struct lease *result_;					\
		if (IS_EMPTY(WHAT, LIST)) {				\
			result_ = NULL;					\
		} else {						\
			result_ = &pool->leases[WHAT->LIST.first];	\
		}							\
		result_;						\
	})

#define REMOVE(WHAT, LIST, ENTRY, LEASE)				\
	{								\
		passert(IS_INSERTED(LEASE, ENTRY));			\
		unsigned index = LEASE - pool->leases;			\
		if (WHAT->LIST.first == index) {			\
			WHAT->LIST.first = LEASE->ENTRY.next;		\
		} else {						\
			/* not first; must have prev */			\
			passert(LEASE->ENTRY.prev != SENTINEL);		\
			passert(LEASE->ENTRY.prev < pool->nr_leases);	\
			pool->leases[LEASE->ENTRY.prev].ENTRY.next =	\
				LEASE->ENTRY.next;			\
		}							\
		if (WHAT->LIST.last == index) {				\
			WHAT->LIST.last = LEASE->ENTRY.prev;		\
		} else {						\
			/* not last; must have next */			\
			passert(LEASE->ENTRY.next != SENTINEL);		\
			passert(LEASE->ENTRY.next < pool->nr_leases);	\
			pool->leases[LEASE->ENTRY.next].ENTRY.prev =	\
				LEASE->ENTRY.prev;			\
		}							\
		LEASE->ENTRY.next = LEASE->ENTRY.prev = ENTRY_UNUSED;	\
		WHAT->LIST.nr--;					\
		passert(!IS_INSERTED(LEASE, ENTRY));			\
	}

#define FILL(WHAT, LIST, ENTRY, LEASE)					\
	{								\
		/* empty */						\
		unsigned index = LEASE - pool->leases;			\
		WHAT->LIST.first = WHAT->LIST.last = index;		\
		LEASE->ENTRY.next = LEASE->ENTRY.prev = SENTINEL;	\
	}

#define APPEND(WHAT, LIST, ENTRY, LEASE)				\
	{								\
		passert(!IS_INSERTED(LEASE, ENTRY));			\
		if (IS_EMPTY(WHAT, LIST)) {				\
			FILL(WHAT, LIST, ENTRY, LEASE);			\
		} else {						\
			unsigned index = LEASE - pool->leases;		\
			unsigned old_last = WHAT->LIST.last;		\
			LEASE->ENTRY.next = SENTINEL;			\
			LEASE->ENTRY.prev = old_last;			\
			pool->leases[old_last].ENTRY.next = index;	\
			WHAT->LIST.last = index;			\
		}							\
		WHAT->LIST.nr++;					\
		passert(IS_INSERTED(LEASE, ENTRY));			\
	}

#define PREPEND(WHAT, LIST, ENTRY, LEASE)				\
	{								\
		passert(!IS_INSERTED(LEASE, ENTRY));			\
		if (IS_EMPTY(WHAT, LIST)) {				\
			/* empty */					\
			FILL(WHAT, LIST, ENTRY, LEASE);			\
		} else {						\
			unsigned index = LEASE - WHAT->leases;		\
			unsigned old_first = WHAT->LIST.first;		\
			LEASE->ENTRY.next = old_first;			\
			LEASE->ENTRY.prev = SENTINEL;			\
			pool->leases[old_first].ENTRY.prev = index;	\
			WHAT->LIST.first = index;			\
		}							\
		WHAT->LIST.nr++;					\
		passert(IS_INSERTED(LEASE, ENTRY));			\
	}

/*
 * A pool is a range of IP addresses to be individually allocated.
 * A connection may have a pool.
 * That pool may be shared with other connections (hence the reference count).
 *
 * A pool has a linked list of leases.
 */

struct lease {
	co_serial_t assigned_to; /* ALWAYS 1:1 */

	struct entry free_entry;
	struct entry reusable_entry;

	char *reusable_name;
	struct list reusable_bucket;
};

struct ip_pool {
	unsigned pool_refcount;	/* reference counted! */
	ip_range r;
	uint32_t size; /* number of addresses within range */

	unsigned nr_reusable;
	struct list free_list;
	unsigned nr_in_use;	/* active */
	/* --- .free.nr + .nr_in_use --- */
	unsigned nr_leases;	/* nr elements in leases array */

	/*
	 * An array of leases with NR_LEASES elements.  Entry A is for
	 * address r.start+A.
	 */
	struct lease *leases;

	struct ip_pool *next;	/* next pool */
};

static struct ip_pool *pluto_pools = NULL;

static void free_lease_content(struct lease *lease)
{
	pfreeany(lease->reusable_name);
}

static unsigned hasher(const char *name)
{
	/*
	 * 251 is a prime close to 256 (so like <<8).
	 *
	 * There's no real rationale for doing this.
	 */
	unsigned hash = 0;
	for (const char *c = name; *c; c++) {
		hash = hash * 251 + (uint8_t) *c;
	}
	return hash;
}

static struct lease *lease_id_bucket(struct ip_pool *pool, const char *name)
{
	unsigned hash = hasher(name);
	return &pool->leases[hash % pool->nr_leases];
}

static void hash_lease_id(struct ip_pool *pool, struct lease *lease)
{
	struct lease *bucket = lease_id_bucket(pool, lease->reusable_name);
	APPEND(bucket, reusable_bucket, reusable_entry, lease);
	pool->nr_reusable++;
}

static void unhash_lease_id(struct ip_pool *pool, struct lease *lease)
{
	struct lease *bucket = lease_id_bucket(pool, lease->reusable_name);
	REMOVE(bucket, reusable_bucket, reusable_entry, lease);
	pool->nr_reusable--;
}

static ip_address lease_address(const struct ip_pool *pool,
				const struct lease *lease)
{
	/* careful here manipulating raw bits and bytes  */
	ip_address addr = pool->r.start;
	chunk_t addr_chunk = address_as_chunk(&addr);
	/* extract the end */
	uint32_t addr_n;
	passert(addr_chunk.len >= sizeof(addr_n));
	uint8_t *ptr = addr_chunk.ptr; /* cast void */
	ptr += addr_chunk.len - sizeof(addr_n);
	memcpy(&addr_n, ptr, sizeof(addr_n));
	/* new value - overflow? */
	unsigned i = lease - pool->leases;
	addr_n = htonl(ntohl(addr_n) + i);
	/* put it back */
	memcpy(ptr, &addr_n, sizeof(addr_n));
	return addr;
}

static void DBG_pool(bool verbose, const struct ip_pool *pool,
		     const char *format, ...) PRINTF_LIKE(3);
static void DBG_pool(bool verbose, const struct ip_pool *pool,
		     const char *format, ...)
{
	LSWLOG_DEBUG(buf) {
		jam(buf, "pool ");
		jam_range(buf, &pool->r);
		jam(buf, ": ");
		va_list args;
		va_start(args, format);
		jam_va_list(buf, format, args);
		va_end(args);
		if (verbose) {
			jam(buf, "; pool-refcount %u size %u leases %u in-use %u free %u reusable %u",
			    pool->pool_refcount, pool->size, pool->nr_leases,
			    pool->nr_in_use, pool->free_list.nr, pool->nr_reusable);
		}
	}
}

static void DBG_lease(bool verbose, const struct ip_pool *pool, const struct lease *lease,
		      const char *format, ...) PRINTF_LIKE(4);
static void DBG_lease(bool verbose, const struct ip_pool *pool, const struct lease *lease,
		      const char *format, ...)
{
	LSWLOG_DEBUG(buf) {
		jam(buf, "pool ");
		jam_range(buf, &pool->r);
		jam(buf, " lease ");
		ip_address addr = lease_address(pool, lease);
		jam_address(buf, &addr);
		if (co_serial_is_set(lease->assigned_to)) {
			jam(buf, " "PRI_CO, pri_co(lease->assigned_to));
		} else {
			jam(buf, " unassigned");
		}
		jam(buf, ": ");
		va_list args;
		va_start(args, format);
		jam_va_list(buf, format, args);
		va_end(args);
		if (verbose) {
			jam(buf, "; leases %u in-use %u free %u reusable %u",
			    pool->nr_leases, pool->nr_in_use,
			    pool->free_list.nr, pool->nr_reusable);
		}
	}
}

/*
 * A lease is an assignment of a single address from a particular pool.
 *
 * Leases are shared between appropriate connections.
 *
 * Because leases are shared, they are reference-counted.
 * (Since we don't (yet?) free leases that could be shared,
 * we don't actually need reference counting.)
 *
 * When a lease ends, if it could not be shared, it is freed.
 * Otherwise it "lingers" so that the same client (based on ID) can later
 * be assigned the same address from the pool.
 *
 * In the future we may implement code to delete a lingering lease to free
 * the address if there is no free address in the pool.
 *
 * Life cycle:
 *
 * - created by lease_an_address if an existing or lingering lease for the
 *   same thatid isn't found.
 *
 * - released (to linger or freed) by rel_lease_addr.
 *
 * - current code never frees a lease that could be shared.
 *   ??? This constitutes a leak.
 */

static bool can_reuse_lease(const struct connection *c)
{
	/*
	 * Cannot share with PSK - it either uses GroupID or
	 * a non-unique ID_IP* due to clients using pre-NAT IP address
	 */
	if (((c->policy & POLICY_PSK) != LEMPTY) || c->spd.that.authby == AUTHBY_PSK)
		return false;

	/* Cannot share with NULL authentication */
	if (((c->policy & POLICY_AUTH_NULL) != LEMPTY) || c->spd.that.authby == AUTHBY_NULL)
		return false;

	/* Cannot share NULL/NONE ID. Also cannot share ID_IP* due to NAT and dynamic IP */
	if (c->spd.that.id.kind == ID_NULL || c->spd.that.id.kind == ID_NONE ||
	    c->spd.that.id.kind == ID_IPV4_ADDR || c->spd.that.id.kind == ID_IPV6_ADDR)
		return false;

	/* If uniqueids=false - this can mean multiple clients on the same ID & CERT */
	if (!uniqueIDs)
		return false;

	return true;
}

/*
 * return the connection's current lease.
 */
static struct lease *connection_lease(struct connection *c)
{
	if (!c->spd.that.has_lease) {
		return NULL;
	}

	/*
	 * "i" is index of client.addr within pool's range.
	 *
	 * Using unsigned arithmetic means that if client.addr is less
	 * than start, i will wrap around to a very large value.
	 * Therefore a single test against size will indicate
	 * membership in the range.
	 */
	struct ip_pool *pool = c->pool;
	ip_address cp = subnet_prefix(&c->spd.that.client);
	uint32_t i = ntohl_address(&cp) - ntohl_address(&pool->r.start);
	passert(pool->nr_leases <= pool->size);
	passert(i < pool->nr_leases);
	struct lease *lease = &pool->leases[i];
	pexpect(co_serial_is_set(lease->assigned_to));
	pexpect(co_serial_eq(lease->assigned_to, c->serialno));
	return lease;
}

/*
 * mark a lease as ended.
 *
 * If the ID is distinctive and uniqueid is set, the lease "lingers"
 * so that the same client can be reassigned the same address.
 * A lingering lease is available to be re-activated
 * by lease_an_address/find_lingering_lease to the same thatid when uniqueid is
 * set.
 *
 * If uniqueIDs is set or thatid is ID_NONE, we don't know how to share.
 * In that case, we do free the lease since that ID isn't distinctive.
 */

void free_that_address_lease(struct connection *c)
{
	passert(subnet_type(&c->spd.that.client) != NULL);

	struct lease *lease = connection_lease(c);
	if (lease == NULL) {
		return;
	}

	struct ip_pool *pool = c->pool;
	if (lease->reusable_name != NULL) {
		/* the lease is reusable, leave it lingering */
		APPEND(pool, free_list, free_entry, lease);
		pool->nr_in_use--;
		if (DBGP(DBG_BASE)) {
			connection_buf cb;
			DBG_lease(true, pool, lease, "lingering reusable lease '%s' for connection "PRI_CONNECTION,
				  lease->reusable_name, pri_connection(c, &cb));
		}
	} else {
		/* cannot share: free it */
		PREPEND(pool, free_list, free_entry, lease);
		pool->nr_in_use--;
		if (DBGP(DBG_BASE)) {
			connection_buf cb;
			DBG_lease(true, pool, lease, "returning one-time lease for connection "PRI_CONNECTION,
				  pri_connection(c, &cb));
		}
	}

	/* break the link */
	c->spd.that.has_lease = false;
	lease->assigned_to = unset_co_serial;
}

/*
 * return previous lease if there is one lingering for the same ID
 */

static struct lease *recover_lease(const struct connection *c, const char *that_name)
{
	struct ip_pool *pool = c->pool;
	if (pool->nr_leases == 0) {
		return NULL;
	}

	struct lease *bucket = lease_id_bucket(pool, that_name);
	if (IS_EMPTY(bucket, reusable_bucket)) {
		return NULL;
	}

	struct lease *lease;
	for (unsigned current = bucket->reusable_bucket.first;
	     current != SENTINEL; current = lease->reusable_entry.next) {
		passert(current < pool->nr_leases);
		lease = &pool->leases[current];
		passert(lease->reusable_name != NULL);
		if (streq(that_name, lease->reusable_name)) {
			if (IS_INSERTED(lease, free_entry)) {
				REMOVE(pool, free_list, free_entry, lease);
				pool->nr_in_use++;
			}
			if (DBGP(DBG_BASE)) {
				connection_buf cb;
				DBG_lease(false, pool, lease, "reclaimed by "PRI_CONNECTION" using '%s'",
					  pri_connection(c, &cb), that_name);
			}
			return lease;
		}
	}
	return NULL;
}

err_t lease_that_address(struct connection *c, const struct state *st)
{
	struct lease *lease = connection_lease(c);
	if (lease != NULL) {
		/* already leased */
		return NULL;
	}

	struct ip_pool *pool = c->pool;
	const struct id *that_id = &c->spd.that.id;
	bool reusable = can_reuse_lease(c);

	id_buf that_idb;
	char thatstr[IDTOA_BUF + MAX_XAUTH_USERNAME_LEN];
	const char *that_name = str_id(that_id, &that_idb);
	const char *story;

	jam_str(thatstr, sizeof(thatstr), that_name);

	if(st->st_xauth_username[0] != '\0')
		add_str(thatstr, sizeof(thatstr), thatstr, st->st_xauth_username);

	if (DBGP(DBG_BASE)) {
		/*
		 * ??? what is that.client.addr and why do we care?
		 *
		 * XXX: that.client[.addr] is where the lease,
		 * assigned to the remote end, ends up.  If the
		 * connection's previously had a release then it may
		 * still be the old value.
		 */
		subnet_buf b;
		connection_buf cb;
		DBG_pool(false, pool, "requesting %s lease for connection "PRI_CONNECTION" with '%s' and old address %s",
			 reusable ? "reusable" : "one-time",
			 pri_connection(c, &cb), thatstr,
			 str_subnet(&c->spd.that.client, &b));
	}

	struct lease *new_lease = NULL;
	if (reusable) {
		new_lease = recover_lease(c, thatstr);
		story = "recovered";
	}
	if (new_lease == NULL) {
		if (IS_EMPTY(pool, free_list)) {
			/* try to grow the address pool */
			if (pool->nr_leases >= pool->size) {
				if (DBGP(DBG_BASE)) {
					DBG_pool(true, pool, "no free address and no space to grow");
				}
				return "no free address in addresspool"; /* address pool exhausted */
			}
			unsigned old_nr_leases = pool->nr_leases;
			if (pool->nr_leases == 0) {
				pool->nr_leases = min(1U, pool->size);
			} else {
				pool->nr_leases = min(pool->nr_leases * 2, pool->size);
			}
			realloc_things(pool->leases, old_nr_leases, pool->nr_leases, "leases");
			DBG_pool(false, pool, "growing address pool from %u to %u",
				 old_nr_leases, pool->nr_leases);
			/* initialize new leases (and add to free list) */
			for (unsigned l = old_nr_leases; l < pool->nr_leases; l++) {
				struct lease *lease = &pool->leases[l];
				/*
				 * Danger: must initialize entire
				 * struct as resize_things(), which
				 * may use realloc(), can leave the
				 * data uninitialized.
				 */
				*lease = (struct lease) {
					.free_entry = empty_entry,
					.reusable_entry = empty_entry,
					.reusable_bucket = empty_list,
				};
				PREPEND(pool, free_list, free_entry, lease);
			}
			/* destroy existing hash table */
			for (unsigned l = 0; l < old_nr_leases; l++) {
				struct lease *lease = &pool->leases[l];
				lease->reusable_entry = empty_entry;
				lease->reusable_bucket = empty_list;
			}
			/* build a new hash table containing old */
			pool->nr_reusable = 0;
			for (unsigned l = 0; l < old_nr_leases; l++) {
				struct lease *lease = &pool->leases[l];
				if (lease->reusable_name != NULL) {
					hash_lease_id(pool, lease);
				}
			}
		}
		new_lease = HEAD(pool, free_list, free_entry);
		passert(new_lease != NULL);
		REMOVE(pool, free_list, free_entry, new_lease);
		pool->nr_in_use++;
		if (new_lease->reusable_name != NULL) {
			/* oops; takeing over this lingering lease */
			if (DBGP(DBG_BASE)) {
				DBG_lease(false, pool, new_lease, "stealing reusable lease from '%s'",
					  new_lease->reusable_name);
			}
			unhash_lease_id(pool, new_lease);
			story = "stolen";
		} else {
			story = "unused";
		}
		free_lease_content(new_lease);
		if (reusable) {
			new_lease->reusable_name = clone_str(thatstr, "lease name");
			hash_lease_id(pool, new_lease);
		}
	}

	/*
         * convert index i in range to an IP_address
	 *
	 * XXX: does this update that.client addr as a side effect?
	 */
	ip_address ia = lease_address(pool, new_lease);
	c->spd.that.has_lease = true;
	c->spd.that.has_client = true;
	c->spd.that.client = selector_from_address(&ia, &unset_protoport);
	new_lease->assigned_to = c->serialno;

	if (DBGP(DBG_BASE)) {
		subnet_buf a;
		connection_buf cb;
		DBG_lease(true, pool, new_lease,
			  "assign %s %s lease to "PRI_CONNECTION" "PRI_CO" with ID '%s' and that.client %s",
			  story,
			  reusable ? "reusable" : "one-time",
			  pri_connection(c, &cb),
			  pri_co(new_lease->assigned_to),
			  thatstr,
			  str_subnet(&c->spd.that.client, &a));
	}

	return NULL;
}

static void free_addresspool(struct ip_pool *pool)
{

	/* search for pool in list of pools so we can unlink it */
	if (pool == NULL)
		return;

	for (struct ip_pool **pp = &pluto_pools; *pp != NULL; pp = &(*pp)->next) {
		if (*pp == pool) {
			*pp = pool->next;	/* unlink pool */
			for (unsigned l = 0; l < pool->nr_leases; l++) {
				free_lease_content(&pool->leases[l]);
			}
			pfreeany(pool->leases);
			pfree(pool);
			return;
		}
	}
	if (DBGP(DBG_BASE)) {
		DBG_pool(false, pool, "pool %p not found in list of pools", pool);
	}
}

void unreference_addresspool(struct connection *c)
{
	struct ip_pool *pool = c->pool;

	if (DBGP(DBG_BASE)) {
		DBG_pool(true, pool, "unreference addresspool of conn %s[%lu] kind %s refcnt %u",
			 c->name, c->instance_serial,
			 enum_name(&connection_kind_names,
				   c->kind), pool->pool_refcount);
	}

	passert(pool->pool_refcount > 0);

	pool->pool_refcount--;
	if (pool->pool_refcount == 0) {
		if (DBGP(DBG_BASE)) {
			DBG_pool(false, pool, "freeing memory for addresspool ptr %p",
				 pool);
		}
		free_addresspool(pool);
	}

	c->pool = NULL;
}

void reference_addresspool(struct connection *c)
{
	struct ip_pool *pool = c->pool;
	pool->pool_refcount++;
	if (DBGP(DBG_BASE)) {
		connection_buf cb;
		DBG_pool(false, pool, "adding connection "PRI_CONNECTION" of kind %s",
			pri_connection(c, &cb),
			enum_name(&connection_kind_names, c->kind));
	}
}

/*
 * Finds an ip_pool that has exactly matching bounds.
 * If a pool overlaps, an error is logged AND returned
 * *pool is set to the entry found; NULL if none found.
 */
err_t find_addresspool(const ip_range *pool_range, struct ip_pool **pool)
{
	struct ip_pool *h;

	*pool = NULL;	/* nothing found (yet) */
	for (h = pluto_pools; h != NULL; h = h->next) {
		const ip_range *a = pool_range;
		const ip_range *b = &h->r;

		int sc = addrcmp(&a->start, &b->start);

		if (sc == 0 && addrcmp(&a->end, &b->end) == 0) {
			/* exact match */
			*pool = h;
			break;
		} else if (sc < 0 ? addrcmp(&a->end, &b->start) < 0 :
				    addrcmp(&a->start, &b->end) > 0) {
			/* before or after */
		} else {
			/* overlap */
			range_buf prbuf;
			range_buf hbuf;

			loglog(RC_CLASH,
				"ERROR: new addresspool %s INEXACTLY OVERLAPS with existing one %s.",
			       str_range(pool_range, &prbuf),
			       str_range(&h->r, &hbuf));
			return "ERROR: partial overlap of addresspool";
		}
	}
	return NULL;
}

/*
 * the caller must enforce the following:
 * - Range must not include 0.0.0.0 or ::0
 * - The range must be non-empty
 */

struct ip_pool *install_addresspool(const ip_range *pool_range)
{
	struct ip_pool **head = &pluto_pools;
	struct ip_pool *pool = NULL;
	err_t ugh = find_addresspool(pool_range, &pool);

	if (ugh != NULL) {
		/* some problem: refuse to install bad addresspool */
		/* ??? Assume diagnostic already logged? */
	} else if (pool != NULL) {
		/* re-use existing pool */
		if (DBGP(DBG_BASE)) {
			DBG_pool(true, pool, "reusing existing address pool@%p", pool);
		}
	} else {
		/* make a new pool */
		pool = alloc_thing(struct ip_pool, "addresspool entry");

		pool->pool_refcount = 0;
		pool->r = *pool_range;
		if (range_size(&pool->r, &pool->size)) {
			/*
			 * uint32_t overflow, 2001:db8:0:3::/64 truncated to UINT32_MAX
			 * uint32_t overflow, 2001:db8:0:3:1::/96, truncated by 1
			 */
			dbg("WARNING addresspool size overflow truncated to %u", pool->size);
		}
		passert(pool->size > 0);

		pool->nr_in_use = 0;
		pool->nr_leases = 0;
		pool->free_list = empty_list;
		pool->leases = NULL;
		/* insert */
		pool->next = *head;
		*head = pool;

		if (DBGP(DBG_BASE)) {
			DBG_pool(false, pool, "creating new address pool@%p", pool);
		}
	}
	return pool;
}

void show_addresspool_status(struct show *s)
{
	show_separator(s);
#define CHECK(A, B)							\
	if ((A) != (B)) {						\
		LOG_PEXPECT("" #A " (%u) does not match " #B " (%u)",	\
			    A, B);					\
	}
	for (struct ip_pool *pool = pluto_pools;
	     pool != NULL; pool = pool->next) {
		range_buf rb;
		show_comment(s, "address pool %s: %u addresses, %u leases, %u in-use, %u free (%u reusable)",
			     str_range(&pool->r, &rb),
			     pool->size, pool->nr_leases, pool->nr_in_use,
			     pool->free_list.nr,
			     pool->nr_reusable);
		unsigned nr_free = 0;
		unsigned nr_reusable_entries = 0;
		unsigned nr_reusable_names = 0;
		for (unsigned l = 0; l < pool->nr_leases; l++) {
			struct lease *lease = &pool->leases[l];
			ip_address lease_ip = lease_address(pool, lease);
			address_buf lease_ipb;
			const char *lease_str = str_address(&lease_ip, &lease_ipb);
			struct connection *c = connection_by_serialno(lease->assigned_to);
			nr_free += IS_INSERTED(lease, free_entry) ? 1 : 0;
			nr_reusable_entries += IS_INSERTED(lease, reusable_entry) ? 1 : 0;
			nr_reusable_names += lease->reusable_name != NULL ? 1 : 0;
			{
				/* fudge indent so show*() calls are aligned */
				show_comment(s, "    %*s %s "PRI_CO" %s%s",
					     (int)strlen(lease_str), lease_str,
					     IS_INSERTED(lease, free_entry) ? "free" : "assigned to",
					     pri_co(lease->assigned_to),
					     lease->reusable_name != NULL ? " " : "",
					     lease->reusable_name != NULL ? lease->reusable_name : "");
			}
			if (c != NULL) {
				connection_buf cb;
				show_comment(s, "    %*s "PRI_CONNECTION,
					     (int)strlen(lease_str), "",
					     pri_connection(c, &cb));
			} else {
				show_comment(s, "    %*s connection "PRI_CO" does not exist",
					     (int)strlen(lease_str), "",
					     pri_co(lease->assigned_to));
			}
			CHECK(IS_INSERTED(lease, reusable_entry), lease->reusable_name != NULL);
		}
		CHECK(pool->nr_leases, pool->nr_in_use + pool->free_list.nr);
		CHECK(nr_free, pool->free_list.nr);
		CHECK(nr_reusable_entries, pool->nr_reusable);
		CHECK(nr_reusable_names, pool->nr_reusable);
#undef CHECK
	}
}
