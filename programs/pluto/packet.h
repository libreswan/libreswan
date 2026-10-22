/* parsing packets: formats and tools, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2018-2019 Andrew Cagney
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#ifndef _PACKET_H
#define _PACKET_H

#include "lswcdefs.h"
#include "chunk.h"
#include "shunk.h"
#include "ip_address.h"
#include "diag.h"

struct ip_info;
struct logger;
struct pbs_out;

/* a struct_desc describes a structure for the struct I/O routines.
 * This requires arrays of field_desc values to describe struct fields.
 */

/* Note: if an ft_af_enum field has the ISAKMP_ATTR_AF_TV bit set,
 * the subsequent ft_lv field will be interpreted as an immediate value.
 * This matches how attributes are encoded.
 * See RFC 2408 "ISAKMP" 3.3
 */

enum field_type {
	ft_zig,			/* zero (ignore violations) */
	ft_nat,			/* natural number (may be 0) */
	ft_len,			/* length of this struct and any following crud */
	ft_mnpc,		/* message's Next Payload chain field */
	ft_pnpc,		/* payload's Next Payload chain field */
	ft_lss,			/* Last Substructure field */
	ft_lv,			/* length/value field of attribute */
#define FT_LV_ATTRIBUTE_PAYLOAD_SIZE 4
	ft_enum,		/* value from an enumeration */
	ft_loose_enum,		/* value from an enumeration with only some names known */
	ft_loose_enum_enum,	/* value from an enumeration with partial name table based on previous enum */
	ft_af_enum,		/* Attribute Format + value from an enumeration */
	ft_af_loose_enum,	/* Attribute Format + enumeration, some names known */
	ft_lset,		/* bits representing set; uses jam_lset() */
	ft_raw,			/* bytes to be left in network-order */
	ft_end,			/* end of field list */
};

typedef const struct field_desc {
	enum field_type field_type;
	size_t size;		/* size, in bytes, of field */
	const char *name;
	/*
	 * cheap union:
	 *   enum_names * for ft_enum, ft_loose_enum, ft_af_enum, ft_af_loose_enum
	 *   enum_enum_names * for ft_loose_enum_enum
	 *   char *[] for ft_set
	 */
	const void *desc;
} field_desc;

typedef const struct struct_desc {
	const char *name;
	field_desc *fields;
	size_t size;
	int pt;	/* this payload type */
	unsigned nsst; /* Nested Substructure Type */
} struct_desc;

/*
 * Something to fixup later.
 */
struct fixup {
	uint8_t *loc;
	const char *name;
	struct_desc *sd;
	field_desc *fp; /* name .fp from packet.c */
};

void apply_fixup(struct logger *logger, const struct fixup *fixup, uintmax_t value);
uintmax_t fixup_value(struct logger *logger, const struct fixup *fixup);
struct fixup *pbs_out_next_payload_chain(struct pbs_out *outs);

/*
 * The formatting of input and output of packets is done through
 * packet_byte_stream objects.  These describe a stream of bytes in
 * memory.  Several routines are provided to manipulate these objects.
 * Actual packet transfer is done elsewhere.
 *
 * Note: it is safe to copy a PBS with no children because a PBS is
 * only pointed to by its children.  This is done in pbs_out_struct().
 */

struct pbs_in {
	unsigned level;				/* PBS of which we are part */
	struct_desc *desc;
	const char *name;			/* what does this PBS represent? */
	uint8_t *start;				/* public: where this stream starts */
	const uint8_t *cur;			/* public: current position (end) of stream */
	const uint8_t *roof;			/* byte after last in PBS (on output: just a limit) */
};

struct pbs_out {
	struct pbs_out *container;		/* PBS of which we are part */
	struct_desc *desc;
	const char *name;			/* what does this PBS represent? */
	uint8_t *start;				/* public: where this stream starts */
	uint8_t *cur;				/* public: current position (end) of stream */
	uint8_t *roof;				/* byte after last in PBS (on output: just a limit) */

	/*
	 * Number of sub-pbs structures this PBS contains.  At the top
	 * level this is the payload count.
	 */

	unsigned nr_structs;

	/* For an output PBS some things may need to be patched up. */

	/*
	 * For patching Length field in header.
	 *
	 * Filled in by close_pbs_out() calling apply_fixup().
	 * Note: it may not be aligned.
	 */
	struct fixup header_length_field;

	/*
	 * For patching IKEv2's Next Payload field chain.
	 *
	 * IKEv2 has a "chain" of next payloads.  The chain starts
	 * with the message's Next Payload field, and then threads its
	 * way through every single payload header.  For SK, its Next
	 * Payload field is for the first containing payload.
	 *
	 * IKEv1, provided payloads nested within an SK payload are
	 * excluded (see below), is functionally equivalent and so can
	 * also use this code.
	 */
	struct fixup next_payload_chain;

	/*
	 * For patching IKEv2's Last Substructure field.
	 *
	 * XXX: acutually, it's used to verify the last substructure
	 * bit, not set it.  Caller should know when it has reached
	 * the end.
	 *
	 * IKEv2 has nested substructures.  An SA Payload contains
	 * Proposal Substructures, and a Proposal Substructure
	 * contains Transform Substructures.
	 *
	 * When emitting a the substructure, the Last Substruc[ture]
	 * field is set to either that substructure's type (non-last)
	 * or zero (last).
	 *
	 * This is separate to the Next Payload field and the payload
	 * "chain" - the SA payload is both linked into the payload
	 * "chain" (.PT) and requires a specific sub-structure (.SST).
	 *
	 * Since IKEv1's SA, Proposal, and Transform payloads are
	 * functionally equivalent it, too, uses this code (IKEv2
	 * changed the names to avoid confusion).
	 */
	struct fixup last_substructure;

	/*
	 * Output packet byte Stream logger.
	 *
	 * Valid while the struct pbs_out is "open".
	 *
	 * IKEv2 uses on-stack pbs_out which should ensure the
	 * lifetime of the logger pointer is LE the lifetime of the
	 * logger.
	 *
	 * IKEv1 uses the global reply_stream which is a sure way to
	 * break any lifetime guarantees
	 *
	 * The input stream logger starts out with MD but then
	 * switches to a state so more complicated; and its lifetime
	 * is that of MD.
	 */
	struct logger *logger;
};

/*
 * Return a map(shunk_t) or clone(chunk_t) of the entire PBS contents
 * (i.e., for an output PBS that doesn't include any unwritten space
 * at the end).
 */

shunk_t pbs_in_all(const struct pbs_in *pbs);
chunk_t clone_pbs_in_all(const struct pbs_in *pbs, const char *name);

shunk_t pbs_out_all(const struct pbs_out *pbs);
chunk_t clone_pbs_out_all(const struct pbs_out *pbs, const char *name);

/*
 * START..CURSOR - ROOF to_cursor()
 * START - CURSOR..ROOF from_cursor()
 */
shunk_t pbs_in_to_cursor(const struct pbs_in *pbs);
shunk_t pbs_out_to_cursor(const struct pbs_out *pbs);
shunk_t pbs_in_left(const struct pbs_in *pbs);

/*
 * For an input PBS:
 *      pbs_in_left().len is remaming
 *
 * For an output PBS:
 *	pbs_left is amount of space remaining
 *
 * XXX: How can an input pbs have room()?
 */
#define pbs_left(pbs) ((size_t)((pbs)->roof - (pbs)->cur))

/*
 * Input PBS
 */

/*
 * Map a byte buffer to/from an input PBS and a read-only HUNK.
 *
 * XXX: there's a bit of a cheat going on here - the read-only buffer
 * is cast to read-write as pbs_in's buffer is still writable.
 */

struct pbs_in pbs_in_from_shunk(shunk_t shunk, const char *name); /* XXX: hackish */

diag_t pbs_in_struct(struct pbs_in *ins, struct_desc *sd,
		     void *struct_ptr, size_t struct_size,
		     struct pbs_in *obj_pbs) MUST_USE_RESULT;
diag_t pbs_in_bytes(struct pbs_in *pbs, void *bytes, size_t len,
		    const char *name) MUST_USE_RESULT;
diag_t pbs_in_shunk(struct pbs_in *pbs, size_t len, shunk_t *shunk,
		    const char *name) MUST_USE_RESULT;
#define pbs_in_thing(PBS, THING, NAME)		\
	pbs_in_bytes(PBS, &(THING), sizeof(THING), NAME)

/*
 * Output PBS
 *
 * + struct pbs_out contains an embedded logger
 *
 * + should the function fail then an internal error is logged and
 * false returned (they really shouldn't fail).
 */

/*
 * Initializers; point PBS at a pre-allocated (or static) buffer.
 *
 * XXX: should the buffer instead be allocated as part of the PBS?
 */
extern struct pbs_out open_pbs_out(const char *name, uint8_t *buffer,
				   size_t sizeof_buffer, struct logger *logger);

bool close_pbs_out(struct pbs_out *pbs);

/*
 * For sending packets (such as notifications) that won't fragment.
 *
 * MIN_MAX_UDP_DATA_v[46] is the largest a UDP packet can be before it
 * can be fragmented in transit.  i.e., UDP messages smaller than that
 * don't fragment..
 *
 * Filling this buffer is sure sign of code that needs to fragment the
 * message (IKEv2 code uses a code path that always fragments when
 * need; IKEv1 does not).
 */

struct fragment_pbs_out {
	struct pbs_out pbs;
	uint8_t buffer[PMAX(MIN_MAX_UDP_DATA_v4, MIN_MAX_UDP_DATA_v6)];
};

bool open_fragment_pbs_out(const char *name, struct fragment_pbs_out *pbs, struct logger *logger);

struct large_pbs_out {
	struct pbs_out pbs;
	uint8_t buffer[MAX_OUTPUT_UDP_SIZE];
};

bool open_large_pbs_out(const char *name, struct large_pbs_out *pbs, struct logger *logger);

/*
 * Map/clone the current contents (i.e., everything written so far)
 * [start..cur) of an output PBS as a chunk.
 */

bool pbs_out_struct_desc(struct pbs_out *outs,
			 const void *struct_ptr, size_t struct_size,
			 struct_desc *sd, struct pbs_out *obj_pbs) MUST_USE_RESULT;
#define pbs_out_struct(PBS, STRUCT, STRUCT_DESC, STRUCT_PBS)		\
	pbs_out_struct_desc(PBS, &(STRUCT), sizeof(STRUCT), STRUCT_DESC, STRUCT_PBS)

extern bool ikev1_out_generic(struct_desc *sd,
			      struct pbs_out *outs,
			      struct pbs_out *obj_pbs) MUST_USE_RESULT;
extern bool ikev1_out_generic_shunk(struct_desc *sd,
				    struct pbs_out *outs,
				    shunk_t hunk,
				    const char *name) MUST_USE_RESULT;
#define ikev1_out_generic_hunk(sd, outs, HUNK, name)			\
	ikev1_out_generic_shunk((sd), (outs), HUNK_AS_SHUNK(HUNK), (name))

bool pbs_out_zero(struct pbs_out *outs, size_t len, const char *name) MUST_USE_RESULT;

bool pbs_out_repeated_byte(struct pbs_out *pbs, uint8_t byte, size_t len,
			   const char *name) MUST_USE_RESULT;

#define pbs_out_thing(OUTS, THING, NAME) pbs_out_raw(OUTS, &(THING), sizeof(THING), NAME)

bool pbs_out_raw(struct pbs_out *outs, const void *bytes, size_t len,
		 const char *name) MUST_USE_RESULT;

#define pbs_out_hunk(OUTS, HUNK, NAME)					\
	({								\
		typeof(HUNK) hunk_ = HUNK; /* evaluate once */		\
		struct pbs_out *outs_ = OUTS;				\
		pbs_out_raw(outs_, hunk_.ptr, hunk_.len, (NAME));	\
	})


/* ISAKMP Header: for all messages
 * layout from RFC 2408 "ISAKMP" section 3.1
 *
 * NOTE: the IKEv2 header format is identical EXCEPT that the cookies are now
 * called (IKE SA) SPIs.  See RFC 5996 Figure 4.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Initiator                            !
 * !                            Cookie                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Responder                            !
 * !                            Cookie                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Message ID                           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                            Length                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Although the drafts are a little unclear, there are a few
 * places that specify that messages should be padded with 0x00
 * octets (bytes) to make the length a multiple of something.
 *
 * RFC 2408 "ISAKMP" 3.6 specifies that all messages will be
 * padded to be a multiple of 4 octets in length.
 * ??? This looks vestigial, and we ignore this requirement.
 *
 * RFC 2409 "IKE" Appedix B specifies:
 *     Each message should be padded up to the nearest block size
 *     using bytes containing 0x00.
 * ??? This does not appear to be limited to encrypted messages,
 * but it surely must be: the block size is meant to be the encryption
 * block size, and that is meaningless for a non-encrypted message.
 *
 * RFC 2409 "IKE" 5.3 specifies:
 *     Encrypted payloads are padded up to the nearest block size.
 *     All padding bytes, except for the last one, contain 0x00. The
 *     last byte of the padding contains the number of the padding
 *     bytes used, excluding the last one. Note that this means there
 *     will always be padding.
 * ??? This is nuts since payloads are not padded, messages are.
 * It also contradicts Appendix B.  So we ignore it.
 *
 * Summary: we pad encrypted output messages with 0x00 to bring them
 * up to a multiple of the encryption block size.  On input, we require
 * that any encrypted portion of a message be a multiple of the encryption
 * block size.   After any decryption, we ignore padding (any bytes after
 * the first payload that specifies a next payload of none; we don't
 * require them to be zero).
 */

#include "isakmp_hdr.h"

extern struct_desc isakmp_hdr_desc;
/* treat length as raw */
extern struct_desc raw_isakmp_hdr_desc;

/* Generic portion of all ISAKMP payloads.
 * layout from RFC 2408 "ISAKMP" section 3.2
 * This describes the first 32-bit chunk of all payloads.
 * The previous next payload depends on the actual payload type.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_generic {
	uint8_t isag_np;
	uint8_t isag_reserved;
	uint16_t isag_length;
};

/*
 * Nasty evil global packet buffer.
 */

extern uint8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

/*
 * Utilities:
 *
 * XXX: is there a better place to be adding these in functions that
 * build on the primitives?
 */

diag_t pbs_in_address(struct pbs_in *input_pbs,
		      ip_address *address, const struct ip_info *af,
		      const char *WHAT) MUST_USE_RESULT;
bool pbs_out_address(struct pbs_out *output_pbs, const ip_address address,
		     const char *what) MUST_USE_RESULT;

int pbs_peek_byte(const struct pbs_in *ins);

#endif /* _PACKET_H */
