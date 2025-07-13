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
	ft_enum,		/* value from an enumeration */
	ft_loose_enum,		/* value from an enumeration with only some names known */
	ft_loose_enum_enum,	/* value from an enumeration with partial name table based on previous enum */
	ft_af_enum,		/* Attribute Format + value from an enumeration */
	ft_af_loose_enum,	/* Attribute Format + enumeration, some names known */
	ft_lset,		/* bits representing set; uses jam_lset() */
	ft_raw,			/* bytes to be left in network-order */
	ft_end,			/* end of field list */
};

typedef const struct {
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

typedef const struct {
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
	struct_desc *sd;
	field_desc *fp; /* name .fp from packet.c */
};

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
	struct pbs_in *container;		/* PBS of which we are part */
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

	/* For an output PBS some things may need to be patched up. */

	/*
	 * For patching Length field in header.
	 *
	 * Filled in by close_output_pbs().
	 * Note: it may not be aligned.
	 */
	uint8_t *lenfld;	/* start of variable length field */
	field_desc *lenfld_desc;	/* includes length */

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
#define close_output_pbs close_pbs_out

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
extern bool ikev1_out_generic_raw(struct_desc *sd,
				  struct pbs_out *outs, const void *bytes, size_t len,
				  const char *name) MUST_USE_RESULT;
#define ikev1_out_generic_chunk(sd, outs, ch, name) \
	ikev1_out_generic_raw((sd), (outs), (ch).ptr, (ch).len, (name))

bool pbs_out_zero(struct pbs_out *outs, size_t len, const char *name) MUST_USE_RESULT;

bool pbs_out_repeated_byte(struct pbs_out *pbs, uint8_t byte, size_t len,
			   const char *name) MUST_USE_RESULT;

#define pbs_out_thing(OUTS, THING, NAME) pbs_out_raw(OUTS, &(THING), sizeof(THING), NAME)

bool pbs_out_raw(struct pbs_out *outs, const void *bytes, size_t len,
		 const char *name) MUST_USE_RESULT;

#define out_hunk(HUNK, OUTS, NAME) pbs_out_hunk(OUTS, HUNK, NAME)

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

/* ISAKMP Data Attribute (generic representation within payloads)
 * layout from RFC 2408 "ISAKMP" section 3.3
 * This is not a payload type.
 * In TLV format, this is followed by a value field.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !A!       Attribute Type        !    AF=0  Attribute Length     !
 * !F!                             !    AF=1  Attribute Value      !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * .                   AF=0  Attribute Value                       .
 * .                   AF=1  Not Transmitted                       .
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_attribute {
	/* The high order bit of isaat_af_type is the Attribute Format
	 * If it is off, the format is TLV: lv is the length of the following
	 * attribute value.
	 * If it is on, the format is TV: lv is the value of the attribute.
	 * ISAKMP_ATTR_AF_MASK is the mask in host form.
	 *
	 * The low order 15 bits of isaat_af_type is the Attribute Type.
	 * ISAKMP_ATTR_RTYPE_MASK is the mask in host form.
	 */
	uint16_t isaat_af_type;	/* high order bit: AF; lower 15: rtype */
	uint16_t isaat_lv;		/* Length or value */
};

extern struct_desc
	isakmp_oakley_attribute_desc,
	isakmp_ipsec_attribute_desc,
	ikev2_trans_attr_desc;

/* ISAKMP Security Association Payload
 * layout from RFC 2408 "ISAKMP" section 3.4
 * A variable length Situation follows.
 * Previous next payload: ISAKMP_NEXT_SA
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                           Situation                           ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_sa {
	uint8_t isasa_np;		/* Next payload */
	uint8_t isasa_reserved;
	uint16_t isasa_length;		/* Payload length */
	uint32_t isasa_doi;		/* DOI */
};

extern struct_desc isakmp_sa_desc;

extern struct_desc ipsec_sit_desc;

/* ISAKMP Proposal Payload
 * layout from RFC 2408 "ISAKMP" section 3.5
 * A variable length SPI follows.
 *
 * XXX: Don't be confused by the field "Next Payload" in the below -
 * it has nothing to do with the next payload chain.  Its values are
 * either 0 (last) or ISAKMP_NEXT_P.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Proposal #   !  Protocol ID  !    SPI Size   !# of Transforms!
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                        SPI (variable)                         !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_proposal {
	uint8_t isap_pnp;
	uint8_t isap_reserved;
	uint16_t isap_length;
	uint8_t isap_proposal;
	uint8_t isap_protoid;
	uint8_t isap_spisize;
	uint8_t isap_notrans;		/* Number of transforms */
};

extern struct_desc isakmp_proposal_desc;

/* ISAKMP Transform Payload
 * layout from RFC 2408 "ISAKMP" section 3.6
 * Variable length SA Attributes follow.
 *
 * XXX: Don't be confused by the field "Next Payload" in the below -
 * it has nothing to do with the next payload chain.  Its values are
 * either 0 (last) or ISAKMP_NEXT_T.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Transform #  !  Transform-Id !           RESERVED2           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                        SA Attributes                          ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_transform {
	uint8_t isat_tnp;
	uint8_t isat_reserved;
	uint16_t isat_length;
	uint8_t isat_transnum;		/* Number of the transform */
	uint8_t isat_transid;
	uint16_t isat_reserved2;
};

extern struct_desc
	isakmp_isakmp_transform_desc,
	isakmp_ah_transform_desc,
	isakmp_esp_transform_desc,
	isakmp_ipcomp_transform_desc;

/* ISAKMP Key Exchange Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.7
 * Variable Key Exchange Data follow the generic fields.
 * Previous next payload: ISAKMP_NEXT_KE
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                       Key Exchange Data                       ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_keyex_desc;

/* ISAKMP Identification Payload
 * layout from RFC 2408 "ISAKMP" section 3.8
 * See "struct identity" declared later.
 * Variable length Identification Data follow.
 * Previous next payload: ISAKMP_NEXT_ID
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !   ID Type     !             DOI Specific ID Data              !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                   Identification Data                         ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_id {
	uint8_t isaid_np;
	uint8_t isaid_reserved;
	uint16_t isaid_length;
	uint8_t isaid_idtype;
	uint8_t isaid_doi_specific_a;
	uint16_t isaid_doi_specific_b;
};

extern struct_desc isakmp_identification_desc;

/* IPSEC Identification Payload Content
 * layout from RFC 2407 "IPsec DOI" section 4.6.2
 * See struct isakmp_id declared earlier.
 * Note: Hashing skips the ISAKMP generic payload header
 * Variable length Identification Data follow.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Next Payload !   RESERVED    !        Payload Length         !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !   ID Type     !  Protocol ID  !             Port              !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                     Identification Data                       ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_ipsec_id {
	uint8_t isaiid_np;
	uint8_t isaiid_reserved;
	uint16_t isaiid_length;
	uint8_t isaiid_idtype;
	uint8_t isaiid_protoid;
	uint16_t isaiid_port;
};

extern struct_desc isakmp_ipsec_identification_desc;

/* ISAKMP Certificate Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.9
 * Variable length Certificate Data follow the generic fields.
 * Previous next payload: ISAKMP_NEXT_CERT.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Cert Encoding !                                               !
 * +-+-+-+-+-+-+-+-+                                               !
 * ~                       Certificate Data                        ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_cert {
	uint8_t isacert_np;
	uint8_t isacert_reserved;
	uint16_t isacert_length;
	uint8_t isacert_type;
};

/* NOTE: this packet type has a fixed portion that is not a
 * multiple of 4 octets.  This means that sizeof(struct isakmp_cert)
 * yields the wrong value for the length.
 */
#define ISAKMP_CERT_SIZE		5

extern struct_desc isakmp_ipsec_certificate_desc;

/* ISAKMP Certificate Request Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.10
 * Variable length Certificate Types and Certificate Authorities follow.
 * Previous next payload: ISAKMP_NEXT_CR.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Cert. Type   !                                               !
 * +-+-+-+-+-+-+-+-+                                               !
 * ~                    Certificate Authority                      ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_cr {
	uint8_t isacr_np;
	uint8_t isacr_reserved;
	uint16_t isacr_length;
	uint8_t isacr_type;
};

/* NOTE: this packet type has a fixed portion that is not a
 * multiple of 4 octets.  This means that sizeof(struct isakmp_cr)
 * yields the wrong value for the length.
 */
#define ISAKMP_CR_SIZE		5

extern struct_desc isakmp_ipsec_cert_req_desc;

/* ISAKMP Hash Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.11
 * Variable length Hash Data follow.
 * Previous next payload: ISAKMP_NEXT_HASH.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                           Hash Data                           ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_hash_desc;

/* ISAKMP Signature Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.12
 * Variable length Signature Data follow.
 * Previous next payload: ISAKMP_NEXT_SIG.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                         Signature Data                        ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_signature_desc;

/* ISAKMP Nonce Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.13
 * Variable length Nonce Data follow.
 * Previous next payload: ISAKMP_NEXT_NONCE.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                            Nonce Data                         ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_nonce_desc;

/* ISAKMP Notification Payload
 * layout from RFC 2408 "ISAKMP" section 3.14
 * This is followed by a variable length SPI
 * and then possibly by variable length Notification Data.
 * Previous next payload: ISAKMP_NEXT_N
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol ID  !   SPI Size    !      Notify Message Type      !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                Security Parameter Index (SPI)                 ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                       Notification Data                       ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/* From draft-dukes-ike-mode-cfg
   3.2. Attribute Payload
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !     Type      !   RESERVED    !           Identifier          !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     !                                                               !
     ~                           Attributes                          ~
     !                                                               !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_mode_attr {
	uint8_t isama_np;
	uint8_t isama_reserved;
	uint16_t isama_length;
	uint8_t isama_type;
	uint8_t isama_reserved2;
	uint16_t isama_identifier;
};

extern struct_desc isakmp_attr_desc;
extern struct_desc isakmp_xauth_attribute_desc;

/* ISAKMP Notification Payload
 * layout from RFC 2408 "ISAKMP" section 3.14
 * This is followed by a variable length SPI
 * and then possibly by variable length Notification Data.
 * Previous next payload: ISAKMP_NEXT_N
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol ID  !   SPI Size    !      Notify Message Type      !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                Security Parameter Index (SPI)                 ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                       Notification Data                       ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_notification {
	uint8_t isan_np;
	uint8_t isan_reserved;
	uint16_t isan_length;
	uint32_t isan_doi;
	uint8_t isan_protoid;
	uint8_t isan_spisize;
	uint16_t isan_type;
};

extern struct_desc isakmp_notification_desc;

/* ISAKMP Delete Payload
 * layout from RFC 2408 "ISAKMP" section 3.15
 * This is followed by a variable length SPI.
 * Previous next payload: ISAKMP_NEXT_D
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol ID  !   SPI Size    !           # of SPIs           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~               Security Parameter Index(es) (SPI)              ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_delete {
	uint8_t isad_np;
	uint8_t isad_reserved;
	uint16_t isad_length;
	uint32_t isad_doi;
	uint8_t isad_protoid;
	uint8_t isad_spisize;
	uint16_t isad_nospi;
};

extern struct_desc isakmp_delete_desc;

/* ISAKMP Vendor ID Payload
 * layout from RFC 2408 "ISAKMP" section 3.15
 * This is followed by a variable length VID.
 * Previous next payload: ISAKMP_NEXT_VID
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                        Vendor ID (VID)                        ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_vendor_id_desc;
/* ISAKMP NAT-Traversal NAT-D
 * layout from draft-ietf-ipsec-nat-t-ike-01.txt section 3.2
 *
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                 HASH of the address and port                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_nat_d;
extern struct_desc isakmp_nat_d_drafts;

/* ISAKMP NAT-Traversal NAT-OA
 * layout from draft-ietf-ipsec-nat-t-ike-01.txt section 4.2
 *
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !   ID Type     !   RESERVED    !            RESERVED           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !         IPv4 (4 octets) or IPv6 address (16 octets)           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_nat_oa {
	uint8_t isanoa_np;
	uint8_t isanoa_reserved_1;
	uint16_t isanoa_length;
	uint8_t isanoa_idtype;
	uint8_t isanoa_reserved_2;
	uint16_t isanoa_reserved_3;
};
extern struct_desc isakmp_nat_oa;

extern struct_desc isakmp_nat_oa_drafts;

extern struct_desc isakmp_ignore_desc; /* generic payload (when ignoring) */

/* ISAKMP IKE Fragmentation Payload
 * Cisco proprietary, undocumented
 * Microsoft documentation link: http://msdn.microsoft.com/en-us/library/cc233452.aspx
 * This must be the first and only payload in a message,
 * i.e. next payload field must always be zero.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !          Fragment_ID          !  Fragment_num !     Flags     !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                         Fragment Data                         ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define NSIZEOF_isakmp_ikefrag	8	/* on-the-wire sizeof struct isakmp_ikefrag */
struct isakmp_ikefrag {
	uint8_t isafrag_np;		/* always zero, this must be the only payload */
	uint8_t isafrag_reserved;
	uint16_t isafrag_length;
	uint16_t isafrag_id;	/* MUST specify the same value for each fragment
				 * generated from the same IKE message */
	uint8_t isafrag_number;
	uint8_t isafrag_flags;	/* LAST_FRAGMENT =  0x01 */
};

extern struct_desc isakmp_ikefrag_desc;

/*
 * This a really the least significant bit in the flags octet, but it's the
 * only flag at the moment. Should really change from ft_nat to ft_set so we
 * can do proper bit naming/setting
 */
#define ISAKMP_FRAG_LAST	1

/* descriptor for each V1 payload type
 *
 * There is a slight problem in that some payloads differ, depending
 * on the mode.  Since this is table only used for top-level payloads,
 * Proposal and Transform payloads need not be handled.
 * That leaves only Identification payloads as a problem.
 * We make all these entries NULL.
 * ??? is there a good reason for these two things to be in one table?
 */
extern struct_desc *v1_payload_desc(unsigned p);

/* descriptor for V2 payload type. */
extern struct_desc *v2_payload_desc(unsigned p);


/*
 * IKEv2 structures
 */
/*
 * 3.2.  Generic Payload Header
 */
struct ikev2_generic {
	uint8_t isag_np;
	uint8_t isag_critical;
	uint16_t isag_length;
};
extern struct_desc ikev2_generic_desc;
extern struct_desc ikev2_unknown_payload_desc;

struct ikev2_sa {
	uint8_t isasa_np;		/* Next payload */
	uint8_t isasa_critical;
	uint16_t isasa_length;		/* Payload length */
};

extern struct_desc ikev2_sa_desc;

/*
 * IKEv2 Proposal Substructure
 *
 * Layout taken from RFC 7296 3.3.1.  Proposal Substructure
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Last Substruc |   RESERVED    |         Proposal Length       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                        SPI (variable)                         ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~                        <Transforms>                           ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct ikev2_prop {
	uint8_t isap_lp;		/* Last proposal or not */
					/* Matches IKEv1 ISAKMP_NEXT_P by design */
	uint8_t isap_critical;
	uint16_t isap_length;		/* Payload length */
	uint8_t isap_propnum;
	uint8_t isap_protoid;
	uint8_t isap_spisize;
	uint8_t isap_numtrans;
};

extern struct_desc ikev2_prop_desc;

/* RFC 8784 */
struct ikev2_ppk_id {
	uint8_t isappkid_type;
};
extern struct_desc ikev2_ppk_id_desc;

/* rfc4306, section 3.3.2 */
struct ikev2_trans {
	uint8_t isat_lt;		/* Last transform or not */
					/* Matches IKEv1 ISAKMP_NEXT_T by design */
	uint8_t isat_critical;
	uint16_t isat_length;		/* Payload length */
	uint8_t isat_type;		/* transform type */
	uint8_t isat_res2;
	uint16_t isat_transid;		/* ID */
};
extern struct_desc ikev2_trans_desc;

/* rfc4306, section 3.3.5 */
struct ikev2_trans_attr {
	uint16_t isatr_type;		/* Attribute Type */
	uint16_t isatr_lv;		/* Length (AF=0) or Value (AF=1) */
	/* u_intXX_t isatr_value;	Value if AF=0, absent if AF=1 */
};

/* rfc4306, section 3.4 */
struct ikev2_ke {
	uint8_t isak_np;		/* Next payload */
	uint8_t isak_critical;
	uint16_t isak_length;		/* Payload length */
	uint16_t isak_group;		/* transform type */
	uint16_t isak_res2;
};
extern struct_desc ikev2_ke_desc;

/* rfc4306, section 3.5 */
struct ikev2_id {
	uint8_t isai_np;		/* Next payload */
	uint8_t isai_critical;
	uint16_t isai_length;		/* Payload length */
	uint8_t isai_type;		/* ID type */
	uint8_t isai_res1;
	uint8_t isai_res2;
	uint8_t isai_res3;
};
extern struct_desc ikev2_id_i_desc;
extern struct_desc ikev2_id_r_desc;

/* rfc4306, section 3.8 */
struct ikev2_auth {
	uint8_t isaa_np;		/* Next payload */
	uint8_t isaa_critical;
	uint16_t isaa_length;		/* Payload length */
	uint8_t isaa_auth_method;
	uint8_t isaa_res1;
	uint16_t isaa_res2;
};
extern struct_desc ikev2_auth_desc;

/* rfc4306 section 3.6 CERT Payload */
struct ikev2_cert {
	uint8_t isac_np;	/* Next payload */
	uint8_t isac_critical;
	uint16_t isac_length;	/* Payload length */
	uint8_t isac_enc;	/* encoding type */
};

/* NOTE: this packet type has a fixed portion that is not a
 * multiple of 4 octets.  This means that sizeof(struct isakmp_cr)
 * yields the wrong value for the length.
 */
#define IKEV2_CERT_SIZE		5
extern struct_desc ikev2_certificate_desc;

/* RFC-7296 section 3.10 CERTREQ Payload */
struct ikev2_certreq {
	uint8_t isacertreq_np;		/* Next payload */
	uint8_t isacertreq_critical;
	uint16_t isacertreq_length;	/* Payload length */
	uint8_t isacertreq_enc;	/* encoding type */
};

/* NOTE: this packet type has a fixed portion that is not a
 * multiple of 4 octets.  This means that sizeof(struct isakmp_cr)
 * yields the wrong value for the length.
 */
#define IKEV2_CERTREQ_SIZE	5
extern struct_desc ikev2_certificate_req_desc;

/* rfc4306, section 3.9, nonce, uses generic header */
extern struct_desc ikev2_nonce_desc;

/*
 * IKEv2 Notify Payload
 *
 * Layout from RFC 7296 3.10.  Notify Payload
 *
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Next Payload  |C|  RESERVED   |         Payload Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Protocol ID  |   SPI Size    |      Notify Message Type      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~                Security Parameter Index (SPI)                 ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~                       Notification Data                       ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct ikev2_notify {
	uint8_t isan_np;	/* Next payload */
	uint8_t isan_critical;
	uint16_t isan_length;	/* Payload length */
	uint8_t isan_protoid;	/* Protocol ID: noSA=0,IKE=1,AH=2,ESP=3 */
	uint8_t isan_spisize;	/* SPI size: 0 for IKE_SA */
	uint16_t isan_type;	/* Notification type, see v2_notification_t */
};

extern struct_desc ikev2_notify_desc;

/* IKEv2 Delete Payload
 * layout from RFC 5996 Section 3.11
 * This is followed by a variable length SPI.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !C| RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol ID  !   SPI Size    !           Num of SPIs         !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~               Security Parameter Index(es) (SPI)              ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ikev2_delete {
	uint8_t isad_np;
	uint8_t isad_reserved;
	uint16_t isad_length;
	uint8_t isad_protoid;
	uint8_t isad_spisize;
	uint16_t isad_nrspi;
};

extern struct_desc ikev2_delete_desc;

/* rfc4306, section 3.13 */
struct ikev2_ts {
	uint8_t isat_np;	/* Next Payload */
	uint8_t isat_critical;
	uint16_t isat_length;	/* Payload length */
	uint8_t isat_num;	/* number of TSs */
	uint8_t isat_res1;
	uint16_t isat_res2;
};

struct ikev2_ts_header {
	uint8_t isath_type;
	uint8_t isath_ipprotoid;
	uint16_t isath_length;
};

struct ikev2_ts_portrange {
	uint16_t isatpr_startport;
	uint16_t isatpr_endport;
};

extern struct_desc ikev2_ts_i_desc;
extern struct_desc ikev2_ts_r_desc;
extern struct_desc ikev2_ts_header_desc;
extern struct_desc ikev2_ts_portrange_desc;

/* rfc4306, section 3.14, encrypted payload, uses generic header */
extern struct_desc ikev2_sk_desc;

/*
 * Configuration Payload . RFC 5996 section 3.15
 */
struct ikev2_cp {
	uint8_t isacp_np;
	uint8_t isacp_critical;
	uint16_t isacp_length;
	uint8_t isacp_type;
	uint8_t isacp_res1; /* 3 octets */
	uint16_t isat_res2;
};

extern struct_desc ikev2_cp_desc;

struct ikev2_cp_attribute {
	uint16_t type;
	uint16_t len;
};

extern struct_desc ikev2_cp_attribute_desc;

/* RFC 4306, section 3.16 */
extern struct_desc ikev2_eap_desc;

/* RFC 3748, section 4 */
struct eap_termination {
	uint8_t eap_code;
	uint8_t eap_identifier;
	uint16_t eap_length;
};
extern struct_desc eap_termination_desc;

/* RFC 5216, section 3.1 */
struct eap_tls {
	uint8_t eap_code;
	uint8_t eap_identifier;
	uint16_t eap_length;
	uint8_t eap_type;
	uint8_t eaptls_flags;
};
extern struct_desc eap_tls_desc;

/*
 * Fragment Message. RFC 7383 section 2.5
 */
#define NSIZEOF_ikev2_skf	8	/* on-the-wire sizeof struct ikev2_skf */
struct ikev2_skf {
	uint8_t isaskf_np;
	uint8_t isaskf_critical;
	uint16_t isaskf_length;
	uint16_t isaskf_number;
	uint16_t isaskf_total;
};

extern struct_desc ikev2_skf_desc;

/*
 * 3.12.  Vendor ID Payload
 *
 *  The Vendor ID Payload fields are defined as follows:
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                        Vendor ID (VID)                        ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
extern struct_desc ikev2_vendor_id_desc;


/* union of all payloads */

union payload {
	struct isakmp_generic generic;
	struct isakmp_sa sa;
	struct isakmp_proposal proposal;
	struct isakmp_transform transform;
	struct isakmp_id id; /* Main Mode */
	struct isakmp_cert cert;
	struct isakmp_cr cr;
	struct isakmp_ipsec_id ipsec_id; /* Quick Mode */
	struct isakmp_notification notification;
	struct isakmp_delete delete;
	struct isakmp_nat_oa nat_oa;
	struct isakmp_mode_attr mode_attribute;
	struct ikev2_generic v2gen;
	struct ikev2_ke v2ke;
	struct ikev2_trans v2trans;
	struct ikev2_prop v2prop;
	struct ikev2_sa v2sa;
	struct ikev2_id v2id;
	struct ikev2_auth v2auth;
	struct ikev2_ts v2ts;
	struct ikev2_cert v2cert;
	struct ikev2_certreq v2certreq;
	struct ikev2_notify v2n;
	struct ikev2_delete v2delete;
	struct ikev2_cp v2cp;
	struct ikev2_cp_attribute v2cp_attribute;
	struct ikev2_skf v2skf;
};

struct suggested_group {
	uint16_t /*oakley_group_t*/ sg_group;
};

extern struct_desc suggested_group_desc;

struct ikev2_redirect_part {
	u_int8_t gw_identity_type;
	u_int8_t gw_identity_len;
};
extern struct_desc ikev2_redirect_desc;

struct ikev2_notify_ipcomp_data {
	u_int16_t ikev2_cpi;
	u_int8_t ikev2_notify_ipcomp_trans;
};
extern struct_desc ikev2notify_ipcomp_data_desc;

struct ikev2_ticket_lifetime {
    uint32_t sr_lifetime;
};
extern struct_desc ikev2_ticket_lifetime_desc;

extern struct_desc sec_ctx_desc;

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
