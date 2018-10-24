/* parsing packets: formats and tools
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015,2018 Andrew Cagney
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <netinet/in.h>
#include <string.h>

#include <libreswan.h>

#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "impair.h"

#include "packet.h"

const pb_stream empty_pbs;

/* ISAKMP Header: for all messages
 * layout from RFC 2408 "ISAKMP" section 3.1
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
 */

static field_desc isa_fields[] = {
	{ ft_raw, COOKIE_SIZE, "initiator cookie", NULL },
	{ ft_raw, COOKIE_SIZE, "responder cookie", NULL },
	{ ft_mnpc, 8 / BITS_PER_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_loose_enum, 8 / BITS_PER_BYTE, "ISAKMP version", &version_names },
	{ ft_enum, 8 / BITS_PER_BYTE, "exchange type", &exchange_names_ikev1orv2 },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", isakmp_flag_names },
	{ ft_nat, 32 / BITS_PER_BYTE, "Message ID", NULL },
	{ ft_len, 32 / BITS_PER_BYTE, "length", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_hdr_desc = {
	.name = "ISAKMP Message",
	.fields = isa_fields,
	.size = sizeof(struct isakmp_hdr),
	.pt = ISAKMP_NEXT_NONE,
};

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

static field_desc isag_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_end, 0, NULL, NULL }
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

/* Oakley Attributes */
static field_desc isaat_fields_oakley[] = {
	{ ft_af_enum, 16 / BITS_PER_BYTE, "af+type", &oakley_attr_names },
	{ ft_lv, 16 / BITS_PER_BYTE, "length/value", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_oakley_attribute_desc = {
	.name = "ISAKMP Oakley attribute",
	.fields = isaat_fields_oakley,
	.size = sizeof(struct isakmp_attribute),
};

/* IPsec DOI Attributes */
static field_desc isaat_fields_ipsec[] = {
	{ ft_af_enum, 16 / BITS_PER_BYTE, "af+type", &ipsec_attr_names },
	{ ft_lv, 16 / BITS_PER_BYTE, "length/value", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_ipsec_attribute_desc = {
	.name = "ISAKMP IPsec DOI attribute",
	.fields = isaat_fields_ipsec,
	.size = sizeof(struct isakmp_attribute),
};

/* XAUTH Attributes */
static field_desc isaat_fields_xauth[] = {
	{ ft_af_loose_enum, 16 / BITS_PER_BYTE, "ModeCfg attr type", &modecfg_attr_names },
	{ ft_lv, 16 / BITS_PER_BYTE, "length/value", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_xauth_attribute_desc = {
	.name = "ISAKMP ModeCfg attribute",
	.fields = isaat_fields_xauth,
	.size = sizeof(struct isakmp_attribute),
};

/* ISAKMP Security Association Payload
 * layout from RFC 2408 "ISAKMP" section 3.4
 *
 * A variable length Situation followed by 0 or more Proposal payloads
 * follow.
 *
 * The "Next Payload [...] field MUST NOT contain the values for the
 * Proposal or Transform payloads as they are considered part of the
 * security association negotiation".  Hence .csst is set.
 *
 * Previous next payload: ISAKMP_NEXT_SA
 *
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
static field_desc isasa_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 32 / BITS_PER_BYTE, "DOI", &doi_names },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_sa_desc = {
	.name = "ISAKMP Security Association Payload",
	.fields = isasa_fields,
	.size = sizeof(struct isakmp_sa),
	.pt = ISAKMP_NEXT_SA,
	.nsst = ISAKMP_NEXT_P,
};

static field_desc ipsec_sit_field[] = {
	{ ft_set, 32 / BITS_PER_BYTE, "IPsec DOI SIT", &sit_bit_names },
	{ ft_end, 0, NULL, NULL }
};

struct_desc ipsec_sit_desc = {
	.name = "IPsec DOI SIT",
	.fields = ipsec_sit_field,
	.size = sizeof(uint32_t),
};

/* ISAKMP Proposal Payload
 * layout from RFC 2408 "ISAKMP" section 3.5
 *
 * A variable length SPI and then Transform Payloads follow.
 *
 * XXX:
 *
 * The Next Payload field below is something of a misnomer.  It
 * doesn't play any part in the Next Payload Chain.  Instead it just
 * acts as a flag where 0 indicate if it is the last payload within
 * the SA.
 *
 * In IKEv2, this payload/field has been replaced by a sub-structure and
 * "Last Substruct[ure]" field (and then makes the point that it is
 * entirely redundant).
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Proposal #   !  Protocol-Id  !    SPI Size   !# of Transforms!
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                        SPI (variable)                         !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static field_desc isap_fields[] = {
	{ ft_lss, 8 / BITS_PER_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_nat, 8 / BITS_PER_BYTE, "proposal number", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "protocol ID", &ikev1_protocol_names },
	{ ft_nat, 8 / BITS_PER_BYTE, "SPI size", NULL },
	{ ft_nat, 8 / BITS_PER_BYTE, "number of transforms", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_proposal_desc = {
	.name = "ISAKMP Proposal Payload",
	.fields = isap_fields,
	.size = sizeof(struct isakmp_proposal),
	.nsst = ISAKMP_NEXT_T,
};

/* ISAKMP Transform Payload
 * layout from RFC 2408 "ISAKMP" section 3.6
 *
 * Variable length SA Attributes follow.
 *
 * XXX:
 *
 * The Next Payload field below is something of a misnomer.  It
 * doesn't play any part in the Next Payload Chain.  Instead it just
 * acts as a flag where zero indicates that it is last payload within
 * the proposal.
 *
 * In IKEv2, this payload/field has been replaced by a sub-structure and
 * "Last Substruct[ure]" field (and then makes the point that it is
 * entirely redundant).
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

/* PROTO_ISAKMP */
static field_desc isat_fields_isakmp[] = {
	{ ft_lss, 8 / BITS_PER_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_nat, 8 / BITS_PER_BYTE, "ISAKMP transform number", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "ISAKMP transform ID", &isakmp_transformid_names },
	{ ft_zig, 16 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_isakmp_transform_desc = {
	.name = "ISAKMP Transform Payload (ISAKMP)",
	.fields = isat_fields_isakmp,
	.size = sizeof(struct isakmp_transform),
};

/* PROTO_IPSEC_AH */
static field_desc isat_fields_ah[] = {
	{ ft_lss, 8 / BITS_PER_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_nat, 8 / BITS_PER_BYTE, "AH transform number", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "AH transform ID", &ah_transformid_names },
	{ ft_zig, 16 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_ah_transform_desc = {
	.name = "ISAKMP Transform Payload (AH)",
	.fields = isat_fields_ah,
	.size = sizeof(struct isakmp_transform),
};

/* PROTO_IPSEC_ESP */
static field_desc isat_fields_esp[] = {
	{ ft_lss, 8 / BITS_PER_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_nat, 8 / BITS_PER_BYTE, "ESP transform number", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "ESP transform ID", &esp_transformid_names },
	{ ft_zig, 16 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_esp_transform_desc = {
	.name = "ISAKMP Transform Payload (ESP)",
	.fields = isat_fields_esp,
	.size = sizeof(struct isakmp_transform),
};

/* PROTO_IPCOMP */
static field_desc isat_fields_ipcomp[] = {
	{ ft_lss, 8 / BITS_PER_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_nat, 8 / BITS_PER_BYTE, "IPCOMP transform number", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "IPCOMP transform ID", &ipcomp_transformid_names },
	{ ft_zig, 16 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_ipcomp_transform_desc = {
	.name = "ISAKMP Transform Payload (COMP)",
	.fields = isat_fields_ipcomp,
	.size = sizeof(struct isakmp_transform),
};

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
struct_desc isakmp_keyex_desc =	{
	.name = "ISAKMP Key Exchange Payload",
	.fields = isag_fields,
	.size = sizeof(struct isakmp_generic),
	.pt = ISAKMP_NEXT_KE,
};

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
static field_desc isaid_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "ID type", &ike_idtype_names }, /* ??? depends on DOI? */
	{ ft_nat, 8 / BITS_PER_BYTE, "DOI specific A", NULL },          /* ??? depends on DOI? */
	{ ft_nat, 16 / BITS_PER_BYTE, "DOI specific B", NULL },         /* ??? depends on DOI? */
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_identification_desc = {
	.name = "ISAKMP Identification Payload",
	.fields = isaid_fields,
	.size = sizeof(struct isakmp_id),
	.pt = ISAKMP_NEXT_ID,
};

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
static field_desc isaiid_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "ID type", &ike_idtype_names },
	{ ft_nat, 8 / BITS_PER_BYTE, "Protocol ID", NULL }, /* ??? UDP/TCP or 0? */
	{ ft_nat, 16 / BITS_PER_BYTE, "port", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_ipsec_identification_desc = {
	.name = "ISAKMP Identification Payload (IPsec DOI)",
	.fields = isaiid_fields,
	.size = sizeof(struct isakmp_ipsec_id),
	.pt = ISAKMP_NEXT_ID,
};

/* ISAKMP Certificate Payload: oddball fixed field beyond the generic ones.
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
static field_desc isacert_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "cert encoding", &ike_cert_type_names },
	{ ft_end, 0, NULL, NULL }
};

/* Note: the size field of isakmp_ipsec_certificate_desc cannot be
 * sizeof(struct isakmp_cert) because that will rounded up for padding.
 */
struct_desc isakmp_ipsec_certificate_desc = {
	.name = "ISAKMP Certificate Payload",
	.fields = isacert_fields,
	.size = ISAKMP_CERT_SIZE,
	.pt = ISAKMP_NEXT_CERT,
};

/* ISAKMP Certificate Request Payload: oddball field beyond the generic ones.
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
static field_desc isacr_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "cert type", &ike_cert_type_names },
	{ ft_end, 0, NULL, NULL }
};

/* Note: the size field of isakmp_ipsec_cert_req_desc cannot be
 * sizeof(struct isakmp_cr) because that will rounded up for padding.
 */
struct_desc isakmp_ipsec_cert_req_desc = {
	.name = "ISAKMP Certificate RequestPayload",
	.fields = isacr_fields,
	.size = ISAKMP_CR_SIZE,
	.pt = ISAKMP_NEXT_CR,
};

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
struct_desc isakmp_hash_desc = {
	.name = "ISAKMP Hash Payload",
	.fields = isag_fields,
	.size = sizeof(struct isakmp_generic),
	.pt = ISAKMP_NEXT_HASH,
};

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
struct_desc isakmp_signature_desc = {
	.name = "ISAKMP Signature Payload",
	.fields = isag_fields,
	.size = sizeof(struct isakmp_generic),
	.pt = ISAKMP_NEXT_SIG,
};

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
struct_desc isakmp_nonce_desc =	{
	.name = "ISAKMP Nonce Payload",
	.fields = isag_fields,
	.size = sizeof(struct isakmp_generic),
	.pt = ISAKMP_NEXT_NONCE,
};

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
 * !  Protocol-ID  !   SPI Size    !      Notify Message Type      !
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
static field_desc isan_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 32 / BITS_PER_BYTE, "DOI", &doi_names },
	{ ft_nat, 8 / BITS_PER_BYTE, "protocol ID", NULL }, /* ??? really enum: ISAKMP, IPSEC, ESP, ... */
	{ ft_nat, 8 / BITS_PER_BYTE, "SPI size", NULL },
	{ ft_enum, 16 / BITS_PER_BYTE, "Notify Message Type", &ikev1_notify_names },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_notification_desc = {
	.name = "ISAKMP Notification Payload",
	.fields = isan_fields,
	.size = sizeof(struct isakmp_notification),
	.pt = ISAKMP_NEXT_N,
};

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
 * !  Protocol-Id  !   SPI Size    !           # of SPIs           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~               Security Parameter Index(es) (SPI)              ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static field_desc isad_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 32 / BITS_PER_BYTE, "DOI", &doi_names },
	{ ft_nat, 8 / BITS_PER_BYTE, "protocol ID", NULL }, /* ??? really enum: ISAKMP, IPSEC */
	{ ft_nat, 8 / BITS_PER_BYTE, "SPI size", NULL },
	{ ft_nat, 16 / BITS_PER_BYTE, "number of SPIs", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_delete_desc = {
	.name = "ISAKMP Delete Payload",
	.fields = isad_fields,
	.size = sizeof(struct isakmp_delete),
	.pt = ISAKMP_NEXT_D,
};

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
struct_desc isakmp_vendor_id_desc = {
	.name = "ISAKMP Vendor ID Payload",
	.fields = isag_fields,
	.size = sizeof(struct isakmp_generic),
	.pt = ISAKMP_NEXT_VID,
};

/* MODECFG */
/*
 * From draft-dukes-ike-mode-cfg
 * 3.2. Attribute Payload
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   ! Next Payload  !   RESERVED    !         Payload Length        !
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   !     Type      !   RESERVED    !           Identifier          !
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   !                                                               !
 *   ~                           Attributes                          ~
 *   !                                                               !
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static field_desc isaattr_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "Attr Msg Type", &attr_msg_type_names },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_nat, 16 / BITS_PER_BYTE, "Identifier", NULL },
	{ ft_end, 0, NULL, NULL }
};

/* MODECFG */
/* From draft-dukes-ike-mode-cfg
 * 3.2. Attribute Payload
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   ! Next Payload  !   RESERVED    !         Payload Length        !
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   !     Type      !   RESERVED    !           Identifier          !
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   !                                                               !
 *   !                                                               !
 *   ~                           Attributes                          ~
 *   !                                                               !
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct_desc isakmp_attr_desc = {
	.name = "ISAKMP Mode Attribute",
	.fields = isaattr_fields,
	.size = sizeof(struct isakmp_mode_attr),
	.pt = ISAKMP_NEXT_MCFG_ATTR,
};

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
struct_desc isakmp_nat_d = {
	.name = "ISAKMP NAT-D Payload",
	.fields = isag_fields,
	.size = sizeof(struct isakmp_generic),
	.pt = ISAKMP_NEXT_NATD_RFC,
};

struct_desc isakmp_nat_d_drafts = {
	.name = "ISAKMP NAT-D Payload (draft)",
	.fields = isag_fields,
	.size = sizeof(struct isakmp_generic),
	.pt = ISAKMP_NEXT_NATD_DRAFTS,
};

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
static field_desc isanat_oa_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "ID type", &ike_idtype_names },
	{ ft_zig, 24 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_nat_oa = {
	.name = "ISAKMP NAT-OA Payload",
	.fields = isanat_oa_fields,
	.size = sizeof(struct isakmp_nat_oa),
	.pt = ISAKMP_NEXT_NATOA_RFC,
};

struct_desc isakmp_nat_oa_drafts = {
	.name = "ISAKMP NAT-OA Payload (draft)",
	.fields = isanat_oa_fields,
	.size = sizeof(struct isakmp_nat_oa),
	.pt = ISAKMP_NEXT_NATOA_DRAFTS,
};

/* Generic payload: an unknown input payload */

struct_desc isakmp_ignore_desc = {
	.name = "ignored ISAKMP Generic Payload",
	.fields = isag_fields,
	.size = sizeof(struct isakmp_generic),
	.pt = ISAKMP_NEXT_NONE,
};

/* ISAKMP IKE Fragmentation Payload
 * Cisco proprietary, undocumented
 *
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !          Fragment ID          !  Frag Number  !     Flags     !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                         Fragment Data                         ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static field_desc isafrag_fields[] = {
	{ ft_zig, 8 / BITS_PER_BYTE, "next payload type", NULL },
	{ ft_zig, 8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_nat, 16 / BITS_PER_BYTE, "fragment id", NULL },
	{ ft_nat, 8 / BITS_PER_BYTE, "fragment number", NULL },
	{ ft_nat, 8 / BITS_PER_BYTE, "flags", NULL }, /* 0x1 means last fragment */
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_ikefrag_desc = {
	.name = "ISAKMP IKE Fragment Payload",
	.fields = isafrag_fields,
	.size = sizeof(struct isakmp_ikefrag),
	.pt = ISAKMP_NEXT_IKE_FRAGMENTATION,
};

/*
 * GENERIC IKEv2 header.
 * Note differs from IKEv1, in that it has flags with one bit a critical bit
 */
static field_desc ikev2generic_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_end,  0, NULL, NULL }
};
/* only for reading an unknown-to-us payload */
struct_desc ikev2_generic_desc = {
	.name = "IKEv2 Generic Payload",
	.fields = ikev2generic_fields,
	.size = sizeof(struct ikev2_generic),
	.pt = ISAKMP_NEXT_v2NONE,	/* could be any unknown */
};
/* for IMPAIR_ADD_UNKNOWN_PAYLOAD_TO_* */
struct_desc ikev2_unknown_payload_desc = {
	.name = "IKEv2 Unknown Payload",
	.fields = ikev2generic_fields,
	.size = sizeof(struct ikev2_generic),
	.pt = ISAKMP_NEXT_v2UNKNOWN,
};

/*
 * IKEv2 - Security Association Payload
 *
 * layout from RFC 4306 - section 3.3.
 * A variable number of Proposal Substructures follow.
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                          <Proposals>                          ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
struct_desc ikev2_sa_desc = {
	.name = "IKEv2 Security Association Payload",
	.fields = ikev2generic_fields,
	.size = sizeof(struct ikev2_sa),
	.pt = ISAKMP_NEXT_v2SA,
	.nsst = v2_PROPOSAL_NON_LAST,
};

/* IKEv2 - Proposal sub-structure
 *
 * 3.3.1.  Proposal Substructure
 *
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! 0 (last) or 2 !   RESERVED    !         Proposal Length       !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Proposal #    !  Protocol ID  !    SPI Size   !# of Transforms!
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ~                        SPI (variable)                         ~
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                        <Transforms>                           ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *             Figure 7:  Proposal Substructure
 */
static field_desc ikev2prop_fields[] = {
	{ ft_lss, 8 / BITS_PER_BYTE, "last proposal", &ikev2_last_proposal_desc },
	{ ft_zig,  8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_nat,  8 / BITS_PER_BYTE, "prop #", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "proto ID", &ikev2_sec_proto_id_names },
	{ ft_nat,  8 / BITS_PER_BYTE, "spi size", NULL },
	{ ft_nat,  8 / BITS_PER_BYTE, "# transforms", NULL },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_prop_desc = {
	.name = "IKEv2 Proposal Substructure Payload",
	.fields = ikev2prop_fields,
	.size = sizeof(struct ikev2_prop),
	.nsst = v2_TRANSFORM_NON_LAST,
};

/*
 * 3.3.2.  Transform Substructure
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! 0 (last) or 3 !   RESERVED    !        Transform Length       !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !Transform Type !   RESERVED    !          Transform ID         !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                      Transform Attributes                     ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static field_desc ikev2trans_fields[] = {
	{ ft_lss, 8 / BITS_PER_BYTE, "last transform", &ikev2_last_transform_desc },
	{ ft_zig,  8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "IKEv2 transform type", &ikev2_trans_type_names },
	{ ft_zig,  8 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_loose_enum_enum, 16 / BITS_PER_BYTE, "IKEv2 transform ID", &v2_transform_ID_enums }, /* select enum based on transform type */
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_trans_desc = {
	.name = "IKEv2 Transform Substructure Payload",
	.fields = ikev2trans_fields,
	.size = sizeof(struct ikev2_trans),
};

/*
 * 3.3.5.   [Transform] Attribute substructure
 *
 *                          1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     !A!       Attribute Type        !    AF=0  Attribute Length     !
 *     !F!                             !    AF=1  Attribute Value      !
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     !                   AF=0  Attribute Value                       !
 *     !                   AF=1  Not Transmitted                       !
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static field_desc ikev2_trans_attr_fields[] = {
	{ ft_af_enum, 16 / BITS_PER_BYTE, "af+type", &ikev2_trans_attr_descs },
	{ ft_lv,      16 / BITS_PER_BYTE, "length/value", NULL },
	{ ft_end,     0, NULL, NULL }
};

struct_desc ikev2_trans_attr_desc = {
	.name = "IKEv2 Attribute Substructure Payload",
	.fields = ikev2_trans_attr_fields,
	.size = sizeof(struct ikev2_trans_attr),
};

/* 3.4.  Key Exchange Payload
 *
 * The Key Exchange Payload, denoted KE in this memo, is used to
 * exchange Diffie-Hellman public numbers as part of a Diffie-Hellman
 * key exchange.  The Key Exchange Payload consists of the IKE generic
 * payload header followed by the Diffie-Hellman public value itself.
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !          DH Group #           !           RESERVED            !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                       Key Exchange Data                       ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *              Figure 10:  Key Exchange Payload Format
 *
 */
static field_desc ikev2ke_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 16 / BITS_PER_BYTE, "DH group", &oakley_group_names },
	{ ft_zig, 16 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_end,  0, NULL, NULL },
};

struct_desc ikev2_ke_desc = {
	.name = "IKEv2 Key Exchange Payload",
	.fields = ikev2ke_fields,
	.size = sizeof(struct ikev2_ke),
	.pt = ISAKMP_NEXT_v2KE,
};

/*
 * 3.5.  Identification Payloads
 *
 * The Identification Payloads, denoted IDi and IDr in this memo, allow
 * peers to assert an identity to one another.  This identity may be
 * used for policy lookup, but does not necessarily have to match
 * anything in the CERT payload; both fields may be used by an
 * implementation to perform access control decisions.
 *
 * NOTE: In IKEv1, two ID payloads were used in each direction to hold
 * Traffic Selector (TS) information for data passing over the SA.  In
 * IKEv2, this information is carried in TS payloads (see section 3.13).
 *
 * The Identification Payload consists of the IKE generic payload header
 * followed by identification fields as follows:
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !   ID Type     !                 RESERVED                      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                   Identification Data                         ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *             Figure 11:  Identification Payload Format
 */

static field_desc ikev2id_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "ID type", &ikev2_idtype_names },
	{ ft_zig, 24 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_end,  0, NULL, NULL },
};

struct_desc ikev2_id_i_desc = {
	.name ="IKEv2 Identification - Initiator - Payload",
	.fields = ikev2id_fields,
	.size = sizeof(struct ikev2_id),
	.pt = ISAKMP_NEXT_v2IDi,
};

struct_desc ikev2_id_r_desc = {
	.name ="IKEv2 Identification - Responder - Payload",
	.fields = ikev2id_fields,
	.size = sizeof(struct ikev2_id),
	.pt = ISAKMP_NEXT_v2IDr,
};

/*
 * IKEv2 - draft-ietf-ipsecme-qr-ikev2-01 (no ascii art provided in RFC)
 * PPK_ID types
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +---------------+-----------------------------------------------+
 *    | PPK Type      |                                               |
 *    +---------------+         PPK Data                              +
 *    ~                                                               ~
 *    +---------------+-----------------------------------------------+
 *
 * PPK_ID Type               Value
 * -----------               -----
 * Reserved                  0
 * PPK_ID_OPAQUE             1
 * PPK_ID_FIXED              2
 * Unassigned                3-127
 * Reserved for private use  128-255
 */
static field_desc ikev2_ppk_id_fields[] = {
	{ ft_enum, 8 / BITS_PER_BYTE, "PPK ID type", &ikev2_ppk_id_type_names },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_ppk_id_desc = {
	.name = "IKEv2 PPK ID Payload",
	.fields = ikev2_ppk_id_fields,
	.size = sizeof(struct ikev2_ppk_id),
};


static field_desc ikev2cp_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "ikev2_cfg_type", &ikev2_cp_type_names },
	{ ft_zig, 24 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_cp_desc = {
	.name = "IKEv2 Configuration Payload",
	.fields = ikev2cp_fields,
	.size = sizeof(struct ikev2_cp),
	.pt = ISAKMP_NEXT_v2CP,
};

static field_desc ikev2_cp_attrbute_fields[] = {
	{ ft_enum, 16 / BITS_PER_BYTE, "Attribute Type", &ikev2_cp_attribute_type_names },
	{ ft_lv, 16 / BITS_PER_BYTE, "length/value", NULL },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_cp_attribute_desc = {
	.name = "IKEv2 Configuration Payload Attribute",
	.fields = ikev2_cp_attrbute_fields,
	.size = sizeof(struct ikev2_cp_attribute),
};

/* section 3.6
 * The Certificate Payload is defined as follows:
 *
 *                          1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     ! Cert Encoding !                                               !
 *     +-+-+-+-+-+-+-+-+                                               !
 *     ~                       Certificate Data                        ~
 *     !                                                               !
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static field_desc ikev2_cert_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "ikev2 cert encoding",
	  &ikev2_cert_type_names },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_certificate_desc = {
	.name = "IKEv2 Certificate Payload",
	.fields = ikev2_cert_fields,
	.size = IKEV2_CERT_SIZE,
	.pt = ISAKMP_NEXT_v2CERT,
};

/* section 3.7
 *
 * The Certificate Request Payload is defined as follows:
 *
 *                          1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     ! Cert Encoding !                                               !
 *     +-+-+-+-+-+-+-+-+                                               !
 *     ~                    Certification Authority                    ~
 *     !                                                               !
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

static field_desc ikev2_cert_req_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "ikev2 cert encoding",
	  &ikev2_cert_type_names },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_certificate_req_desc = {
	.name = "IKEv2 Certificate Request Payload",
	.fields = ikev2_cert_req_fields,
	.size = IKEV2_CERT_SIZE,
	.pt = ISAKMP_NEXT_v2CERTREQ,
};

/*
 * 3.8.  Authentication Payload
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Auth Method   !                RESERVED                       !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                      Authentication Data                      ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *               Figure 14:  Authentication Payload Format
 *
 */
static field_desc ikev2a_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "auth method", &ikev2_auth_names },
	{ ft_zig, 24 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_a_desc = {
	.name = "IKEv2 Authentication Payload",
	.fields = ikev2a_fields,
	.size = sizeof(struct ikev2_a),
	.pt = ISAKMP_NEXT_v2AUTH,
};

/*
 * 3.9.  Nonce Payload
 *
 * The Nonce Payload, denoted Ni and Nr in this memo for the initiator's
 * and responder's nonce respectively, contains random data used to
 * guarantee liveness during an exchange and protect against replay
 * attacks.
 *
 * The Nonce Payload is defined as follows:
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                            Nonce Data                         ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *                 Figure 15:  Nonce Payload Format
 */
struct_desc ikev2_nonce_desc = {
	.name = "IKEv2 Nonce Payload",
	.fields = ikev2generic_fields,
	.size = sizeof(struct ikev2_generic),
	.pt = ISAKMP_NEXT_v2Ni, /*==ISAKMP_NEXT_v2Nr*/
};

/*    3.10 Notify Payload
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !  Protocol ID  !   SPI Size    !      Notify Message Type      !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                Security Parameter Index (SPI)                 ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                       Notification Data                       ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static field_desc ikev2_notify_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "Protocol ID", &ikev2_protocol_names },
	/* names used are v1 names may be we should use 4306 3.3.1 names */
	{ ft_nat,  8 / BITS_PER_BYTE, "SPI size", NULL },
	{ ft_loose_enum, 16 / BITS_PER_BYTE, "Notify Message Type",
	  &ikev2_notify_names },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_notify_desc = {
	.name = "IKEv2 Notify Payload",
	.fields = ikev2_notify_fields,
	.size = sizeof(struct ikev2_notify),
	.pt = ISAKMP_NEXT_v2N,
};

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

static field_desc ikev2_delete_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_PER_BYTE, "protocol ID", &ikev2_del_protocol_names },
	{ ft_nat, 8 / BITS_PER_BYTE, "SPI size", NULL },
	{ ft_nat, 16 / BITS_PER_BYTE, "number of SPIs", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc ikev2_delete_desc = {
	.name = "IKEv2 Delete Payload",
	.fields = ikev2_delete_fields,
	.size = sizeof(struct ikev2_delete),
	.pt = ISAKMP_NEXT_v2D,
};

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
struct_desc ikev2_vendor_id_desc = {
	.name = "IKEv2 Vendor ID Payload",
	.fields = ikev2generic_fields,
	.size = sizeof(struct ikev2_generic),
	.pt = ISAKMP_NEXT_v2V,
};

/*
 * 3.13.  Traffic Selector Payload
 *
 *
 * The Traffic Selector Payload, denoted TS in this memo, allows peers
 * to identify packet flows for processing by IPsec security services.
 * The Traffic Selector Payload consists of the IKE generic payload
 * header followed by individual traffic selectors as follows:
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Number of TSs !                 RESERVED                      !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                       <Traffic Selectors>                     ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static field_desc ikev2ts_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_nat,  8 / BITS_PER_BYTE, "number of TS", NULL },
	{ ft_zig, 24 / BITS_PER_BYTE, "reserved", NULL },
	{ ft_end,  0, NULL, NULL }
};
struct_desc ikev2_ts_i_desc = {
	.name = "IKEv2 Traffic Selector - Initiator - Payload",
	.fields = ikev2ts_fields,
	.size = sizeof(struct ikev2_ts),
	.pt = ISAKMP_NEXT_v2TSi,
};
struct_desc ikev2_ts_r_desc = {
	.name = "IKEv2 Traffic Selector - Responder - Payload",
	.fields = ikev2ts_fields,
	.size = sizeof(struct ikev2_ts),
	.pt = ISAKMP_NEXT_v2TSr,
};

/*
 * 3.13.1.  Traffic Selector
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !   TS Type     !IP Protocol ID*|       Selector Length         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |           Start Port*         |           End Port*           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                         Starting Address*                     ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                         Ending Address*                       ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *                Figure 20: Traffic Selector
 */
static field_desc ikev2ts1_fields[] = {
	{ ft_enum, 8 / BITS_PER_BYTE, "TS type", &ikev2_ts_type_names },
	{ ft_nat,  8 / BITS_PER_BYTE, "IP Protocol ID", NULL },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_nat, 16 / BITS_PER_BYTE, "start port", NULL },
	{ ft_nat, 16 / BITS_PER_BYTE, "end port", NULL },
	{ ft_end,  0, NULL, NULL }
};
struct_desc ikev2_ts1_desc = {
	.name = "IKEv2 Traffic Selector",
	.fields = ikev2ts1_fields,
	.size = sizeof(struct ikev2_ts1),
};

/*
 * 3.14.  Encrypted Payload
 *                         1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ! Next Payload  !C!  RESERVED   !         Payload Length        !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                     Initialization Vector                     !
 *    !         (length is block size for encryption algorithm)       !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ~                    Encrypted IKE Payloads                     ~
 *    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !               !             Padding (0-255 octets)            !
 *    +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
 *    !                                               !  Pad Length   !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ~                    Integrity Checksum Data                    ~
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *             Figure 21:  Encrypted Payload Format
 */
struct_desc ikev2_sk_desc = {
	.name = "IKEv2 Encryption Payload",
	.fields = ikev2generic_fields,
	.size = sizeof(struct ikev2_generic),
	.pt = ISAKMP_NEXT_v2SK,
};

/*
 * RFC 7383 2.5.  Fragmenting Message
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Next Payload  |C|  RESERVED   |         Payload Length        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |        Fragment Number        |        Total Fragments        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                     Initialization Vector                     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ~                      Encrypted content                        ~
 *    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |               |             Padding (0-255 octets)            |
 *    +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
 *    |                                               |  Pad Length   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    ~                    Integrity Checksum Data                    ~
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *	Next Payload (1 octet) - in the very first fragment (with Fragment
 *	Number equal to 1), this field MUST be set to the payload type of
 *	the first inner payload (the same as for the Encrypted payload).
 *	In the rest of the Fragment messages (with Fragment Number greater
 *	than 1), this field MUST be set to zero.
 *
 * XXX: Even though the SKF's Next Payload field isn't really part of
 * the Next Payload chain (it is under the fragmentation code's
 * control so should be an ft_enum) it needs to be ft_pnpc so that the
 * code triggering an update of the message's next payload chain
 * executed.
 *
 *                         Encrypted Fragment Payload
 */
static field_desc ikev2skf_fields[] = {
	{ ft_pnpc, 8 / BITS_PER_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_set, 8 / BITS_PER_BYTE, "flags", critical_names },
	{ ft_len, 16 / BITS_PER_BYTE, "length", NULL },
	{ ft_nat, 16 / BITS_PER_BYTE, "fragment number", NULL },
	{ ft_nat, 16 / BITS_PER_BYTE, "total fragments", NULL },
	{ ft_end,  0, NULL, NULL }
};
struct_desc ikev2_skf_desc = {
	.name = "IKEv2 Encrypted Fragment",
	.fields = ikev2skf_fields,
	.size = sizeof(struct ikev2_skf),
	.pt = ISAKMP_NEXT_v2SKF,
};

static field_desc suggested_group_fields[] = {
	{ ft_enum, 16 / BITS_PER_BYTE, "suggested DH Group", &oakley_group_names },
	{ ft_end,  0, NULL, NULL }
};

struct_desc suggested_group_desc = {
	.name = "Suggested Group",
	.fields = suggested_group_fields,
	.size = sizeof(struct suggested_group),
	.pt = ISAKMP_NEXT_v2NONE,
};

#ifdef HAVE_LABELED_IPSEC

/*
 * Undocumented Security Context for Labeled IPsec
 *
 * See struct sec_ctx in state.h
 */
#include "labeled_ipsec.h"	/* for struct sec_ctx */

static field_desc sec_ctx_fields[] = {
	{ ft_nat,  8 / BITS_PER_BYTE, "DOI", NULL },
	{ ft_nat,  8 / BITS_PER_BYTE, "Alg", NULL },
	{ ft_nat, 16 / BITS_PER_BYTE, "length", NULL },	/* not ft_len */
	{ ft_end,  0, NULL, NULL }
};

struct_desc sec_ctx_desc = {
	.name = "Label Security Context",
	.fields = sec_ctx_fields,
	.size = sizeof(struct sec_ctx),
};

#endif

/*
 * descriptor for each V1 payload type
 *
 * There is a slight problem in that some payloads differ, depending
 * on the mode.  Since this is table only used for top-level payloads,
 * Proposal and Transform payloads need not be handled.  That leaves
 * only Identification payloads as a problem.  We make all these
 * entries NULL
 */
struct_desc *v1_payload_desc(unsigned p)
{
	static struct_desc *const v1_payload_descs[] = {
		NULL,                           /* 0 ISAKMP_NEXT_NONE (No other payload following) */
		&isakmp_sa_desc,                /* 1 ISAKMP_NEXT_SA (Security Association) */
		NULL,                           /* 2 ISAKMP_NEXT_P (Proposal) */
		NULL,                           /* 3 ISAKMP_NEXT_T (Transform) */
		&isakmp_keyex_desc,             /* 4 ISAKMP_NEXT_KE (Key Exchange) */
		NULL,                           /* 5 ISAKMP_NEXT_ID (Identification) */
		&isakmp_ipsec_certificate_desc, /* 6 ISAKMP_NEXT_CERT (Certificate) */
		&isakmp_ipsec_cert_req_desc,    /* 7 ISAKMP_NEXT_CR (Certificate Request) */
		&isakmp_hash_desc,              /* 8 ISAKMP_NEXT_HASH (Hash) */
		&isakmp_signature_desc,         /* 9 ISAKMP_NEXT_SIG (Signature) */
		&isakmp_nonce_desc,             /* 10 ISAKMP_NEXT_NONCE (Nonce) */
		&isakmp_notification_desc,      /* 11 ISAKMP_NEXT_N (Notification) */
		&isakmp_delete_desc,            /* 12 ISAKMP_NEXT_D (Delete) */
		&isakmp_vendor_id_desc,         /* 13 ISAKMP_NEXT_VID (Vendor ID) */
		&isakmp_attr_desc,              /* 14 ISAKMP_NEXT_MCFG_ATTR (ModeCfg)  */
		NULL,                           /* 15 */
		NULL,                           /* 16 */
		NULL,                           /* 17 */
		NULL,                           /* 18 */
		NULL,                           /* 19 */
		&isakmp_nat_d,                  /* 20=130 ISAKMP_NEXT_NATD_RFC=ISAKMP_NEXT_NATD_DRAFTS (NAT-D) */
		&isakmp_nat_oa,                 /* 21=131 ISAKMP_NEXT_NATOA_RFC=ISAKMP_NEXT_NATOA_DRAFTS (NAT-OA) */
	};
	return p < elemsof(v1_payload_descs) ? v1_payload_descs[p] : NULL;
}

struct_desc *v2_payload_desc(unsigned p)
{
	static struct_desc *const v2_payload_descs[] = {
		&ikev2_sa_desc,                 /* 33 ISAKMP_NEXT_v2SA */
		&ikev2_ke_desc,                 /* 34 ISAKMP_NEXT_v2KE */
		&ikev2_id_i_desc,		/* 35 ISAKMP_NEXT_v2IDi */
		&ikev2_id_r_desc,		/* 36 ISAKMP_NEXT_v2IDr */
		&ikev2_certificate_desc,        /* 37 ISAKMP_NEXT_v2CERT */
		&ikev2_certificate_req_desc,    /* 38 ISAKMP_NEXT_v2CERTREQ */
		&ikev2_a_desc,                  /* 39 ISAKMP_NEXT_v2AUTH */
		&ikev2_nonce_desc,              /* 40 ISAKMP_NEXT_v2Ni / ISAKMP_NEXT_v2Nr */
		&ikev2_notify_desc,             /* 41 ISAKMP_NEXT_v2N */
		&ikev2_delete_desc,             /* 42 ISAKMP_NEXT_v2D */
		&ikev2_vendor_id_desc,          /* 43 ISAKMP_NEXT_v2V */
		&ikev2_ts_i_desc,		/* 44 ISAKMP_NEXT_v2TSi */
		&ikev2_ts_r_desc,		/* 45 ISAKMP_NEXT_v2TSr */
		&ikev2_sk_desc,                 /* 46 ISAKMP_NEXT_v2SK */
		&ikev2_cp_desc,			/* 47 ISAKMP_NEXT_v2CP */
		NULL,				/* 48 */
		NULL,				/* 49 */
		NULL,				/* 50 */
		NULL,				/* 51 */
		NULL,				/* 52 */
		&ikev2_skf_desc,                /* 53 ISAKMP_NEXT_v2SKF */
	};
	if (p < ISAKMP_v2PAYLOAD_TYPE_BASE) {
		return NULL;
	}
	unsigned q = p - ISAKMP_v2PAYLOAD_TYPE_BASE;
	if (q >= elemsof(v2_payload_descs)) {
		return NULL;
	}
	return v2_payload_descs[q];
}

void init_pbs(pb_stream *pbs, uint8_t *start, size_t len, const char *name)
{
	*pbs = (pb_stream) {
		/* .container = NULL, */
		/* .desc = NULL, */
		.name = name,
		.start = start,
		.cur = start,
		.roof = start + len,
		/* .lenfld = NULL, */
		/* .lenfld_desc = NULL, */
		/* .previous_np = NULL, */
		/* .previous_npc.fp = NULL, */
		/* .previous_np_struct = NULL, */
	};
}

void init_out_pbs(pb_stream *pbs, uint8_t *start, size_t len, const char *name)
{
	init_pbs(pbs, start, len, name);
	memset(start, 0xFA, len);	/* value likely to be unpleasant */
}

pb_stream open_out_pbs(const char *name, uint8_t *buffer, size_t sizeof_buffer)
{
	pb_stream out_pbs;
	init_out_pbs(&out_pbs, buffer, sizeof_buffer, name);
	DBGF(DBG_EMITTING, "Opening output PBS %s", name);
	return out_pbs;
}

pb_stream same_chunk_as_in_pbs(chunk_t chunk, const char *name)
{
	pb_stream pbs;
	init_pbs(&pbs, chunk.ptr, chunk.len, name);
	return pbs;
}

chunk_t same_out_pbs_as_chunk(pb_stream *pbs)
{
	chunk_t chunk = {
		.ptr = pbs->start,
		.len = pbs_offset(pbs),
	};
	return chunk;
}

chunk_t clone_out_pbs_as_chunk(pb_stream *pbs, const char *name)
{
	return clone_chunk(same_out_pbs_as_chunk(pbs), name);
}

chunk_t same_in_pbs_as_chunk(pb_stream *pbs)
{
	return chunk(pbs->start, pbs_room(pbs));
}

chunk_t clone_in_pbs_as_chunk(pb_stream *pbs, const char *name)
{
	return clone_chunk(same_in_pbs_as_chunk(pbs), name);
}

chunk_t same_in_pbs_left_as_chunk(pb_stream *pbs)
{
	return chunk(pbs->cur, pbs_left(pbs));
}

chunk_t clone_in_pbs_left_as_chunk(pb_stream *pbs, const char *name)
{
	return clone_chunk(same_in_pbs_left_as_chunk(pbs), name);
}

static err_t enum_enum_checker(
	const char *struct_name,
	const field_desc *fp,
	uint32_t last_enum)
{
	enum_names *ed = enum_enum_table(fp->desc, last_enum);

	if (ed == NULL) {
		return builddiag("%s of %s has an unknown type: %" PRIu32 " (0x%" PRIx32 ")",
				 fp->name, struct_name,
				 last_enum,
				 last_enum);
	}
	return NULL;
}

/* print a host struct
 *
 * This code assumes that the network and host structure
 * members have the same alignment and size!  This requires
 * that all padding be explicit.
 */
static void DBG_print_struct(const char *label, const void *struct_ptr,
		      struct_desc *sd, bool len_meaningful)
{
	bool immediate = FALSE;
	const uint8_t *inp = struct_ptr;
	field_desc *fp;
	uint32_t last_enum = 0;

	DBG_log("%s%s:", label, sd->name);

	for (fp = sd->fields; fp->field_type != ft_end; fp++) {
		int i = fp->size;
		uint32_t n = 0;

		switch (fp->field_type) {
		case ft_zig:		/* zero (ignore violations) */
			inp += i;
			break;
		case ft_nat:            /* natural number (may be 0) */
		case ft_len:            /* length of this struct and any following crud */
		case ft_lv:             /* length/value field of attribute */
		case ft_enum:           /* value from an enumeration */
		case ft_loose_enum:     /* value from an enumeration with only some names known */
		case ft_mnpc:
		case ft_pnpc:
		case ft_lss:		/* last substructure field */
		case ft_loose_enum_enum:	/* value from an enumeration with partial name table based on previous enum */
		case ft_af_enum:        /* Attribute Format + value from an enumeration */
		case ft_af_loose_enum:  /* Attribute Format + value from an enumeration */
		case ft_set:            /* bits representing set */
			/* grab i bytes */
			switch (i) {
			case 8 / BITS_PER_BYTE:
				n = *(const uint8_t *)inp;
				break;
			case 16 / BITS_PER_BYTE:
				n = *(const uint16_t *)inp;
				break;
			case 32 / BITS_PER_BYTE:
				n = *(const uint32_t *)inp;
				break;
			default:
				bad_case(i);
			}

			/* display the result */
			switch (fp->field_type) {
			case ft_len:    /* length of this struct and any following crud */
			case ft_lv:     /* length/value field of attribute */
				if (!immediate && !len_meaningful)
					break;
			/* FALL THROUGH */
			case ft_nat: /* natural number (may be 0) */
				DBG_log("   %s: %" PRIu32 " (0x%" PRIx32 ")",
					fp->name,
					n,
					n);
				break;

			case ft_af_loose_enum:  /* Attribute Format + value from an enumeration */
			case ft_af_enum:        /* Attribute Format + value from an enumeration */
			{
				immediate = ((n & ISAKMP_ATTR_AF_MASK) ==
					     ISAKMP_ATTR_AF_TV);
				last_enum = n & ~ISAKMP_ATTR_AF_MASK;
				/*
				 * try to deal with fp->desc
				 * containing a selection of
				 * AF+<value> and <value> entries.
				 */
				const char *name = enum_name(fp->desc, last_enum);
				if (name == NULL) {
					name = enum_show(fp->desc, n);
				}
				DBG_log("   %s: %s%s (0x%" PRIx32 ")",
					fp->name,
					immediate ? "AF+" : "",
					name, n);
				break;
			}

			case ft_enum:           /* value from an enumeration */
			case ft_loose_enum:     /* value from an enumeration with only some names known */
			case ft_mnpc:
			case ft_pnpc:
			case ft_lss:
				last_enum = n;
				DBG_log("   %s: %s (0x%" PRIx32 ")",
					fp->name,
					enum_show(fp->desc, n),
					n);
				break;

			case ft_loose_enum_enum:
			{
				struct esb_buf buf;
				const char *name = enum_enum_showb(fp->desc,
								   last_enum,
								   n, &buf);
				DBG_log("   %s: %s (0x%" PRIx32 ")",
					fp->name,
					name, n);
			}
				break;

			case ft_set: /* bits representing set */
				DBG_log("   %s: %s (0x%" PRIx32 ")",
					fp->name,
					bitnamesof(fp->desc, n),
					n);
				break;
			default:
				bad_case(fp->field_type);
			}
			inp += i;
			break;

		case ft_raw:            /* bytes to be left in network-order */
		{
			char m[50];     /* arbitrary limit on name width in log */

			snprintf(m, sizeof(m), "   %s:", fp->name);
			DBG_dump(m, inp, i);
			inp += i;
		}
		break;
		default:
			bad_case(fp->field_type);
		}
	}
}

static void DBG_prefix_print_struct(const pb_stream *pbs,
				    const char *label, const void *struct_ptr,
				    struct_desc *sd, bool len_meaningful)
{
	/* print out a title, with a prefix of asterisks to show
	 * the nesting level.
	 */
	char space[40]; /* arbitrary limit on label+flock-of-* */
	size_t len = strlen(label);

	if (sizeof(space) <= len) {
		DBG_print_struct(label, struct_ptr, sd, len_meaningful);
	} else {
		const pb_stream *p = pbs;
		char *pre = &space[sizeof(space) - (len + 1)];

		strcpy(pre, label);

		/* put at least one * out */
		for (;; ) {
			if (pre <= space)
				break;
			*--pre = '*';
			if (p == NULL)
				break;
			p = p->container;
		}
		DBG_print_struct(pre, struct_ptr, sd, len_meaningful);
	}
}

/* "parse" a network struct into a host struct.
 *
 * This code assumes that the network and host structure
 * members have the same alignment and size!  This requires
 * that all padding be explicit.
 *
 * If obj_pbs is supplied, a new pb_stream is created for the
 * variable part of the structure (this depends on their
 * being one length field in the structure).  The cursor of this
 * new PBS is set to after the parsed part of the struct.
 *
 * This routine returns TRUE iff it succeeds.
 */
bool in_struct(void *struct_ptr, struct_desc *sd,
	       pb_stream *ins, pb_stream *obj_pbs)
{
	err_t ugh = NULL;
	uint8_t *cur = ins->cur;

	if (ins->roof - cur < (ptrdiff_t)sd->size) {
		ugh = builddiag("not enough room in input packet for %s (remain=%li, sd->size=%zu)",
				sd->name, (long int)(ins->roof - cur),
				sd->size);
	} else {
		uint8_t *roof = cur + sd->size; /* may be changed by a length field */
		uint8_t *outp = struct_ptr;
		bool immediate = FALSE;
		uint32_t last_enum = 0;

		for (field_desc *fp = sd->fields; ugh == NULL; fp++) {

			/* field ends within PBS? */
			passert(cur + fp->size <= ins->roof);
			/* field ends within struct? */
			passert(cur + fp->size <= ins->cur + sd->size);
			/* "offset into struct" - "offset into pbs" == "start of struct"? */
			passert(outp - (cur - ins->cur) == struct_ptr);

#if 0
			DBGF(DBG_PARSING, "%td (%td) '%s'.'%s' %d bytes ",
			     (cur - ins->cur), (cur - ins->start),
			     sd->name, fp->name,
			     fp->size);
#endif

			switch (fp->field_type) {
			case ft_zig: /* should be zero, ignore if not - liberal in what to receive, strict to send */
				for (size_t i = fp->size; i != 0; i--) {
					uint8_t byte = *cur;
					if (byte != 0) {
						/* We cannot zeroize it, it would break our hash calculation. */
						libreswan_log( "byte at offset %td (%td) of '%s'.'%s' is 0x%02"PRIx8" but should have been zero (ignored)",
							       (cur - ins->cur),
							       (cur - ins->start),
							       sd->name, fp->name,
							       byte);
					}
					cur++;
					*outp++ = '\0'; /* probably redundant */
				}
				break;

			case ft_nat:            /* natural number (may be 0) */
			case ft_len:            /* length of this struct and any following crud */
			case ft_lv:             /* length/value field of attribute */
			case ft_enum:           /* value from an enumeration */
			case ft_loose_enum:     /* value from an enumeration with only some names known */
			case ft_mnpc:
			case ft_pnpc:
			case ft_lss:
			case ft_loose_enum_enum:	/* value from an enumeration with partial name table based on previous enum */
			case ft_af_enum:        /* Attribute Format + value from an enumeration */
			case ft_af_loose_enum:  /* Attribute Format + value from an enumeration */
			case ft_set:            /* bits representing set */
			{
				uint32_t n = 0;

				/* Reportedly fails on arm, see bug #775 */
				for (size_t i = fp->size; i != 0; i--)
					n = (n << BITS_PER_BYTE) | *cur++;

				switch (fp->field_type) {
				case ft_len:    /* length of this struct and any following crud */
				case ft_lv:     /* length/value field of attribute */
				{
					uint32_t len = fp->field_type ==
							ft_len ? n :
							immediate ? sd->size :
							n + sd->size;

					if (len < sd->size) {
						ugh = builddiag(
							"%s of %s is smaller than minimum",
							fp->name,
							sd->name);
					} else if (pbs_left(ins) < len) {
						ugh = builddiag(
							"%s of %s is larger than can fit",
							fp->name,
							sd->name);
					} else {
						roof = ins->cur + len;
					}
					break;
				}

				case ft_af_loose_enum: /* Attribute Format + value from an enumeration */
				case ft_af_enum: /* Attribute Format + value from an enumeration */
					immediate = ((n & ISAKMP_ATTR_AF_MASK) ==
						     ISAKMP_ATTR_AF_TV);
					last_enum = n & ~ISAKMP_ATTR_AF_MASK;
					/*
					 * Lookup fp->desc using N and
					 * not LAST_ENUM.  Only when N
					 * (value or AF+value) is
					 * found is it acceptable.
					 */
					if (fp->field_type == ft_af_enum &&
					    enum_name(fp->desc, n) == NULL) {
						ugh = builddiag("%s of %s has an unknown value: %s%" PRIu32 " (0x%" PRIx32 ")",
								fp->name, sd->name,
								immediate ? "AF+" : "",
								last_enum, n);
					}
					break;

				case ft_enum:   /* value from an enumeration */
					if (enum_name(fp->desc, n) == NULL) {
						ugh = builddiag("%s of %s has an unknown value: %" PRIu32 " (0x%" PRIx32 ")",
								fp->name, sd->name,
								n,
								n);
					}
				/* FALL THROUGH */
				case ft_loose_enum:     /* value from an enumeration with only some names known */
				case ft_mnpc:
				case ft_pnpc:
				case ft_lss:
					last_enum = n;
					break;

				case ft_loose_enum_enum:	/* value from an enumeration with partial name table based on previous enum */
					ugh = enum_enum_checker(sd->name, fp, last_enum);
					break;

				case ft_set:            /* bits representing set */
					if (!testset(fp->desc, n)) {
						ugh = builddiag("bitset %s of %s has unknown member(s): %s (0x%" PRIx32 ")",
								fp->name, sd->name,
								bitnamesof(fp->desc, n),
								n);
					}
					break;

				default:
					break;
				}

				/* deposit the value in the struct */
				switch (fp->size) {
				case 8 / BITS_PER_BYTE:
					*(uint8_t *)outp = n;
					break;
				case 16 / BITS_PER_BYTE:
					*(uint16_t *)outp = n;
					break;
				case 32 / BITS_PER_BYTE:
					*(uint32_t *)outp = n;
					break;
				default:
					bad_case(fp->size);
				}
				outp += fp->size;
				break;
			}

			case ft_raw: /* bytes to be left in network-order */
				for (size_t i = fp->size; i != 0; i--)
					*outp++ = *cur++;
				break;

			case ft_end: /* end of field list */
				passert(cur == ins->cur + sd->size);
				if (obj_pbs != NULL) {
					init_pbs(obj_pbs, ins->cur,
						 roof - ins->cur, sd->name);
					obj_pbs->container = ins;
					obj_pbs->desc = sd;
					obj_pbs->cur = cur;
				}
				ins->cur = roof;
				DBG(DBG_PARSING,
				    DBG_prefix_print_struct(ins, "parse ",
							    struct_ptr, sd,
							    TRUE));
				return TRUE;

			default:
				bad_case(fp->field_type);
			}
		}
	}

	/* some failure got us here: report it */
	libreswan_log_rc(RC_LOG_SERIOUS, "%s", ugh);
	return FALSE;
}

bool in_raw(void *bytes, size_t len, pb_stream *ins, const char *name)
{
	if (pbs_left(ins) < len) {
		libreswan_log_rc(RC_LOG_SERIOUS,
				 "not enough bytes left to get %s from %s",
				 name, ins->name);
		return FALSE;
	} else {
		if (bytes == NULL) {
			DBG(DBG_PARSING,
			    DBG_log("skipping %u raw bytes of %s (%s)",
				    (unsigned) len, ins->name, name);
			    DBG_dump(name, ins->cur, len));
		} else {
			memcpy(bytes, ins->cur, len);
			DBG(DBG_PARSING,
			    DBG_log("parsing %u raw bytes of %s into %s",
				    (unsigned) len, ins->name, name);
			    DBG_dump(name, bytes, len));
		}
		ins->cur += len;
		return TRUE;
	}
}

/*
 * Check IKEv2's Last Substructure field.
 */

static void update_last_substructure(pb_stream *outs,
				     struct_desc *sd, field_desc *fp,
				     const uint8_t *inp, uint8_t *cur)
{
	/*
	 * The containing structure should be expecting substructures.
	 */
	passert(fp->size == 1);
	pexpect(outs->desc->nsst != 0);
	uint8_t n = *inp;
	pexpect(n == 0 || n == outs->desc->nsst);
	*cur = n;
	/*
	 * Since there's a previous substructure, it can no longer be
	 * last.  Check/set its last substructure field to its type.
	 */
	if (outs->last_substructure.loc != NULL) {
		struct esb_buf ssb;
		DBGF(DBG_EMITTING, "last substructure: checking '%s'.'%s'.'%s' is %s (0x%x)",
		     outs->desc->name,
		     outs->last_substructure.sd->name,
		     outs->last_substructure.fp->name,
		     enum_showb(outs->last_substructure.fp->desc,
				outs->desc->nsst, &ssb),
		     outs->desc->nsst);
		pexpect(outs->last_substructure.loc[0] == outs->desc->nsst);
	}
	/*
	 * Now save the location of this Last Substructure.
	 */
	DBGF(DBG_EMITTING, "last substructure: saving location '%s'.'%s'.'%s'",
	     outs->desc->name, sd->name, fp->name);
	outs->last_substructure.loc = cur;
	outs->last_substructure.sd = sd;
	outs->last_substructure.fp = fp;
}

static void close_last_substructure(pb_stream *pbs)
{
	if (pbs->last_substructure.loc != NULL) {
		DBGF(DBG_EMITTING, "last substructure: checking '%s'.'%s'.'%s' is 0",
		     pbs->desc->name,
		     pbs->last_substructure.sd->name,
		     pbs->last_substructure.fp->name);
		pexpect(pbs->desc->nsst != 0);
		pexpect(pbs->last_substructure.loc[0] == 0);
#if 0
	} else {
		/* XXX: too strong, rejects empty? */
		pexpect(pbs->desc->nsst == 0);
#endif
	}
}

/*
 * Next Payload Chain
 */

static void start_next_payload_chain(pb_stream *message,
				     struct_desc *sd, field_desc *fp,
				     const uint8_t *inp, uint8_t *cur)
{
	passert(fp->size == 1);
	DBGF(DBG_EMITTING, "next payload chain: saving message location '%s'.'%s'",
	     sd->name, fp->name);
	message->next_payload_chain.loc = cur;
	message->next_payload_chain.sd = sd;
	message->next_payload_chain.fp = fp;
	uint8_t n = *inp;
	if (n != ISAKMP_NEXT_NONE) {
		struct esb_buf npb;
		DBGF(DBG_EMITTING, "next payload chain: ignoring supplied '%s'.'%s' value %d:%s",
		     sd->name, fp->name, n,
		     enum_showb(fp->desc, n, &npb));
		n = ISAKMP_NEXT_NONE;
	}
	*cur = n;
}

static void update_next_payload_chain(pb_stream *outs,
				      struct_desc *sd, field_desc *fp,
				      const uint8_t *inp, uint8_t *cur)
{
	passert(fp->size == 1);
	passert(sd->pt != ISAKMP_NEXT_NONE);

	/*
	 * Normally only comes after the header and ft_mnpc.  However,
	 * as part of authenticating, IKEv1 fakes up a PBS containing
	 * just the "Identification Payload".
	 */
	if (outs->container == NULL) {
		struct esb_buf npb;
		DBGF(DBG_EMITTING,
		     "next payload chain: no previous for current %s (%d:%s); assumed to be fake",
		     sd->name, sd->pt, enum_showb(fp->desc, sd->pt, &npb));
		return;
	}

	/*
	 * Find the message (packet) PBS containing the next payload
	 * chain pointers initialized by start_next_payload_chain().
	 * Since there is a single chain, running through the message,
	 * this is stored in the outermost PBS.
	 *
	 * XXX: don't try to be all fancy and copy back values; could
	 * use an outs->message pointer; but since nesting is minimial
	 * this isn't really urgent
	 */
	pb_stream *message = outs->container;
	passert(message != NULL);
	while (message->container != NULL) {
		message = message->container;
	}
	passert(message->next_payload_chain.loc != NULL);
	passert(message->next_payload_chain.sd != NULL);
	passert(message->next_payload_chain.fp != NULL);
	pexpect(*message->next_payload_chain.loc == ISAKMP_NEXT_NONE);

	/*
	 * Initialize this payload's next payload chain
	 *
	 * v2SKF is a hack - the fragmentation code gets to dictate
	 * the value, not this code.  Since SKF there should be
	 * nothing after an SFK payload this works.
	 */
	uint8_t n = *inp;
	if (sd->pt == ISAKMP_NEXT_v2SKF) {
		struct esb_buf npb;
		DBGF(DBG_EMITTING, "next payload chain: using supplied v2SKF '%s'.'%s' value %d:%s",
		     sd->name, fp->name, n,
		     enum_showb(fp->desc, n, &npb));
	} else if (n != ISAKMP_NEXT_NONE) {
		struct esb_buf npb;
		DBGF(DBG_EMITTING, "next payload chain: ignoring supplied '%s'.'%s' value %d:%s",
		     sd->name, fp->name, n,
		     enum_showb(fp->desc, n, &npb));
		n = ISAKMP_NEXT_NONE;
	}
	*cur = n;

	/* update previous struct's next payload type field */
	struct esb_buf npb;
	DBGF(DBG_EMITTING, "next payload chain: setting previous '%s'.'%s' to current %s (%d:%s)",
	     message->next_payload_chain.sd->name,
	     message->next_payload_chain.fp->name,
	     sd->name, sd->pt, enum_showb(fp->desc, sd->pt, &npb));
	*message->next_payload_chain.loc = sd->pt;

	/* save new */
	DBGF(DBG_EMITTING,
	     "next payload chain: saving location '%s'.'%s' in '%s'",
	     sd->name, fp->name, message->name);
	message->next_payload_chain.loc = cur;
	message->next_payload_chain.sd = sd;
	message->next_payload_chain.fp = fp;
}

/* "emit" a host struct into a network packet.
 *
 * This code assumes that the network and host structure
 * members have the same alignment and size!  This requires
 * that all padding be explicit.
 *
 * If obj_pbs is non-NULL, its pbs describes a new output stream set up
 * to contain the object.  The cursor will be left at the variable part.
 * This new stream must subsequently be finalized by close_output_pbs().
 *
 * The value of any field of type ft_len is computed, not taken
 * from the input struct.  The length is actually filled in when
 * the object's output stream is finalized.  If obj_pbs is NULL,
 * finalization is done by out_struct before it returns.
 *
 * This routine returns TRUE iff it succeeds.
 */

bool out_struct(const void *struct_ptr, struct_desc *sd,
		pb_stream *outs, pb_stream *obj_pbs)
{
	err_t ugh = NULL;
	const u_int8_t *inp = struct_ptr;
	u_int8_t *cur = outs->cur;

	DBG(DBG_EMITTING,
	    DBG_prefix_print_struct(outs, "emit ", struct_ptr, sd,
				    obj_pbs == NULL));

	if (outs->roof - cur < (ptrdiff_t)sd->size) {
		ugh = builddiag(
			"not enough room left in output packet to place %s",
			sd->name);
	} else {
		bool immediate = FALSE;
		uint32_t last_enum = 0;

		/* new child stream for portion of payload after this struct */
		pb_stream obj = {
			.container = outs,
			.desc = sd,
			.name = sd->name,

			/* until a length field is discovered */
			/* .lenfld = NULL, */
			/* .lenfld_desc = NULL, */

			/* until an ft_mnpc field is discovered */
			/* message.previous_np = {0}, */

			/* until an ft_lss is discovered */
			/* .last_substructure = {0}, */
		};

		for (field_desc *fp = sd->fields; ugh == NULL; fp++) {
			size_t i = fp->size;

			/* make sure that there is space for the next structure element */
			passert(outs->roof - cur >= (ptrdiff_t)i);

			/* verify that the spot is correct in the offset */
			passert(cur - outs->cur <= (ptrdiff_t)(sd->size - i));

			/* verify that we are at the right place in the input structure */
			passert(inp - (cur - outs->cur) == struct_ptr);

#if 0
			DBG_log("out_struct: %d %s",
				(int) (cur - outs->cur),
				fp->name == NULL ? "<end>" : fp->name);
#endif
			switch (fp->field_type) {
			case ft_zig: /* zero */
				memset(cur, 0, i);
				inp += i;
				cur += i;
				break;

			case ft_mnpc:
				start_next_payload_chain(outs, sd, fp,
							 inp, cur);
				last_enum = ISAKMP_NEXT_NONE;
				inp += fp->size;
				cur += fp->size;
				break;

			case ft_pnpc:
				update_next_payload_chain(outs, sd, fp,
							  inp, cur);
				last_enum = ISAKMP_NEXT_NONE;
				inp += fp->size;
				cur += fp->size;
				break;

			case ft_lss:
				update_last_substructure(outs, sd, fp,
							 inp, cur);
				last_enum = ISAKMP_NEXT_NONE;
				inp += fp->size;
				cur += fp->size;
				break;

			case ft_len:            /* length of this struct and any following crud */
			case ft_lv:             /* length/value field of attribute */
				if (!immediate) {
					/* We can't check the length because it must
					 * be filled in after variable part is supplied.
					 * We do record where this is so that it can be
					 * filled in by a subsequent close_output_pbs().
					 */
					passert(obj.lenfld == NULL);    /* only one ft_len allowed */
					obj.lenfld = cur;
					obj.lenfld_desc = fp;

					/* fill with crap so failure to overwrite will be noticed */
					memset(cur, 0xFA, i);

					inp += i;
					cur += i;
					break;
				}
				/* immediate form is just like a number */
				/* FALL THROUGH */
			case ft_nat:            /* natural number (may be 0) */
			case ft_enum:           /* value from an enumeration */
			case ft_loose_enum:     /* value from an enumeration with only some names known */
			case ft_loose_enum_enum:	/* value from an enumeration with partial name table based on previous enum */
			case ft_af_enum:        /* Attribute Format + value from an enumeration */
			case ft_af_loose_enum:  /* Attribute Format + value from an enumeration */
			case ft_set:            /* bits representing set */
			{
				uint32_t n;

				switch (i) {
				case 8 / BITS_PER_BYTE:
					n = *(const uint8_t *)inp;
					break;
				case 16 / BITS_PER_BYTE:
					n = *(const uint16_t *)inp;
					break;
				case 32 / BITS_PER_BYTE:
					n = *(const uint32_t *)inp;
					break;
				default:
					bad_case(i);
				}

				switch (fp->field_type) {

				case ft_af_loose_enum: /* Attribute Format + value from an enumeration */
				case ft_af_enum: /* Attribute Format + value from an enumeration */
					immediate = ((n & ISAKMP_ATTR_AF_MASK) ==
						     ISAKMP_ATTR_AF_TV);
					last_enum = n & ~ISAKMP_ATTR_AF_MASK;
					if (fp->field_type == ft_af_enum &&
					    enum_name(fp->desc, n) == NULL) {
						ugh = builddiag("%s of %s has an unknown value: 0x%x+%" PRIu32 " (0x%" PRIx32 ")",
								fp->name, sd->name,
								n & ISAKMP_ATTR_AF_MASK,
								last_enum, n);
						if (impair_emitting) {
							libreswan_log("IMPAIR: emitting %s", ugh);
							ugh = NULL;
						}
					}
					break;

				case ft_enum:   /* value from an enumeration */
					if (enum_name(fp->desc, n) == NULL) {
						ugh = builddiag("%s of %s has an unknown value: %" PRIu32 " (0x%" PRIx32 ")",
								fp->name, sd->name,
								n,
								n);
					}
				/* FALL THROUGH */
				case ft_loose_enum:     /* value from an enumeration with only some names known */
					last_enum = n;
					break;

				case ft_loose_enum_enum:	/* value from an enumeration with partial name table based on previous enum */
					ugh = enum_enum_checker(sd->name, fp, last_enum);
					break;

				case ft_set:            /* bits representing set */
					if (!testset(fp->desc, n)) {
						ugh = builddiag("bitset %s of %s has unknown member(s): %s (0x%" PRIx32 ")",
								fp->name, sd->name,
								bitnamesof(fp->desc, n),
								n);
					}
					break;

				default:
					break;
				}

				/* emit i low-order bytes of n in network order */
				while (i-- != 0) {
					cur[i] = (uint8_t)n;
					n >>= BITS_PER_BYTE;
				}
				inp += fp->size;
				cur += fp->size;
				break;
			}

			case ft_raw: /* bytes to be left in network-order */
				for (; i != 0; i--)
					*cur++ = *inp++;
				break;

			case ft_end: /* end of field list */
				passert(cur == outs->cur + sd->size);

				obj.start = outs->cur;
				obj.cur = cur;
				obj.roof = outs->roof; /* limit of possible */
				/* obj.lenfld* and obj.previous_np* already set */

				if (obj_pbs == NULL) {
					close_output_pbs(&obj); /* fill in length field, if any */
				} else {
					/* We set outs->cur to outs->roof so that
					 * any attempt to output something into outs
					 * before obj is closed will trigger an error.
					 */
					outs->cur = outs->roof;

					*obj_pbs = obj;
				}
				return TRUE;

			default:
				bad_case(fp->field_type);
			}
		}
	}

	/* some failure got us here: report it */
	loglog(RC_LOG_SERIOUS, "%s", ugh); /* ??? serious, but errno not relevant */
	return FALSE;
}

bool ikev1_out_generic(uint8_t np, struct_desc *sd,
		 pb_stream *outs, pb_stream *obj_pbs)
{
	passert(sd->fields == isag_fields);
	passert(sd->pt != ISAKMP_NEXT_NONE);
	struct isakmp_generic gen = {
		.isag_np = np,
	};
	return out_struct(&gen, sd, outs, obj_pbs);
}

bool ikev1_out_generic_raw(uint8_t np, struct_desc *sd,
		     pb_stream *outs, const void *bytes, size_t len,
		     const char *name)
{
	pb_stream pbs;

	if (!ikev1_out_generic(np, sd, outs, &pbs) ||
	    !out_raw(bytes, len, &pbs, name))
		return FALSE;

	close_output_pbs(&pbs);
	return TRUE;
}

static bool space_for(size_t len, pb_stream *outs, const char *fmt, ...) PRINTF_LIKE(3);
static bool space_for(size_t len, pb_stream *outs, const char *fmt, ...)
{
	if (pbs_left(outs) == 0) {
		/* should this be a DBGLOG? */
		LSWLOG_RC(RC_LOG_SERIOUS, buf) {
			lswlogf(buf, "%s is already full; discarding ", outs->name);
			va_list ap;
			va_start(ap, fmt);
			lswlogvf(buf, fmt, ap);
			va_end(ap);
		}
		return false;
	} else if (pbs_left(outs) <= len) {
		/* overflow at at left==1; left==0 for already overflowed */
		LSWLOG_RC(RC_LOG_SERIOUS, buf) {
			lswlogf(buf, "%s is full; unable to emit ", outs->name);
			va_list ap;
			va_start(ap, fmt);
			lswlogvf(buf, fmt, ap);
			va_end(ap);
		}
		/* overflow the buffer */
		outs->cur += pbs_left(outs);
		return false;
	} else {
		LSWDBGP(DBG_EMITTING, buf) {
			lswlogs(buf, "emitting ");
			va_list ap;
			va_start(ap, fmt);
			lswlogvf(buf, fmt, ap);
			va_end(ap);
			lswlogf(buf, " into %s", outs->name);
		}
		return true;
	}
}

bool out_raw(const void *bytes, size_t len, pb_stream *outs, const char *name)
{
	if (space_for(len, outs, "%zu raw bytes of %s", len, name)) {
		DBG(DBG_EMITTING, DBG_dump(name, bytes, len));
		memcpy(outs->cur, bytes, len);
		outs->cur += len;
		return true;
	} else {
		return false;
	}
}

bool out_repeated_byte(uint8_t byte, size_t len, pb_stream *outs, const char *name)
{
	if (space_for(len, outs, "%zu 0x%02x repeated bytes of %s", len, byte, name)) {
		memset(outs->cur, byte, len);
		outs->cur += len;
		return true;
	} else {
		return false;
	}
}

bool out_zero(size_t len, pb_stream *outs, const char *name)
{
	if (space_for(len, outs, "%zu zero bytes of %s", len, name)) {
		memset(outs->cur, 0, len);
		outs->cur += len;
		return true;
	} else {
		return false;
	}
}

pb_stream open_output_struct_pbs(pb_stream *outs, const void *struct_ptr,
				 struct_desc *sd)
{
	pb_stream obj_pbs;
	if (out_struct(struct_ptr, sd, outs, &obj_pbs)) {
		return obj_pbs;
	} else {
		return empty_pbs;
	}
}


/*
 * Reply messages are built in this nasty evil global buffer.
 *
 * Only one packet can be built at a time.  That should be ok as
 * packets are only built on the main thread and code and a packet is
 * created using a single operation.
 *
 * In the good old days code would partially construct a packet,
 * wonder off to do crypto and process other packets, and then assume
 * things could be picked up where they were left off.  Code to make
 * that work (saving restoring the buffer, re-initializing the buffer
 * in strange places, ....) has all been removed.
 *
 * Something else that should go is global access to REPLY_STREAM.
 * Instead all code should use open_reply_stream() and a reference
 * with only local scope.  This should reduce the odds of code
 * meddling in reply_stream on the sly.
 *
 * Another possibility is to move the buffer onto the stack.  However,
 * the PBS is 64K and that isn't so good for small machines.  Then
 * again the send.[hc] and demux[hc] code both allocate 64K stack
 * buffers already.  Oops.
 */

pb_stream reply_stream;
uint8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

/*
 * close_output_pbs: record current length and check previous_NP
 *
 * Note: currently, this may be repeated any number of times;
 * the last call's setting of the length wins.
 */

void close_output_pbs(pb_stream *pbs)
{
	if (pbs->lenfld != NULL) {
		uint32_t len = pbs_offset(pbs);
		int i = pbs->lenfld_desc->size;

		passert(i > 0);

		if (pbs->lenfld_desc->field_type == ft_lv)
			len -= sizeof(struct isakmp_attribute);

		DBG(DBG_EMITTING, DBG_log("emitting length of %s: %" PRIu32,
					  pbs->name, len));

		/* emit octets of length in network order */
		while (i-- != 0) {
			pbs->lenfld[i] = (uint8_t)len;
			len >>= BITS_PER_BYTE;
		}
	}

	/* if there is one */
	close_last_substructure(pbs);

	if (pbs->container != NULL)
		pbs->container->cur = pbs->cur; /* pass space utilization up */
}
