/* parsing IKEv1 packets: formats
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015,2018 Andrew Cagney
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


#include "pluto_constants.h"
#include "passert.h"

#include "ikev1_packet.h"


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
	{ ft_af_enum, 16 / BITS_IN_BYTE, "af+type", &oakley_attr_names },
	{ ft_lv, 16 / BITS_IN_BYTE, "length/value", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_oakley_attribute_desc = {
	.name = "ISAKMP Oakley attribute",
	.fields = isaat_fields_oakley,
	.size = sizeof(struct isakmp_attribute),
};

/* IPsec DOI Attributes */

static field_desc isaat_fields_ipsec[] = {
	{ ft_af_enum, 16 / BITS_IN_BYTE, "af+type", &ipsec_attr_names },
	{ ft_lv, 16 / BITS_IN_BYTE, "length/value", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_ipsec_attribute_desc = {
	.name = "ISAKMP IPsec DOI attribute",
	.fields = isaat_fields_ipsec,
	.size = sizeof(struct isakmp_attribute),
};

/* XAUTH Attributes */

static field_desc isaat_fields_xauth[] = {
	{ ft_af_loose_enum, 16 / BITS_IN_BYTE, "ModeCfg attr type", &modecfg_attr_names },
	{ ft_lv, 16 / BITS_IN_BYTE, "length/value", NULL },
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 32 / BITS_IN_BYTE, "DOI", &doi_names },
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
	{ ft_lset, 32 / BITS_IN_BYTE, "IPsec DOI SIT", &sit_bit_names },
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
	{ ft_lss, 8 / BITS_IN_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_nat, 8 / BITS_IN_BYTE, "proposal number", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "protocol ID", &ikev1_protocol_names },
	{ ft_nat, 8 / BITS_IN_BYTE, "SPI size", NULL },
	{ ft_nat, 8 / BITS_IN_BYTE, "number of transforms", NULL },
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
	{ ft_lss, 8 / BITS_IN_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_nat, 8 / BITS_IN_BYTE, "ISAKMP transform number", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "ISAKMP transform ID", &isakmp_transformid_names },
	{ ft_zig, 16 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_isakmp_transform_desc = {
	.name = "ISAKMP Transform Payload (ISAKMP)",
	.fields = isat_fields_isakmp,
	.size = sizeof(struct isakmp_transform),
};

/* PROTO_IPSEC_AH */

static field_desc isat_fields_ah[] = {
	{ ft_lss, 8 / BITS_IN_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_nat, 8 / BITS_IN_BYTE, "AH transform number", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "AH transform ID", &ah_transformid_names },
	{ ft_zig, 16 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_ah_transform_desc = {
	.name = "ISAKMP Transform Payload (AH)",
	.fields = isat_fields_ah,
	.size = sizeof(struct isakmp_transform),
};

/* PROTO_IPSEC_ESP */

static field_desc isat_fields_esp[] = {
	{ ft_lss, 8 / BITS_IN_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_nat, 8 / BITS_IN_BYTE, "ESP transform number", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "ESP transform ID", &esp_transformid_names },
	{ ft_zig, 16 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_esp_transform_desc = {
	.name = "ISAKMP Transform Payload (ESP)",
	.fields = isat_fields_esp,
	.size = sizeof(struct isakmp_transform),
};

/* PROTO_IPCOMP */

static field_desc isat_fields_ipcomp[] = {
	{ ft_lss, 8 / BITS_IN_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_nat, 8 / BITS_IN_BYTE, "IPCOMP transform number", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "IPCOMP transform ID", &ipsec_ipcomp_algo_names },
	{ ft_zig, 16 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_ipcomp_transform_desc = {
	.name = "ISAKMP Transform Payload (COMP)",
	.fields = isat_fields_ipcomp,
	.size = sizeof(struct isakmp_transform),
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_end, 0, NULL, NULL }
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "ID type", &ikev1_ike_id_type_names }, /* ??? depends on DOI? */
	{ ft_nat, 8 / BITS_IN_BYTE, "DOI specific A", NULL },          /* ??? depends on DOI? */
	{ ft_nat, 16 / BITS_IN_BYTE, "DOI specific B", NULL },         /* ??? depends on DOI? */
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "ID type", &ikev1_ike_id_type_names },
	{ ft_loose_enum, 8 / BITS_IN_BYTE, "Protocol ID", &ip_protocol_id_names, },
	{ ft_nat, 16 / BITS_IN_BYTE, "port", NULL },
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "cert encoding", &ike_cert_type_names },
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &payload_names_ikev1orv2 },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "cert type", &ike_cert_type_names },
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 32 / BITS_IN_BYTE, "DOI", &doi_names },
	{ ft_nat, 8 / BITS_IN_BYTE, "protocol ID", NULL }, /* ??? really enum: ISAKMP, IPSEC, ESP, ... */
	{ ft_nat, 8 / BITS_IN_BYTE, "SPI size", NULL },
	{ ft_enum, 16 / BITS_IN_BYTE, "Notify Message Type", &v1_notification_names },
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 32 / BITS_IN_BYTE, "DOI", &doi_names },
	{ ft_nat, 8 / BITS_IN_BYTE, "protocol ID", NULL }, /* ??? really enum: ISAKMP, IPSEC */
	{ ft_nat, 8 / BITS_IN_BYTE, "SPI size", NULL },
	{ ft_nat, 16 / BITS_IN_BYTE, "number of SPIs", NULL },
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "Attr Msg Type", &attr_msg_type_names },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_nat, 16 / BITS_IN_BYTE, "Identifier", NULL },
	{ ft_end, 0, NULL, NULL }
};

/*
 * MODECFG
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
 *   !                                                               !
 *   ~                           Attributes                          ~
 *   !                                                               !
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct_desc isakmp_attr_desc = {
	.name = "ISAKMP Mode Attribute",
	.fields = isaattr_fields,
	.size = sizeof(struct isakmp_mode_attr),
	.pt = ISAKMP_NEXT_MODECFG,
};

/*
 * ISAKMP NAT-Traversal NAT-D
 * RFC 3947 https://tools.ietf.org/html/rfc3947
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

/*
 * ISAKMP NAT-Traversal NAT-OA
 * RFC 3947 https://tools.ietf.org/html/rfc3947
 *
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !   ID Type     !                   RESERVED                    !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !         IPv4 (4 octets) or IPv6 address (16 octets)           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

static field_desc isanat_oa_fields[] = {
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev1_payload_names },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "ID type", &ikev1_ike_id_type_names },
	{ ft_zig, 24 / BITS_IN_BYTE, "reserved", NULL },
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
	{ ft_zig, 8 / BITS_IN_BYTE, "next payload type", NULL },
	{ ft_zig, 8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_nat, 16 / BITS_IN_BYTE, "fragment id", NULL },
	{ ft_nat, 8 / BITS_IN_BYTE, "fragment number", NULL },
	{ ft_nat, 8 / BITS_IN_BYTE, "flags", NULL }, /* 0x1 means last fragment */
	{ ft_end, 0, NULL, NULL }
};

struct_desc isakmp_ikefrag_desc = {
	.name = "ISAKMP IKE Fragment Payload",
	.fields = isafrag_fields,
	.size = sizeof(struct isakmp_ikefrag),
	.pt = ISAKMP_NEXT_IKE_FRAGMENTATION,
};

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
		&isakmp_attr_desc,              /* 14 ISAKMP_NEXT_MCFG_ATTR (ModeCfg) */
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

bool ikev1_out_generic(struct_desc *sd,
		       struct pbs_out *outs, struct pbs_out *obj_pbs)
{
	PASSERT(outs->logger, sd->fields == isag_fields);
	PASSERT(outs->logger, sd->pt != ISAKMP_NEXT_NONE);
	struct isakmp_generic gen = {
		.isag_np = 0,
	};
	return pbs_out_struct(outs, gen, sd, obj_pbs);
}

bool ikev1_out_generic_shunk(struct_desc *sd, struct pbs_out *outs,
			     shunk_t hunk, const char *name)
{
	struct pbs_out pbs;

	if (!ikev1_out_generic(sd, outs, &pbs)) {
		/* already logged */
	}

	if (!pbs_out_hunk(&pbs, hunk, name)) {
		/* already logged */
		return false;
	}

	close_pbs_out(&pbs);
	return true;
}
