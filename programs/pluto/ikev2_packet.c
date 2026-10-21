/* parsing IKEv2 packets: formats
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
#include "constants.h"
#include "passert.h"

#include "ikev2_packet.h"

/*
 * GENERIC IKEv2 header.
 * Note differs from IKEv1, in that it has flags with one bit a critical bit
 */

static field_desc ikev2generic_fields[] = {
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
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
	{ ft_lss, 8 / BITS_IN_BYTE, "last proposal", &ikev2_last_proposal_desc },
	{ ft_zig,  8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_nat,  8 / BITS_IN_BYTE, "prop #", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "proto ID", &ikev2_proposal_protocol_id_names },
	{ ft_nat,  8 / BITS_IN_BYTE, "spi size", NULL },
	{ ft_nat,  8 / BITS_IN_BYTE, "# transforms", NULL },
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
	{ ft_lss, 8 / BITS_IN_BYTE, "last transform", &ikev2_last_transform_desc },
	{ ft_zig,  8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_loose_enum, 8 / BITS_IN_BYTE, "IKEv2 transform type", &ikev2_trans_type_names },
	{ ft_zig,  8 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_loose_enum_enum, 16 / BITS_IN_BYTE, "IKEv2 transform ID",
	  &ikev2_trans_type_transform_names }, /* select enum based on transform type */
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
	{ ft_af_enum, 16 / BITS_IN_BYTE, "af+type", &ikev2_trans_attr_descs },
	{ ft_lv,      16 / BITS_IN_BYTE, "length/value", NULL },
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

static field_desc ikev2_ke_payload_fields[] = {
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 16 / BITS_IN_BYTE, "KEM", &ikev2_trans_type_ke_names },
	{ ft_zig, 16 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_end,  0, NULL, NULL },
};

struct_desc ikev2_ke_payload_desc = {
	.name = "IKEv2 Key Exchange Payload",
	.fields = ikev2_ke_payload_fields,
	.size = sizeof(struct ikev2_ke_payload),
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
 *    !   ID Type     !                "RESERVED"                     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                   Identification Data                         ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *             Figure 11:  Identification Payload Format
 *
 * Because the ID payload's RESERVED field is included in the AUTH
 * hash calculation it isn't really reserved (aka send zero, ignore on
 * input).  Hence it is flagged as ft_raw and not ft_zig.
 */

static field_desc ikev2id_fields[] = {
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "ID type", &ikev2_ike_id_type_names },
	{ ft_raw, 24 / BITS_IN_BYTE, "reserved", NULL },
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
 * IKEv2 - RFC 8784 (no ascii art provided in RFC)
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
	{ ft_enum, 8 / BITS_IN_BYTE, "PPK ID type", &ikev2_ppk_id_type_names },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_ppk_id_desc = {
	.name = "IKEv2 PPK ID Payload",
	.fields = ikev2_ppk_id_fields,
	.size = sizeof(struct ikev2_ppk_id),
};

static field_desc ikev2cp_fields[] = {
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "ikev2_cfg_type", &ikev2_cp_type_names },
	{ ft_zig, 24 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_cp_desc = {
	.name = "IKEv2 Configuration Payload",
	.fields = ikev2cp_fields,
	.size = sizeof(struct ikev2_cp),
	.pt = ISAKMP_NEXT_v2CP,
};

static field_desc ikev2_cp_attrbute_fields[] = {
	{ ft_loose_enum, 16 / BITS_IN_BYTE, "Attribute Type", &ikev2_cp_attribute_type_names },
	{ ft_lv, 16 / BITS_IN_BYTE, "length/value", NULL },
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "ikev2 cert encoding",
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "ikev2 cert encoding",
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

static field_desc ikev2_auth_fields[] = {
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "auth method", &ikev2_auth_method_names },
	{ ft_zig, 24 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_auth_desc = {
	.name = "IKEv2 Authentication Payload",
	.fields = ikev2_auth_fields,
	.size = sizeof(struct ikev2_auth),
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "Protocol ID", &ikev2_notify_protocol_id_names },
	/* names used are v1 names may be we should use 4306 3.3.1 names */
	{ ft_nat,  8 / BITS_IN_BYTE, "SPI size", NULL },
	{ ft_loose_enum, 16 / BITS_IN_BYTE, "Notify Message Type",
	  &v2_notification_names },
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "protocol ID", &ikev2_delete_protocol_id_names },
	{ ft_nat, 8 / BITS_IN_BYTE, "SPI size", NULL },
	{ ft_nat, 16 / BITS_IN_BYTE, "number of SPIs", NULL },
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

static field_desc ikev2_ts_fields[] = {
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_nat,  8 / BITS_IN_BYTE, "number of TS", NULL },
	{ ft_zig, 24 / BITS_IN_BYTE, "reserved", NULL },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_ts_i_desc = {
	.name = "IKEv2 Traffic Selector - Initiator - Payload",
	.fields = ikev2_ts_fields,
	.size = sizeof(struct ikev2_ts),
	.pt = ISAKMP_NEXT_v2TSi,
};

struct_desc ikev2_ts_r_desc = {
	.name = "IKEv2 Traffic Selector - Responder - Payload",
	.fields = ikev2_ts_fields,
	.size = sizeof(struct ikev2_ts),
	.pt = ISAKMP_NEXT_v2TSr,
};

/*
 * Different types of traffic selector are handled together
 * See RFC 7296 and draft-ietf-ipsecme-labeled-ipsec-04
 *
 * 3.13.1.  Traffic Selector
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !   TS Type     !IP Protocol ID*|       Selector Length         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |           Start Port          |           End Port            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                         Starting Address                      ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    !                                                               !
 *    ~                         Ending Address                        ~
 *    !                                                               !
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *                Figure 20: Traffic Selector
 *
 * 2.1.  TS_SECLABEL payload format
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +---------------+---------------+-------------------------------+
 *    |   TS Type     |    Reserved   |       Selector Length         |
 *    +---------------+---------------+-------------------------------+
 *    |                                                               |
 *    ~                         Security Label*                       ~
 *    |                                                               |
 *    +---------------------------------------------------------------+
 *
 *                Figure 1: Labeled IPsec Traffic Selector
 */

/*
 * These are just read raw, so no struct or fields/desc are needed
 */

/*
 * Traffic Selector Header - read header, then sub out work to type handler
 */

static field_desc ikev2_ts_header_fields[] = {
	{ ft_enum, 8 / BITS_IN_BYTE, "TS type", &ikev2_ts_type_names },
	{ ft_loose_enum,  8 / BITS_IN_BYTE, "IP Protocol ID", &ip_protocol_id_names, },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_ts_header_desc = {
	.name = "IKEv2 Traffic Selector Header",
	.fields = ikev2_ts_header_fields,
	.size = 4 /*sizeof(struct ikev2_ts_header) */ ,
};

static field_desc ikev2_ts_portrange_fields[] = {
	{ ft_nat, 16 / BITS_IN_BYTE, "start port", NULL },
	{ ft_nat, 16 / BITS_IN_BYTE, "end port", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc ikev2_ts_portrange_desc = {
	.name = "IKEv2 IP Traffic Selector port range",
	.fields = ikev2_ts_portrange_fields,
	.size = sizeof(struct ikev2_ts_portrange),
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

/* 3.16.  EAP
 *
 * Use the generic IKEv2 headers only as the struct here. Several different EAP
 * message types can be as the payload and the encoding depends on EAP header.
 * The EAP messages are encoded/decoded as nested structs, and the message types
 * supported are defined below.
 */

struct_desc ikev2_eap_desc = {
	.name = "EAP Payload",
	.fields = ikev2generic_fields,
	.size = sizeof(struct ikev2_generic),
	.pt = ISAKMP_NEXT_v2EAP,
};

/*
 * RFC 3748 4.2. Success and Failure
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Code      |  Identifier   |            Length             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

static field_desc eap_termination_fields[] = {
	{ ft_enum, 8 / BITS_IN_BYTE, "code", &eap_code_names },
	{ ft_nat, 8 / BITS_IN_BYTE, "identifier", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc eap_termination_desc = {
	.name = "EAP Success/Failure",
	.fields = eap_termination_fields,
	.size = sizeof(struct eap_termination),
};

/*
 * RFC 5216 3.1.  EAP-TLS
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Code      |   Identifier  |            Length             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Type      |     Flags     |      TLS Message Length
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     TLS Message Length        |       TLS Data...
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  TLS Message Length is included only if 'L' flag is set.
 *
 * Since presence of 'TLS Message Length' depends on flags, it's not part of
 * the field/struct descriptor, but explicitly encoded/decoded in code together
 * with the 'TLS data' as the payload.
 */
static field_desc eap_tls_fields[] = {
	{ ft_enum, 8 / BITS_IN_BYTE, "code", &eap_code_names },
	{ ft_nat, 8 / BITS_IN_BYTE, "identifier", NULL },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "type", &eap_type_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &eaptls_flag_names },
	{ ft_end, 0, NULL, NULL }
};

struct_desc eap_tls_desc = {
	.name = "EAP TLS header",
	.fields = eap_tls_fields,
	.size = sizeof(struct eap_tls),
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
	{ ft_pnpc, 8 / BITS_IN_BYTE, "next payload type", &ikev2_payload_names },
	{ ft_lset, 8 / BITS_IN_BYTE, "flags", &payload_flag_names },
	{ ft_len, 16 / BITS_IN_BYTE, "length", NULL },
	{ ft_nat, 16 / BITS_IN_BYTE, "fragment number", NULL },
	{ ft_nat, 16 / BITS_IN_BYTE, "total fragments", NULL },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_skf_desc = {
	.name = "IKEv2 Encrypted Fragment",
	.fields = ikev2skf_fields,
	.size = sizeof(struct ikev2_skf),
	.pt = ISAKMP_NEXT_v2SKF,
};

/*
 * IKEv2 REDIRECT Payload - variable part
 *
 *                         1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | GW Ident Type |  GW Ident Len |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               ~
 *    ~                   New Responder GW Identity                   ~
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    ~                        Nonce Data                             ~
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * This is actually Notify Data in IKEv2 Notify payload (see RFC 5685)
 *
 * This struct_desc will be used for checking GW Ident Type and GW
 * Ident Len fields, the rest when using in_struct will be stored in
 * separate struct pbs_in.
 */
static field_desc ikev2redirect_fields[] = {
	{ ft_enum, 8 / BITS_IN_BYTE, "GW Identity type", &ikev2_redirect_gw_names },
	{ ft_nat,  8 / BITS_IN_BYTE, "GW Identity length", NULL },	/* this cannot be ft_len,
									   because of the Nonce Data */
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_redirect_desc = {
	.name = "IKEv2 Redirect Notify Data",
	.fields = ikev2redirect_fields,
	.size = sizeof(struct ikev2_redirect_part),
};

static field_desc ikev2_suggested_kem_fields[] = {
	{ ft_enum, 16 / BITS_IN_BYTE, "suggested KEM", &ikev2_trans_type_ke_names },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2_suggested_kem_desc = {
	.name = "Suggested KEM",
	.fields = ikev2_suggested_kem_fields,
	.size = sizeof(struct ikev2_suggested_kem),
	.pt = ISAKMP_NEXT_v2NONE,
};

/*
 * TICKET_LT_OPAQUE Notify Payload - variable part
 *
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                       Lifetime                                |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    ~                        Ticket                                 ~
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static field_desc ikev2_ticket_lifetime_fields[] = {
	{ ft_nat, 32 / BITS_IN_BYTE, "Lifetime", NULL },
	{ ft_end,  0, NULL, NULL }
};
struct_desc ikev2_ticket_lifetime_desc = {
	.name = "TICKET_LT_OPAQUE Lifetime",
	.fields = ikev2_ticket_lifetime_fields,
	.size = sizeof(struct ikev2_ticket_lifetime),
};

/*
 * IPcomp Notify as per RFC 7296:
 *
 * The data associated with this Notify message includes a two-octet
 * IPComp CPI followed by a one-octet Transform ID optionally followed
 * by attributes whose length and format are defined by that Transform
 * ID.
 *
 * Currently, we only support one Transform ID (2, IPCOMP_DEFLATE) which has
 * no further attributes.
 */

static field_desc ikev2notify_ipcomp_fields[] = {
	{ ft_nat, 16 / BITS_IN_BYTE, "IPcomp SPI (CPI)", NULL },
	{ ft_enum, 8 / BITS_IN_BYTE, "IKEv2 Notification IPCOMP Transform IDs", &ipsec_ipcomp_algo_names },
	{ ft_end,  0, NULL, NULL }
};

struct_desc ikev2notify_ipcomp_data_desc = {
	.name = "IKEv2 IPcomp Notify Data",
	.fields = ikev2notify_ipcomp_fields,
	//.size = sizeof(struct ikev2_notify_ipcomp_data),
	.size = 3,
};

struct_desc *v2_payload_desc(unsigned p)
{
	/* use BUILD_BUG_ON() or static_assert? */
	passert(sizeof(struct ikev2_trans_attr) == FT_LV_ATTRIBUTE_PAYLOAD_SIZE);

	static struct_desc *const v2_payload_descs[] = {
		&ikev2_sa_desc,                 /* 33 ISAKMP_NEXT_v2SA */
		&ikev2_ke_payload_desc,         /* 34 ISAKMP_NEXT_v2KE */
		&ikev2_id_i_desc,		/* 35 ISAKMP_NEXT_v2IDi */
		&ikev2_id_r_desc,		/* 36 ISAKMP_NEXT_v2IDr */
		&ikev2_certificate_desc,        /* 37 ISAKMP_NEXT_v2CERT */
		&ikev2_certificate_req_desc,    /* 38 ISAKMP_NEXT_v2CERTREQ */
		&ikev2_auth_desc,               /* 39 ISAKMP_NEXT_v2AUTH */
		&ikev2_nonce_desc,              /* 40 ISAKMP_NEXT_v2Ni / ISAKMP_NEXT_v2Nr */
		&ikev2_notify_desc,             /* 41 ISAKMP_NEXT_v2N */
		&ikev2_delete_desc,             /* 42 ISAKMP_NEXT_v2D */
		&ikev2_vendor_id_desc,          /* 43 ISAKMP_NEXT_v2V */
		&ikev2_ts_i_desc,		/* 44 ISAKMP_NEXT_v2TSi */
		&ikev2_ts_r_desc,		/* 45 ISAKMP_NEXT_v2TSr */
		&ikev2_sk_desc,                 /* 46 ISAKMP_NEXT_v2SK */
		&ikev2_cp_desc,			/* 47 ISAKMP_NEXT_v2CP */
		&ikev2_eap_desc,		/* 48 ISAKMP_NEXT_v2EAP */
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
