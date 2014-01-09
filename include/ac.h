/* Support of X.509 attribute certificates
 * Copyright (C) 2002 Ueli Gallizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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
 */

#ifndef _AC_H
#define _AC_H

/* definition of ietfAttribute kinds */

typedef enum {
	IETF_ATTRIBUTE_OCTETS =     0,
	IETF_ATTRIBUTE_OID =        1,
	IETF_ATTRIBUTE_STRING =     2
} ietfAttribute_t;

/* access structure for an ietfAttribute */

typedef struct ietfAttr ietfAttr_t;

struct ietfAttr {
	time_t installed;
	int count;
	ietfAttribute_t kind;
	chunk_t value;
};

typedef struct ietfAttrList ietfAttrList_t;

struct ietfAttrList {
	ietfAttrList_t   *next;
	ietfAttr_t       *attr;
};

/* access structure for an X.509 attribute certificate */

typedef struct x509acert x509acert_t;

struct x509acert {
	x509acert_t    *next;
	time_t installed;
	chunk_t certificate;
	chunk_t certificateInfo;
	u_int version;
	/*   holder */
	/*     baseCertificateID */
	chunk_t holderIssuer;
	chunk_t holderSerial;
	chunk_t entityName;
	/*   v2Form */
	chunk_t issuerName;
	/*   signature */
	int sigAlg;
	chunk_t serialNumber;
	/*   attrCertValidityPeriod */
	time_t notBefore;
	time_t notAfter;
	/*   attributes */
	ietfAttrList_t       *charging;
	ietfAttrList_t       *groups;
	/*   extensions */
	chunk_t authKeyID;
	chunk_t authKeySerialNumber;
	bool noRevAvail;
	/* signatureAlgorithm */
	int algorithm;
	chunk_t signature;
};

extern void free_ietfAttrList(ietfAttrList_t *list);
extern void decode_groups(char *groups, ietfAttrList_t **listp);
extern void load_acerts(void);
extern void free_acerts(void);
extern void list_acerts(bool utc);
extern void list_groups(bool utc);

#endif /* _AC_H */
