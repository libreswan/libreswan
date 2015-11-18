/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <cert.h>
#include <secder.h>
#include "nss_copies.h"

/*
 * The NSS functions CERT_CheckCrlTimes() and CERT_CompareAVA() are not yet
 * exported by the library, even though they exist in the public headers.
 *
 * This file contains the copied code necessary to make use of them and
 * provides NSSCERT_CheckCrlTimes() and NSSCERT_CompareAVA() for pluto use.
 * When these become available from NSS we will be able to #ifdef based on
 * NSS version.
 *
 * See: https://bugzilla.mozilla.org/show_bug.cgi?id=294538
 */

static void _NSSCPY_canonicalize(SECItem * foo)
{
    int ch, lastch, len, src, dest;

    /* strip trailing whitespace. */
    len = foo->len;
    while (len > 0 && ((ch = foo->data[len - 1]) == ' ' ||
	   ch == '\t' || ch == '\r' || ch == '\n')) {
	len--;
    }

    src = 0;
    /* strip leading whitespace. */
    while (src < len && ((ch = foo->data[src]) == ' ' ||
	   ch == '\t' || ch == '\r' || ch == '\n')) {
	src++;
    }
    dest = 0; lastch = ' ';
    while (src < len) {
	ch = foo->data[src++];
	if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
	    ch = ' ';
	    if (ch == lastch)
		continue;
	} else if (ch >= 'A' && ch <= 'Z') {
	    ch |= 0x20;  /* downshift */
	}
	foo->data[dest++] = lastch = ch;
    }
    foo->len = dest;
}

/* SECItems a and b contain DER-encoded printable strings. */
static SECComparison _NSSCPY_CERT_CompareDERPrintableStrings(const SECItem *a,
							     const SECItem *b)
{
    SECComparison rv = SECLessThan;
    SECItem * aVal = CERT_DecodeAVAValue(a);
    SECItem * bVal = CERT_DecodeAVAValue(b);

    if (aVal && aVal->len && aVal->data &&
	bVal && bVal->len && bVal->data) {
	_NSSCPY_canonicalize(aVal);
	_NSSCPY_canonicalize(bVal);
	rv = SECITEM_CompareItem(aVal, bVal);
    }
    SECITEM_FreeItem(aVal, PR_TRUE);
    SECITEM_FreeItem(bVal, PR_TRUE);
    return rv;
}

static SECComparison _NSSCPY_CERT_CompareAVA(const CERTAVA *a, const CERTAVA *b)
{
    SECComparison rv;

    rv = SECITEM_CompareItem(&a->type, &b->type);
    if (SECEqual != rv)
	return rv;  /* Attribute types don't match. */
    /* Let's be optimistic.  Maybe the values will just compare equal. */
    rv = SECITEM_CompareItem(&a->value, &b->value);
    if (SECEqual == rv)
	return rv;  /* values compared exactly. */
    if (a->value.len && a->value.data && b->value.len && b->value.data) {
	/* Here, the values did not match.
	** If the values had different encodings, convert them to the same
	** encoding and compare that way.
	*/
	if (a->value.data[0] != b->value.data[0]) {
	    /* encodings differ.  Convert both to UTF-8 and compare. */
	    SECItem * aVal = CERT_DecodeAVAValue(&a->value);
	    SECItem * bVal = CERT_DecodeAVAValue(&b->value);
	    if (aVal && aVal->len && aVal->data &&
		bVal && bVal->len && bVal->data) {
		rv = SECITEM_CompareItem(aVal, bVal);
	    }
	    SECITEM_FreeItem(aVal, PR_TRUE);
	    SECITEM_FreeItem(bVal, PR_TRUE);
	} else if (a->value.data[0] == 0x13) { /* both are printable strings. */
	    /* printable strings */
	    rv = _NSSCPY_CERT_CompareDERPrintableStrings(&a->value, &b->value);
	}
    }
    return rv;
}

/*
 * copies of NSS functions that are not yet exported by the library
 */
static SECStatus _NSSCPY_GetCrlTimes(CERTCrl *date, PRTime *notBefore,
					     PRTime *notAfter)
{
	int rv;
	/* convert DER not-before time */
	rv = DER_DecodeTimeChoice(notBefore, &date->lastUpdate);
	if (rv) {
		return(SECFailure);
	}

	/* convert DER not-after time */
	if (date->nextUpdate.data) {
		rv = DER_DecodeTimeChoice(notAfter, &date->nextUpdate);
		if (rv) {
			return(SECFailure);
		}
	} else {
		LL_I2L(*notAfter, 0L);
	}

	return(SECSuccess);
}

static SECCertTimeValidity _NSSCPY_CheckCrlTimes(CERTCrl *crl, PRTime t)
{
	PRTime notBefore, notAfter, llPendingSlop, tmp1;
	SECStatus rv;
	PRInt32 pSlop = CERT_GetSlopTime();

	rv = _NSSCPY_GetCrlTimes(crl, &notBefore, &notAfter);
	if (rv) {
		return(secCertTimeExpired);
	}
	LL_I2L(llPendingSlop, pSlop);
	/* convert to micro seconds */
	LL_I2L(tmp1, PR_USEC_PER_SEC);
	LL_MUL(llPendingSlop, llPendingSlop, tmp1);
	LL_SUB(notBefore, notBefore, llPendingSlop);
	if ( LL_CMP( t, <, notBefore ) ) {
		return(secCertTimeNotValidYet);
	}
	/* If next update is omitted and the test for notBefore passes, then
	 * we assume that the crl is up to date.
	 */
	if ( LL_IS_ZERO(notAfter) ) {
		return(secCertTimeValid);
	}
	if ( LL_CMP( t, >, notAfter) ) {
		return(secCertTimeExpired);
	}
	return(secCertTimeValid);
}

SECCertTimeValidity NSSCERT_CheckCrlTimes(CERTCrl *crl, PRTime t)
{
	return _NSSCPY_CheckCrlTimes(crl, t);
}

SECComparison NSSCERT_CompareAVA(const CERTAVA *a, const CERTAVA *b)
{
	return _NSSCPY_CERT_CompareAVA(a, b);
}
