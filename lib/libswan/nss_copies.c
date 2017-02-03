/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <cert.h>
#include <secder.h>
#include "nss_copies.h"

/*
 * The NSS function CERT_CompareAVA() has only been exported by the
 *  library very recently (3.21 does not have it, 3.28 does) , even
 *  though it exists in the public header.
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

SECComparison NSSCERT_CompareAVA(const CERTAVA *a, const CERTAVA *b)
{
	return _NSSCPY_CERT_CompareAVA(a, b);
}
