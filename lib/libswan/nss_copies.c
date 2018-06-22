/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifdef _MIPS_SIM
# include <sgidefs.h>
#endif

#include <cert.h>
#include <secder.h>

/*
 * The NSS function CERT_CompareAVA() appears in the NSS header files,
 * but the library does not actually export the function. This is a copy
 * of that function until upstream NSS is fixed and the fix available in
 * the common Linux distributions. This workaround is enabled using
 * NSS_REQ_AVA_COPY=true
 *
 * See also:
 * https://bugzilla.mozilla.org/show_bug.cgi?id=1336487
 * https://bugzilla.mozilla.org/show_bug.cgi?id=294538
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

SECComparison CERT_CompareAVA(const CERTAVA *a, const CERTAVA *b)
{
	return _NSSCPY_CERT_CompareAVA(a, b);
}
