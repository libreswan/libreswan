# Try to establish, it will fail because the CRL list is out-of-date.
# Since crlcheckinterval=0, no further action is taken.

ipsec up nss-cert-crl

# should be no pending CRL fetches; force an update

ipsec listcrls
ipsec fetchcrls
ipsec listcrls

# only one fetch
grep '^CRL: ' /tmp/pluto.log
