# Try to establish, it will fail because the CRL list is out-of-date.
# Since crl-strict=true, a fetch of CRLs is initiated (or would be if
# it weren't impaired).
ipsec up nss-cert-crl

# check there's a pending CRL; fetch it and confirm it has cleared
ipsec listcrls
ipsec fetchcrls
ipsec listcrls

# finally trigger the revival; will re-fail but this time because the
# cert is revoked.
ipsec whack --impair trigger_revival:1
