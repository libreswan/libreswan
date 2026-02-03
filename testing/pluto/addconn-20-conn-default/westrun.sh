ipsec add first
ipsec add second
# conn second should inherit the conn %default values with 3des-sha1
ipsec status |grep "algorithms:"
# connection should fail to load - don't accept %fromcert without cert
ipsec add cert-complain
# this one should work as %fromcert means for the CERT received with IKE
ipsec add cert-allow
echo done
