# fail quick for -bad certs that are supposed to fail
ipsec whack --impair suppress-retransmits
# stock certificate test
ipsec auto --up west
ipsec auto --delete west
# following tests should work
ipsec auto --up west-bcCritical
ipsec auto --delete west-bcCritical
sleep 2
ipsec auto --up west-ekuOmit
ipsec auto --delete west-ekuOmit
sleep 2
ipsec auto --up west-bcOmit
ipsec auto --delete west-bcOmit
sleep 2
ipsec auto --up west-ekuCritical-eku-ipsecIKE
ipsec auto --delete west-ekuCritical-eku-ipsecIKE
sleep 2
ipsec auto --up west-eku-serverAuth
ipsec auto --delete west-eku-serverAuth
sleep 2
ipsec auto --up west-ku-nonRepudiation
ipsec auto --delete west-ku-nonRepudiation
sleep 2
# This one works only because of the NSS TLS fallback
ipsec auto --up west-ekuCritical
ipsec auto --delete west-ekuCritical
sleep 2
ipsec auto --up west-kuCritical
ipsec auto --delete west-kuCritical
sleep 2
ipsec auto --up west-kuOmit
ipsec auto --delete west-kuOmit
sleep 2
ipsec auto --up west-eku-clientAuth
ipsec auto --delete west-eku-clientAuth
sleep 2
ipsec auto --up west-eku-ipsecIKE
ipsec auto --delete west-eku-ipsecIKE
sleep 2
ipsec auto --up west-ku-keyAgreement-digitalSignature
ipsec auto --delete west-ku-keyAgreement-digitalSignature
sleep 2
# following should not fail, but does?
ipsec auto --up west-ekuCritical-eku-emailProtection
ipsec auto --delete west-ekuCritical-eku-emailProtection
sleep 2
# following tests should fail
ipsec auto --up west-ekuBOGUS-bad
ipsec auto --delete west-ekuBOGUS-bad
sleep 2
ipsec auto --up west-ku-keyAgreement-bad
ipsec auto --delete west-ku-keyAgreement-bad
echo "done"
