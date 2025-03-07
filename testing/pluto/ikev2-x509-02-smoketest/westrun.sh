# fail quick for -bad certs that are supposed to fail
ipsec whack --impair suppress_retransmits
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
ipsec auto --up west-sanCritical
ipsec auto --delete west-sanCritical
sleep 2
# This one works now - older NSS versions relied on NSS TLS fallback
ipsec auto --up west-ekuCritical
ipsec auto --delete west-ekuCritical
sleep 2
ipsec auto --up west-eku-clientAuth
ipsec auto --delete west-eku-clientAuth
sleep 2
ipsec auto --up west-eku-ipsecIKE
ipsec auto --delete west-eku-ipsecIKE
sleep 2
# fails on older versions of NSS only
ipsec auto --up west-ekuCritical-eku-emailProtection
ipsec auto --delete west-ekuCritical-eku-emailProtection
sleep 2
# following test should fail (but it does not - It is an nss-ism - we will ignore it for now)
ipsec auto --up west-ekuBOGUS-bad
ipsec auto --delete west-ekuBOGUS-bad
echo "done"
