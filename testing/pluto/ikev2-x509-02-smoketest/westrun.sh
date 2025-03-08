# fail quick for -bad certs that are supposed to fail
ipsec whack --impair suppress_retransmits
# stock certificate test
ipsec auto --up west
ipsec auto --delete west
# following tests should work
ipsec auto --up west-bcCritical
ipsec auto --delete west-bcCritical
sleep 2
ipsec auto --up west-bcOmit
ipsec auto --delete west-bcOmit
sleep 2
ipsec auto --up west-sanCritical
ipsec auto --delete west-sanCritical
sleep 2
echo "done"
