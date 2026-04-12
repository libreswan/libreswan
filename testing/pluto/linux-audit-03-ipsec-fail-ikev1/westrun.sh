# ipsec fail tests
# See description of limitations of this test
ipsec up ikev1-ipsec-fail #retransmits
ipsec delete ikev1-ipsec-fail
ipsec up ikev1-aggr-ipsec-fail #retransmits
ipsec delete ikev1-aggr-ipsec-fail
echo done
