ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add other
ipsec auto --up other
ipsec whack --trafficstatus
ipsec whack --impair send-no-delete
ipsec restart
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add main
ipsec auto --up main
ipsec whack --trafficstatus

echo "done"
