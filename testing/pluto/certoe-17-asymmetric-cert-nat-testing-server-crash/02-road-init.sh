/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits

# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 2' -- ipsec auto --status

# establish a baseline: one trap, no state and nothing up
ipsec _kernel policy
ipsec _kernel state
ipsec whack --trafficstatus
ipsec whack --shuntstatus
echo "initdone"
