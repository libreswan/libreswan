/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12

cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear

ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 2' -- ipsec status

ipsec whack --impair suppress_retransmits

# establish a baseline: one trap, no state and nothing up
ipsec _kernel policy
ipsec _kernel state
ipsec trafficstatus
ipsec shuntstatus
echo "initdone"
