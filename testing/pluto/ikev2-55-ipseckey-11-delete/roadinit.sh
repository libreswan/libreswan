/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add road-east-ikev2
# Make road patient enough to receive east's IKE_AUTH (DNS query takes some time).
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
echo "initdone"
