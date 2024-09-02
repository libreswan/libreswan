/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
dig +short  @192.1.3.254 road.testing.libreswan.org  IPSECKEY | sort
ipsec auto --add road-east-ikev2
ipsec whack --impair suppress_retransmits
echo "initdone"
