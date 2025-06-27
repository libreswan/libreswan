/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair ike_responder_spi:0
ipsec add west-east
echo "initdone"
