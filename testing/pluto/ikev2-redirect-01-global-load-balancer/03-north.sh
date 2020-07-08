/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add north-east
ipsec whack --impair delete-on-retransmit
ipsec whack --impair revival
echo initdone
ipsec auto --up north-east
echo "1. north connection add+up done"
ipsec auto --delete north-east
echo "1. north connection delete done"
