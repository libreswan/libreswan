/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-ikev2
ipsec whack --impair suppress_retransmits
# road should have only one public key of its own
ipsec auto --listpubkeys

echo "initdone"
