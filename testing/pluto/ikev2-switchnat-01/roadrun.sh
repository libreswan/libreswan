ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add road1
ipsec auto --up road1
ipsec whack --impair send-no-delete
ipsec restart
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add road2
ipsec auto --up road2

echo done
