ipsec add road1
ipsec up road1 # sanitize-retransmits
ipsec whack --impair send_no_delete
ipsec restart
../../guestbin/wait-until-pluto-started
ipsec add road2
ipsec up road2 # sanitize-retransmits
echo done
