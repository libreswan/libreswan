../../guestbin/prep.sh

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --checkpubkeys --listcrls    # conflicting commands
