/testing/guestbin/swan-prep --nokeys

# scrub any password file
:> /etc/ipsec.secrets

# start
ipsec start
../../guestbin/wait-until-pluto-started

# generate fresh keys
../../guestbin/genhostkey.sh $PWD
