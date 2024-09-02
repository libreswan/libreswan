/testing/guestbin/swan-prep --hostkeys
: > /etc/ipsec.secrets
ipsec start
../../guestbin/wait-until-pluto-started
