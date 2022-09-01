/testing/guestbin/swan-prep --nokeys
:> /etc/ipsec.secrets
ipsec start
../../guestbin/wait-until-pluto-started
