/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add --config missing-prefix.conf   missing-prefix

ipsec add --config implied-prefix.conf   implied-prefix
ipsec connectionstatus implied-prefix   | grep updown

ipsec add --config redundant-prefix.conf redundant-prefix
ipsec connectionstatus redundant-prefix | grep updown
