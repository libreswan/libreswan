/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec auto --add ikev1-dpdtimeout # requires dpddelay
ipsec auto --add ikev1-dpddelay   # requires dpdtimeout
ipsec auto --add ikev1-dpdaction  # requires dpddelay+dpdtimeout
ipsec auto --add ikev1-dpdaction-dpdtimeout  # requires dpddelay

ipsec auto --add ikev2-dpdtimeout # ignore dpdtimeout
ipsec auto --add ikev2-dpdaction  # requires dpddelay
