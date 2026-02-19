/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

# don't use tabs, guest things it is tab completion
ipsec add ikev1-dpdtimeout=10s            # requires dpddelay
ipsec add ikev1-dpddelay=10s              # requires dpdtimeout
ipsec add ikev1-dpdaction=clear           # requires dpddelay+dpdtimeout
ipsec add ikev1-dpdaction=clear-dpdtimeout=10s # requires dpddelay
ipsec add ikev1-dpddelay=10s-dpdtimeout=0s # requires dpdtimeout!=0

ipsec add ikev2-dpdtimeout=10s            # ignore dpdtimeout
ipsec add ikev2-dpdaction=clear           # requires dpddelay
