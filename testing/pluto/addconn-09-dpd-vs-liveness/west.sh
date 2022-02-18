/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

# don't use tabs, guest things it is tab completion
ipsec auto --add ikev1-dpdtimeout=10s            # requires dpddelay
ipsec auto --add ikev1-dpddelay=10s              # requires dpdtimeout
ipsec auto --add ikev1-dpdaction=clear           # requires dpddelay+dpdtimeout
ipsec auto --add ikev1-dpdaction=clear-dpdtimeout=10s # requires dpddelay
ipsec auto --add ikev1-dpddelay=10s-dpdtimeout=0s # requires dpdtimeout!=0

ipsec auto --add ikev2-dpdtimeout=10s            # ignore dpdtimeout
ipsec auto --add ikev2-dpdaction=clear           # requires dpddelay
