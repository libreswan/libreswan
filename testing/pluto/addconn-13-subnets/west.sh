/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec auto --add s0-s1
ipsec auto --add s1-s1
ipsec auto --add s1-s2
ipsec auto --add s2-s1
ipsec auto --add s2-s2

ipsec auto --add s0-ss1
ipsec auto --add s1-ss1
ipsec auto --add s1-ss2
ipsec auto --add s2-ss1
ipsec auto --add s2-ss2

ipsec auto --add ss0-ss1
ipsec auto --add ss1-ss1
ipsec auto --add ss1-ss2
ipsec auto --add ss2-ss1
ipsec auto --add ss2-ss2

ipsec auto --add s1ss1-s1
ipsec auto --add s1ss2-s1
ipsec auto --add s2ss1-s1
ipsec auto --add s2ss2-s1

ipsec add ikev1-s1ssh
ipsec add ikev1-s2
