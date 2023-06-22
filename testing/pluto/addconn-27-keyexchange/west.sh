/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add ikev2=no
ipsec add ikev2=yes
ipsec add ikev2=always
ipsec add ikev2=never

ipsec add keyexchange=ike
ipsec add keyexchange=ikev1
ipsec add keyexchange=ikev2

ipsec add keyexchange=ike-ikev2=n
ipsec add keyexchange=ike-ikev2=y

ipsec add keyexchange=ikev1-ikev2=n
ipsec add keyexchange=ikev1-ikev2=y

ipsec add keyexchange=ikev2-ikev2=n
ipsec add keyexchange=ikev2-ikev2=y
