/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet-encapsulation=yes
ipsec status |grep encaps:
echo "initdone"
