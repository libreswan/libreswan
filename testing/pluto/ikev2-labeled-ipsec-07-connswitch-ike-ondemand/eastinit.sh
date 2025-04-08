/testing/guestbin/swan-prep --x509
# build install se module
../../guestbin/semodule.sh ipsecspd-full-perm.te
setenforce 0
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
# note order; it seems to matter (but shouldn't)
ipsec auto --add west-to-east
ipsec auto --add distraction
