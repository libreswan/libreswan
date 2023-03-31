/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --ondemand missing
ipsec auto --ondemand missing
ipsec auto --ondemand missing > OUTPUT/ondemand.log 2>&1
cat OUTPUT/ondemand.log
