/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn

ipsec add addconn--leftupdown=
ipsec add addconn--leftupdown=quotes

ipsec add addconn--leftupdown=%disabled
ipsec add addconn--leftupdown=my-updown
ipsec add addconn--leftupdown=left

ipsec add addconn--rightupdown=right

ipsec add addconn--type=passthrough
ipsec add addconn--type=passthrough--leftupdown=left

ipsec whack --name whack                                      --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--updown=from  --updown=from          --host 1.2.3.4 --to --host 5.6.7.8

ipsec whack --name whack--pass               --pass                --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--pass--updown=from  --pass --updown=from  --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e '/: .*updown=/ s/  */ /gp' | sort
