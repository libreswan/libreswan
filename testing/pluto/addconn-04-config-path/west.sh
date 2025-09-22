/testing/guestbin/swan-prep --nokeys
# /etc/ipsec.conf is corrupt

# try absolute non-standard location
cp tmp.conf /tmp
ipsec pluto --config /tmp/tmp.conf
../../guestbin/wait-until-pluto-started
ipsec connectionstatus tmp
ipsec whack --shutdown

# try relative non-standard location
ipsec pluto --config path.conf
../../guestbin/wait-until-pluto-started
ipsec connectionstatus path
ipsec whack --shutdown
