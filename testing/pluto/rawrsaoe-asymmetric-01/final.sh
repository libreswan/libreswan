hostname | grep east > /dev/null && ipsec trafficstatus
# A tunnel should have established
# you should see both RSA and NULL
hostname | grep east > /dev/null && grep IKEv2_AUTH_ /tmp/pluto.log
