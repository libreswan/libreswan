hostname | grep east > /dev/null && ipsec whack --trafficstatus
# A tunnel should have established
hostname | grep east > /dev/null && grep "negotiated connection" /tmp/pluto.log
# you should see both RSA and NULL
hostname | grep east > /dev/null && grep IKEv2_AUTH_ /tmp/pluto.log
