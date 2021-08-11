# confirm east rejects the Traffic Selectors with security labels in it
hostname |grep east > /dev/null && grep "No IKEv2 connection found" /tmp/pluto.log
