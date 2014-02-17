s/ipsec_setup:.*echo "Starting Libreswan IPsec .*"/ipsec_setup:    echo "Starting Libreswan IPsec VER"/
s/ipsec_setup:.*echo "Starting Openswan IPsec .*"/ipsec_setup:    echo "Starting Libreswan IPsec VER"/
/started helper pid=/d
