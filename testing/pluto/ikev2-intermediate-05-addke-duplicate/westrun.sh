# this should negotiate dh19,dh20,dh21
../../guestbin/pluto-up-down.sh 'ike=aes;dh19+dh20+dh21-dh19+dh20+dh21-dh19+dh20+dh21' -- -I 192.0.1.254 192.0.2.254

# this should fail
../../guestbin/pluto-up-down.sh 'ike=aes;dh19-dh20-dh19+dh20'

# this should fail
../../guestbin/pluto-up-down.sh 'ike=aes;dh19+dh20-dh20+dh19'
