# this should negotiate dh19, dh20, dh21
../../guestbin/pluto-up-down.sh 'ike=aes;dh19+dh20+dh21-dh19+dh20+dh21-dh19+dh20+dh21' -- -I 192.0.1.254 192.0.2.254

# this should negotiate dh19, dh20, dh21
../../guestbin/pluto-up-down.sh 'ike=aes;dh19+dh20+dh21-dh20+dh21+dh19-dh21+dh19+dh20' -- -I 192.0.1.254 192.0.2.254

# this should negotiate dh19, none, dh21
../../guestbin/pluto-up-down.sh 'ike=aes;dh19+dh20+dh21-none-dh21+dh19+dh20' -- -I 192.0.1.254 192.0.2.254

# this fail; no backtracking so ADDKE2 fails
../../guestbin/pluto-up-down.sh 'ike=aes;dh19+dh20+dh21-dh19+dh20+dh21-dh19+dh20'
