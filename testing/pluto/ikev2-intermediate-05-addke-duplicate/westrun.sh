# this should negotiate dh19, dh20, dh21
../../guestbin/pluto-up-down.sh leftcert=west 'ike=aes;dh19+dh20+dh21;addke1=dh19+dh20+dh21;addke2=dh19+dh20+dh21' -- -I 192.0.1.254 192.0.2.254

# this should negotiate dh19, dh20, dh21
../../guestbin/pluto-up-down.sh leftcert=west 'ike=aes;dh19+dh20+dh21;addke1=dh20+dh21+dh19;addke2=dh21+dh19+dh20' -- -I 192.0.1.254 192.0.2.254

# this should negotiate dh19, none, dh21
../../guestbin/pluto-up-down.sh leftcert=west 'ike=aes;dh19+dh20+dh21;addke1=none;addke2=dh21+dh19+dh20'           -- -I 192.0.1.254 192.0.2.254

# this fail; no backtracking so ADDKE2 fails
../../guestbin/pluto-up-down.sh leftcert=west 'ike=aes;dh19+dh20+dh21;addke1=dh19+dh20+dh21;addke2=dh19+dh20'
