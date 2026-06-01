ipsec _kernel state
ipsec _kernel policy
hostname | grep east > /dev/null && ipsec whack --globalstatus | grep FAILED_CP_REQUIRED
