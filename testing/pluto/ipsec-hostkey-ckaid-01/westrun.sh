/testing/guestbin/swan-prep --nokeys
rm -f /tmp/newhostkey.txt
ckaid=$(ipsec newhostkey 2>&1 | grep "showhostkey" | sed "s/^.*ckaid //")
ipsec showhostkey --list
ipsec showhostkey --left --ckaid "$ckaid"
