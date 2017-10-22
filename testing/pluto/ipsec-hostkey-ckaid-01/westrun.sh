/testing/guestbin/swan-prep --nokeys
rm -f /tmp/newhostkey.txt
ipsec newhostkey --output /tmp/newhostkey.txt
grep pubkey= /tmp/newhostkey.txt
ipsec showhostkey --list
ckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')
ipsec showhostkey --left --ckaid "$ckaid"
