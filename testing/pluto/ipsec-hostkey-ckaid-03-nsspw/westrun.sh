/testing/guestbin/swan-prep --nokeys --nsspw
ipsec newhostkey
ipsec showhostkey --list
ckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')
ipsec showhostkey --left --ckaid "$ckaid"

