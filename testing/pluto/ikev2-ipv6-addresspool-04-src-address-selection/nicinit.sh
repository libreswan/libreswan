#need swan-prep for ipv6 forwarding 
/testing/guestbin/swan-prep --46
ip6tables -F 
ip6tables -X
ip6tables -t nat -L
: ==== end ====
