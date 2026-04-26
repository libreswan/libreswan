# IPv6 is enabled by default on NIC
ip6tables -F 
ip6tables -X
ip6tables -t nat -L
: ==== end ====
