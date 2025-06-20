# everything as auto=start
EF_DISABLE_BANNER=1 ipsec pluto --impair helper_thread_delay:1 --config /etc/ipsec.conf

# Expecting 2*16 + 5 = 37 tunnels to come up.  Each requires two 2 DH
# offloads (plus possible extra offloads for things like NONCE).

ipsec status | grep Total

../../guestbin/wait-for.sh --timeout 180 --match ', active 37' -- ipsec status
