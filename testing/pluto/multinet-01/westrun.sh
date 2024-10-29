ipsec whack --impair suppress_retransmits
ipsec whack --impair helper_thread_delay:0 # do the timewarp
ipsec auto --up westnet-eastnet-subnets
ipsec whack --trafficstatus
# test return code for --down when using aliases
ipsec auto --down westnet-eastnet-subnets || echo "return code failed - should be 0"
ipsec status | grep westnet
echo done
