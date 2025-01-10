# IKEv2's version of down doesn't do a proper exchange; need to stop
# this end reviving - no way to clear UP bit.

ipsec whack --impair revival
ipsec whack --deletestate 3
