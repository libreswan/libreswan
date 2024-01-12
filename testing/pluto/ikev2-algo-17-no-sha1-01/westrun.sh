# this should fail, as SHA1 is not part of the default proposal set anymore
ipsec whack --impair timeout_on_retransmit
ipsec auto --up westnet-eastnet-no-sha1
echo done
