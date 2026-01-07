# State's received msgid should be incremented after each new
# exchange.  Since west, the IKE SA initiator, is responding to
# CHILD_SA the values start at 0.

grep hdr.isa_msgid /tmp/pluto.log
